"""
Custom x402 middleware adapted for environments with idle timeout constraints.

Key modifications:
- Settlement happens asynchronously after the response is returned.
- Longer HTTP timeouts + retry logic for facilitator /settle (handles 404 + ReadTimeout).
"""

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any, cast, get_args

import httpx
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import validate_call
from x402.common import (
    find_matching_payment_requirements,
    process_price_to_atomic_amount,
    x402_VERSION,
)
from x402.encoding import safe_base64_decode
from x402.facilitator import FacilitatorClient, FacilitatorConfig, SettleResponse
from x402.path import path_is_match
from x402.paywall import get_paywall_html, is_browser_request
from x402.types import (
    HTTPInputSchema,
    PaymentPayload,
    PaymentRequirements,
    PaywallConfig,
    Price,
    SupportedNetworks,
    x402PaymentRequiredResponse,
)

logger = logging.getLogger(__name__)


@validate_call
def require_payment_async_settle(
    price: Price,
    pay_to_address: str,
    path: str | list[str] = "*",
    description: str = "",
    mime_type: str = "",
    max_deadline_seconds: int = 60,
    input_schema: HTTPInputSchema | None = None,
    output_schema: Any | None = None,
    discoverable: bool | None = True,
    facilitator_config: FacilitatorConfig | None = None,
    # For mainnet use "base"; default remains "base-sepolia" (testnet).
    network: str = "base-sepolia",
    resource: str | None = None,
    paywall_config: PaywallConfig | None = None,
    custom_paywall_html: str | None = None,
    on_settlement_success: Callable | None = None,
    on_settlement_failure: Callable | None = None,
):
    # Validate network
    supported_networks = get_args(SupportedNetworks)
    if network not in supported_networks:
        raise ValueError(f"Unsupported network: {network}. Must be one of: {supported_networks}")

    # Compute amounts/domain/asset
    try:
        max_amount_required, asset_address, eip712_domain = process_price_to_atomic_amount(
            price, network
        )
    except Exception as e:
        raise ValueError(f"Invalid price: {price}. Error: {e}") from e

    facilitator = FacilitatorClient(facilitator_config)

    def parse_error_response(response: httpx.Response, default_msg: str) -> str:
        """Extract error from facilitator response, if present."""
        try:
            data = response.json()
            if isinstance(data, dict):
                return (
                    data.get("error")
                    or data.get("invalidReason")
                    or data.get("message")
                    or default_msg
                )
        except Exception:
            pass
        text = response.text.strip()
        return f"HTTP {response.status_code}: {text[:200]}" if text else default_msg

    async def settle_with_retry(
        client: httpx.AsyncClient,
        payment: PaymentPayload,
        payment_requirements: PaymentRequirements,
        headers: dict,
    ) -> SettleResponse:
        """
        Attempt settlement with retry logic for 404 (not yet registered) and timeouts.
        """
        max_retries = 5
        retry_delays = [1.0, 1.0, 2.0, 3.0, 5.0, 8.0]  # ~20s worst case

        # small pause so facilitator can register the verify step
        await asyncio.sleep(1.0)

        for attempt in range(max_retries + 1):
            try:
                resp = await client.post(
                    f"{facilitator.config['url']}/settle",
                    json={
                        "x402Version": payment.x402_version,
                        "paymentPayload": payment.model_dump(by_alias=True),
                        "paymentRequirements": payment_requirements.model_dump(
                            by_alias=True, exclude_none=True
                        ),
                    },
                    headers=headers,
                    follow_redirects=True,
                )
            except httpx.ReadTimeout:
                if attempt < max_retries:
                    delay = retry_delays[min(attempt, len(retry_delays) - 1)]
                    logger.warning(
                        f"Settlement timeout (attempt {attempt + 1}/{max_retries + 1}); retrying in {delay}s..."
                    )
                    await asyncio.sleep(delay)
                    continue
                return SettleResponse(success=False, error_reason="Facilitator timeout during settlement")
            except Exception as e:
                if attempt < max_retries:
                    delay = retry_delays[min(attempt, len(retry_delays) - 1)]
                    logger.warning(
                        f"Settlement error {e!r} (attempt {attempt + 1}/{max_retries + 1}); retrying in {delay}s..."
                    )
                    await asyncio.sleep(delay)
                    continue
                return SettleResponse(success=False, error_reason=f"Settlement error: {e!s}")

            if resp.status_code == 200:
                data = {}
                try:
                    data = resp.json() or {}
                except Exception:
                    # treat 200 with non-JSON body as success
                    return SettleResponse(success=True, error_reason=None)

                # Normalize facilitator variants:
                #  - {"success": bool, "error_reason": str?}
                #  - {"isValid": bool, "invalidReason": str?}
                if isinstance(data, dict):
                    ok = data.get("success")
                    if ok is None:
                        ok = data.get("isValid")
                    ok = bool(ok)
                    reason = data.get("error_reason") or data.get("invalidReason") or data.get("error")
                    return SettleResponse(success=ok, error_reason=None if ok else reason)

                # Fallback — 200 with unexpected shape
                return SettleResponse(success=True, error_reason=None)

            if resp.status_code == 404 and attempt < max_retries:
                delay = retry_delays[min(attempt, len(retry_delays) - 1)]
                logger.info(
                    f"Settlement returned 404 (attempt {attempt + 1}/{max_retries + 1}); retrying in {delay}s..."
                )
                await asyncio.sleep(delay)
                continue

            # Other failure
            err = parse_error_response(resp, f"Facilitator returned HTTP {resp.status_code}")
            return SettleResponse(success=False, error_reason=err)

    async def settle_with_timeout(
        payment: PaymentPayload, payment_requirements: PaymentRequirements
    ) -> SettleResponse:
        """Settle payment with generous timeouts; /settle may take tens of seconds."""
        headers = {"Content-Type": "application/json"}
        if facilitator.config.get("create_headers"):
            custom = await facilitator.config["create_headers"]()
            headers.update(custom.get("settle", {}))

        # Generous timeouts (no HTTP/2 to avoid extra deps)
        timeout = httpx.Timeout(connect=20.0, read=60.0, write=30.0, pool=60.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await settle_with_retry(client, payment, payment_requirements, headers)

    async def settle_in_background(
        request: Request, payment: PaymentPayload, payment_requirements: PaymentRequirements
    ) -> None:
        """Run settlement after the client has received the 2xx response."""
        try:
            settle_response = await settle_with_timeout(payment, payment_requirements)
            if settle_response.success:
                logger.info(
                    f"Payment settled successfully for resource: {payment_requirements.resource}"
                )
                if on_settlement_success:
                    try:
                        await on_settlement_success(request, payment, payment_requirements)
                    except Exception as cb_error:
                        logger.error("Error in settlement success callback: %s", cb_error, exc_info=True)
            else:
                reason = settle_response.error_reason or "Unknown error"
                logger.warning("Settlement failed: %s", reason)
                if on_settlement_failure:
                    try:
                        await on_settlement_failure(request, payment, payment_requirements, reason)
                    except Exception as cb_error:
                        logger.error("Error in settlement failure callback: %s", cb_error, exc_info=True)
        except Exception as e:
            logger.error("Settlement error: %s", e, exc_info=True)
            if on_settlement_failure:
                try:
                    await on_settlement_failure(request, payment, payment_requirements, f"Exception: {e}")
                except Exception as cb_error:
                    logger.error("Error in settlement failure callback: %s", cb_error, exc_info=True)

    async def middleware(request: Request, call_next: Callable):
        # Only guard matching paths
        if not path_is_match(path, request.url.path):
            return await call_next(request)

        # Resource URL
        resource_url = resource or str(request.url)

        # Build payment requirements
        payment_requirements = [
            PaymentRequirements(
                scheme="exact",
                network=cast(SupportedNetworks, network),
                asset=asset_address,
                max_amount_required=max_amount_required,
                resource=resource_url,
                description=description,
                mime_type=mime_type,
                pay_to=pay_to_address,
                max_timeout_seconds=max_deadline_seconds,
                output_schema={
                    "input": {
                        "type": "http",
                        "method": request.method.upper(),
                        "discoverable": discoverable if discoverable is not None else True,
                        **(input_schema.model_dump() if input_schema else {}),
                    },
                    "output": output_schema,
                },
                extra=eip712_domain,
            )
        ]

        def x402_response(error: str):
            """Return a 402 (HTML paywall for browsers, JSON otherwise)."""
            status_code = 402
            if is_browser_request(dict(request.headers)):
                html = custom_paywall_html or get_paywall_html(error, payment_requirements, paywall_config)
                return HTMLResponse(content=html, status_code=status_code, headers={"Content-Type": "text/html; charset=utf-8"})
            data = x402PaymentRequiredResponse(
                x402_version=x402_VERSION, accepts=payment_requirements, error=error
            ).model_dump(by_alias=True)
            return JSONResponse(content=data, status_code=status_code, headers={"Content-Type": "application/json"})

        # Require X-PAYMENT
        payment_header = request.headers.get("X-PAYMENT", "")
        if not payment_header:
            return x402_response("No X-PAYMENT header provided")

        # Decode payment payload
        try:
            payment_dict = json.loads(safe_base64_decode(payment_header))
            payment = PaymentPayload(**payment_dict)
        except Exception as e:
            logger.warning(
                "Invalid payment header format from %s: %s",
                (request.client.host if request.client else "unknown"),
                str(e),
            )
            return x402_response("Invalid payment header format")

        # Match requirements
        selected = find_matching_payment_requirements(payment_requirements, payment)
        if not selected:
            return x402_response("No matching payment requirements found")

        # Verify payment
        verify_response = await facilitator.verify(payment, selected)
        if not verify_response.is_valid:
            return x402_response(f"Invalid payment: {verify_response.invalid_reason or 'Unknown error'}")

        # Stash for downstream handlers if needed
        request.state.payment_details = selected
        request.state.verify_response = verify_response

        # Let the endpoint run
        response = await call_next(request)

        # Only settle on 2xx
        if not (200 <= response.status_code < 300):
            return response

        # Kick off settlement in the background and return immediately
        asyncio.create_task(settle_in_background(request, payment, selected))
        logger.info("Returning response immediately, settlement scheduled in background")
        return response

    return middleware
