"""
Custom x402 middleware adapted for environments with idle timeout constraints.

This is adapted from:
https://github.com/coinbase/x402/blob/7bbfaaf2589df2f787d3fc0b83853a0efc709287/python/x402/src/x402/fastapi/middleware.py#L33

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
    # IMPORTANT: pass "base" from your app for Base mainnet; default remains testnet.
    network: str = "base-sepolia",
    resource: str | None = None,
    paywall_config: PaywallConfig | None = None,
    custom_paywall_html: str | None = None,
    on_settlement_success: Callable | None = None,
    on_settlement_failure: Callable | None = None,
):
    """
    Generate a FastAPI middleware that gates payments for an endpoint.

    This version returns the response immediately after payment verification,
    then settles the payment asynchronously in the background. This allows the
    endpoint to respond quickly (within proxy idle timeout) while still completing
    the settlement process.
    """

    # Validate network
    supported_networks = get_args(SupportedNetworks)
    if network not in supported_networks:
        raise ValueError(f"Unsupported network: {network}. Must be one of: {supported_networks}")

    # Compute payment requirements (amounts, domain, asset)
    try:
        max_amount_required, asset_address, eip712_domain = process_price_to_atomic_amount(
            price, network
        )
    except Exception as e:
        raise ValueError(f"Invalid price: {price}. Error: {e}") from e

    facilitator = FacilitatorClient(facilitator_config)

    def parse_error_response(response: httpx.Response, default_msg: str) -> str:
        """Extract a useful error message from HTTP response."""
        try:
            error_data = response.json()
            if isinstance(error_data, dict) and "error" in error_data:
                return str(error_data["error"])
        except Exception:
            pass
        text = response.text.strip()
        return f"HTTP {response.status_code}: {text[:200]}" if text else default_msg

    async def settle_with_retry(
        client: httpx.AsyncClient,
        payment: PaymentPayload,
        payment_requirements: PaymentRequirements,
        headers: dict[str, str],
    ) -> SettleResponse:
        """
        Attempt settlement with retry logic for 404 (payment not registered yet) and timeouts.
        """
        max_retries = 5
        # Backoff ~1,1,2,3,5,8 (about 20s total worst case)
        retry_delays = [1.0, 1.0, 2.0, 3.0, 5.0, 8.0]

        # Small pause before the first attempt so facilitator can register verify
        await asyncio.sleep(1.0)

        for attempt in range(max_retries + 1):
            try:
                response = await client.post(
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
                        f"Settlement timeout (attempt {attempt + 1}/{max_retries + 1}); "
                        f"retrying in {delay}s..."
                    )
                    await asyncio.sleep(delay)
                    continue
                return SettleResponse(success=False, error_reason="Facilitator timeout during settlement")
            except Exception as e:
                if attempt < max_retries:
                    delay = retry_delays[min(attempt, len(retry_delays) - 1)]
                    logger.warning(
                        f"Settlement error {e!r} (attempt {attempt + 1}/{max_retries + 1}); "
                        f"retrying in {delay}s..."
                    )
                    await asyncio.sleep(delay)
                    continue
                return SettleResponse(success=False, error_reason=f"Settlement error: {e!s}")

            if response.status_code == 200:
                return SettleResponse(**response.json())

            # retry if facilitator hasn't found the payment yet
            if response.status_code == 404 and attempt < max_retries:
                delay = retry_delays[min(attempt, len(retry_delays) - 1)]
                logger.info(
                    f"Settlement returned 404 (attempt {attempt + 1}/{max_retries + 1}); "
                    f"retrying in {delay}s..."
                )
                await asyncio.sleep(delay)
                continue

            # other failure
            error_msg = parse_error_response(response, f"Facilitator returned HTTP {response.status_code}")
            return SettleResponse(success=False, error_reason=error_msg)

    async def settle_with_timeout(payment: PaymentPayload, payment_requirements: PaymentRequirements) -> SettleResponse:
        """Settle payment with generous timeouts; /settle may take tens of seconds."""
        headers: dict[str, str] = {"Content-Type": "application/json"}

        if facilitator.config.get("create_headers"):
            custom_headers = await facilitator.config["create_headers"]()
            headers.update(custom_headers.get("settle", {}))

        # More generous timeouts (connect/read/write/pool). Enable HTTP/2 for better latency.
        timeout = httpx.Timeout(connect=20.0, read=60.0, write=30.0, pool=60.0)
        async with httpx.AsyncClient(timeout=timeout, http2=True) as client:
            return await settle_with_retry(client, payment, payment_requirements, headers)

    async def settle_in_background(request: Request, payment: PaymentPayload, payment_requirements: PaymentRequirements) -> None:
        """Settle payment in the background after response is sent."""
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
                        logger.error(
                            f"Error in settlement success callback: {cb_error}", exc_info=True
                        )
            else:
                error_reason = settle_response.error_reason or "Unknown error"
                logger.warning(f"Settlement failed: {error_reason}")
                if on_settlement_failure:
                    try:
                        await on_settlement_failure(
                            request, payment, payment_requirements, error_reason
                        )
                    except Exception as cb_error:
                        logger.error(
                            f"Error in settlement failure callback: {cb_error}", exc_info=True
                        )
        except Exception as e:
            logger.error(f"Settlement error: {e}", exc_info=True)
            if on_settlement_failure:
                try:
                    await on_settlement_failure(
                        request, payment, payment_requirements, f"Exception: {e}"
                    )
                except Exception as cb_error:
                    logger.error(f"Error in settlement failure callback: {cb_error}", exc_info=True)

    async def middleware(request: Request, call_next: Callable):
        # Skip if the path does not match the gated path(s)
        if not path_is_match(path, request.url.path):
            return await call_next(request)

        # Use explicit resource or the request URL
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
            """Return a 402 response (HTML paywall for browsers, JSON otherwise)."""
            request_headers = dict(request.headers)
            status_code = 402

            if is_browser_request(request_headers):
                html_content = custom_paywall_html or get_paywall_html(
                    error, payment_requirements, paywall_config
                )
                headers = {"Content-Type": "text/html; charset=utf-8"}
                return HTMLResponse(content=html_content, status_code=status_code, headers=headers)
            else:
                response_data = x402PaymentRequiredResponse(
                    x402_version=x402_VERSION,
                    accepts=payment_requirements,
                    error=error,
                ).model_dump(by_alias=True)
                headers = {"Content-Type": "application/json"}
                return JSONResponse(content=response_data, status_code=status_code, headers=headers)

        # Require X-PAYMENT header
        payment_header = request.headers.get("X-PAYMENT", "")
        if payment_header == "":
            return x402_response("No X-PAYMENT header provided")

        # Decode payment payload
        try:
            payment_dict = json.loads(safe_base64_decode(payment_header))
            payment = PaymentPayload(**payment_dict)
        except Exception as e:
            logger.warning(
                f"Invalid payment header format from {request.client.host if request.client else 'unknown'}: {str(e)}"
            )
            return x402_response("Invalid payment header format")

        # Match requirements
        selected_payment_requirements = find_matching_payment_requirements(
            payment_requirements, payment
        )
        if not selected_payment_requirements:
            return x402_response("No matching payment requirements found")

        # Verify payment with facilitator
        verify_response = await facilitator.verify(payment, selected_payment_requirements)
        if not verify_response.is_valid:
            error_reason = verify_response.invalid_reason or "Unknown error"
            return x402_response(f"Invalid payment: {error_reason}")

        # Stash for downstream handlers if needed
        request.state.payment_details = selected_payment_requirements
        request.state.verify_response = verify_response

        # Call the actual endpoint
        response = await call_next(request)

        # If non-2xx, don't attempt settlement
        if not (200 <= response.status_code < 300):
            return response

        # Kick off settlement in the background so the client gets a fast response
        asyncio.create_task(
            settle_in_background(request, payment, selected_payment_requirements)
        )
        logger.info("Returning response immediately, settlement scheduled in background")
        return response

    return middleware
