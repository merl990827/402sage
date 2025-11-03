"""Custom x402 middleware adapted for environments with idle timeout constraints.

This is adapted from:
https://github.com/coinbase/x402/blob/7bbfaaf2589df2f787d3fc0b83853a0efc709287/python/x402/src/x402/fastapi/middleware.py#L33

Key modification: Settlement happens asynchronously after the response is returned,
allowing the endpoint to respond within 6 seconds to avoid proxy idle timeouts.
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
    network: str = "base-sepolia",
    resource: str | None = None,
    paywall_config: PaywallConfig | None = None,
    custom_paywall_html: str | None = None,
    on_settlement_success: Callable | None = None,
    on_settlement_failure: Callable | None = None,
):
    """Generate a FastAPI middleware that gates payments for an endpoint.

    This version returns the response immediately after payment verification,
    then settles the payment asynchronously in the background. This allows the
    endpoint to respond quickly (within proxy idle timeout) while still completing
    the settlement process.

    Args:
        price (Price): Payment price. Can be:
            - Money: USD amount as string/int (e.g., "$3.10", 0.10, "0.001") - defaults to USDC
            - TokenAmount: Custom token amount with asset information
        pay_to_address (str): Ethereum address to receive the payment
        path (str | list[str], optional): Path to gate with payments. Defaults to "*" for all paths.
        description (str, optional): Description of what is being purchased. Defaults to "".
        mime_type (str, optional): MIME type of the resource. Defaults to "".
        max_deadline_seconds (int, optional): Maximum time allowed for payment. Defaults to 60.
        input_schema (Optional[HTTPInputSchema], optional): Schema for the request structure. Defaults to None.
        output_schema (Optional[Any], optional): Schema for the response. Defaults to None.
        discoverable (bool, optional): Whether the route is discoverable. Defaults to True.
        facilitator_config (Optional[Dict[str, Any]], optional): Configuration for the payment facilitator.
            If not provided, defaults to the public x402.org facilitator.
        network (str, optional): Ethereum network ID. Defaults to "base-sepolia" (Base Sepolia testnet).
        resource (Optional[str], optional): Resource URL. Defaults to None (uses request URL).
        paywall_config (Optional[PaywallConfig], optional): Configuration for paywall UI customization.
            Includes options like cdp_client_key, app_name, app_logo, session_token_endpoint.
        custom_paywall_html (Optional[str], optional): Custom HTML to display for paywall instead of default.
        on_settlement_success (Optional[Callable], optional): Callback function called when settlement succeeds.
            Should accept (request, payment, payment_requirements) as arguments.
        on_settlement_failure (Optional[Callable], optional): Callback function called when settlement fails.
            Should accept (request, payment, payment_requirements, error_reason) as arguments.

    Returns:
        Callable: FastAPI middleware function that checks for valid payment before processing requests
    """

    # Validate network is supported
    supported_networks = get_args(SupportedNetworks)
    if network not in supported_networks:
        raise ValueError(f"Unsupported network: {network}. Must be one of: {supported_networks}")

    try:
        max_amount_required, asset_address, eip712_domain = process_price_to_atomic_amount(
            price, network
        )
    except Exception as e:
        raise ValueError(f"Invalid price: {price}. Error: {e}") from e

    facilitator = FacilitatorClient(facilitator_config)

    def parse_error_response(response: httpx.Response, default_msg: str) -> str:
        """Extract error message from HTTP response."""
        try:
            error_data = response.json()
            if isinstance(error_data, dict) and "error" in error_data:
                return error_data["error"]
        except Exception:
            pass

        # Fallback to text or default message
        text = response.text.strip()
        return f"HTTP {response.status_code}: {text[:100]}" if text else default_msg

    async def settle_with_retry(client: httpx.AsyncClient, payment, payment_requirements, headers):
        """Attempt settlement with retry logic for 404 responses."""
        max_retries = 5
        retry_delays = [1.0, 1.0, 2.0, 3.0, 4.0]  # Total: 11 seconds (1s initial + retries)

        # Wait 1 second before first attempt to give facilitator time to register payment
        await asyncio.sleep(1.0)

        for attempt in range(max_retries + 1):
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

            # Success
            if response.status_code == 200:
                return SettleResponse(**response.json())

            # Retry on 404 (payment not registered yet after verification)
            if response.status_code == 404 and attempt < max_retries:
                delay = retry_delays[attempt]
                logger.info(
                    f"Settlement returned 404 (attempt {attempt + 1}/{max_retries + 1}), "
                    f"retrying in {delay}s..."
                )
                await asyncio.sleep(delay)
                continue

            # Failed after retries or non-retryable error
            error_msg = parse_error_response(
                response,
                f"Payment not found after {max_retries + 1} attempts"
                if response.status_code == 404
                else f"Facilitator returned HTTP {response.status_code}",
            )
            return SettleResponse(success=False, error_reason=error_msg)

    async def settle_with_timeout(payment, payment_requirements):
        """Settle payment with extended timeout (30 seconds)."""
        headers = {"Content-Type": "application/json"}

        if facilitator.config.get("create_headers"):
            custom_headers = await facilitator.config["create_headers"]()
            headers.update(custom_headers.get("settle", {}))

        timeout = httpx.Timeout(30.0, connect=10.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await settle_with_retry(client, payment, payment_requirements, headers)

    async def settle_in_background(request, payment, payment_requirements):
        """Settle payment in the background after response is sent."""
        try:
            settle_response = await settle_with_timeout(payment, payment_requirements)
            if settle_response.success:
                logger.info(
                    f"Payment settled successfully for resource: {payment_requirements.resource}"
                )
                # Call success callback if provided
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
                # Call failure callback if provided
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
            # Call failure callback on exception
            if on_settlement_failure:
                try:
                    await on_settlement_failure(
                        request, payment, payment_requirements, f"Exception: {e}"
                    )
                except Exception as cb_error:
                    logger.error(f"Error in settlement failure callback: {cb_error}", exc_info=True)

    async def middleware(request: Request, call_next: Callable):
        # Skip if the path is not the same as the path in the middleware
        if not path_is_match(path, request.url.path):
            return await call_next(request)

        # Get resource URL if not explicitly provided
        resource_url = resource or str(request.url)

        # Construct payment details
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
            """Create a 402 response with payment requirements."""
            request_headers = dict(request.headers)
            status_code = 402

            if is_browser_request(request_headers):
                html_content = custom_paywall_html or get_paywall_html(
                    error, payment_requirements, paywall_config
                )
                headers = {"Content-Type": "text/html; charset=utf-8"}

                return HTMLResponse(
                    content=html_content,
                    status_code=status_code,
                    headers=headers,
                )
            else:
                response_data = x402PaymentRequiredResponse(
                    x402_version=x402_VERSION,
                    accepts=payment_requirements,
                    error=error,
                ).model_dump(by_alias=True)
                headers = {"Content-Type": "application/json"}

                return JSONResponse(
                    content=response_data,
                    status_code=status_code,
                    headers=headers,
                )

        # Check for payment header
        payment_header = request.headers.get("X-PAYMENT", "")

        if payment_header == "":
            return x402_response("No X-PAYMENT header provided")

        # Decode payment header
        try:
            payment_dict = json.loads(safe_base64_decode(payment_header))
            payment = PaymentPayload(**payment_dict)
        except Exception as e:
            logger.warning(
                f"Invalid payment header format from {request.client.host if request.client else 'unknown'}: {str(e)}"
            )
            return x402_response("Invalid payment header format")

        # Find matching payment requirements
        selected_payment_requirements = find_matching_payment_requirements(
            payment_requirements, payment
        )

        if not selected_payment_requirements:
            return x402_response("No matching payment requirements found")

        # Verify payment
        verify_response = await facilitator.verify(payment, selected_payment_requirements)

        if not verify_response.is_valid:
            error_reason = verify_response.invalid_reason or "Unknown error"
            return x402_response(f"Invalid payment: {error_reason}")

        request.state.payment_details = selected_payment_requirements
        request.state.verify_response = verify_response

        # Process the request
        response = await call_next(request)

        # Early return without settling if the response is not a 2xx
        if response.status_code < 200 or response.status_code >= 300:
            return response

        # Schedule settlement to happen in the background (non-blocking)
        # This allows the response to be sent immediately, avoiding proxy idle timeouts
        asyncio.create_task(settle_in_background(request, payment, selected_payment_requirements))

        # Return response immediately without waiting for settlement
        # Note: We don't include X-PAYMENT-RESPONSE header since settlement happens async
        logger.info("Returning response immediately, settlement scheduled in background")

        return response

    return middleware
