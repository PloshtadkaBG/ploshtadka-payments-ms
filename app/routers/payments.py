from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Literal, cast
from uuid import UUID

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, status
from stripe import StripeClient

from app import settings
from app.crud import payment_crud
from app.deps import (
    BookingsClient,
    CurrentUser,
    _get_system_admin,
    can_admin_delete_payment,
    can_read_payment,
    get_bookings_client,
    get_current_user,
    get_stripe_client,
)
from app.schemas import CheckoutRequest, CheckoutResponse, PaymentResponse
from app.scopes import PaymentScope

router = APIRouter(prefix="/payments", tags=["payments"])


# ---------------------------------------------------------------------------
# POST /payments/checkout
# ---------------------------------------------------------------------------


@router.post(
    "/checkout",
    response_model=CheckoutResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_checkout(
    payload: CheckoutRequest,
    current_user: CurrentUser = Depends(get_current_user),
    bookings_client: BookingsClient = Depends(get_bookings_client),
    stripe_client: StripeClient = Depends(get_stripe_client),
) -> CheckoutResponse:
    """
    Create a Stripe Checkout Session for a pending booking.

    The booking's price is fetched from bookings-ms — the client cannot
    manipulate the amount.  Any authenticated user may pay for their own
    booking; admins may pay on behalf of any user.
    """
    # Reject if the booking already has a successful payment
    existing_paid = await payment_crud.get_by_booking_paid(payload.booking_id)
    if existing_paid:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This booking has already been paid.",
        )

    # Fetch authoritative booking data from bookings-ms
    booking = await bookings_client.get_booking(payload.booking_id, current_user)
    if booking is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Booking not found.",
        )

    # Only the booking owner or an admin may pay
    if UUID(booking["user_id"]) != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only pay for your own bookings.",
        )

    # Payment is only meaningful while the booking is still pending
    if booking["status"] != "pending":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Cannot pay for a booking with status '{booking['status']}'.",
        )

    # Amount fetched from booking — never trust client-supplied values
    total_price = Decimal(str(booking["total_price"]))
    currency = booking.get("currency", "EUR").lower()
    amount_cents = int(total_price * 100)
    locale = payload.locale or "en"

    # Append a placeholder that Stripe replaces with the real session ID
    success_url = (
        settings.stripe_success_url.replace("/bookings", f"/{locale}/bookings")
        + "&session_id={CHECKOUT_SESSION_ID}"
    )
    cancel_url = settings.stripe_cancel_url.replace("/bookings", f"/{locale}/bookings")

    expires_at = datetime.now(UTC) + timedelta(
        minutes=settings.stripe_checkout_expires_minutes
    )

    _product_names = {
        "bg": "Резервация на база",
        "en": "Venue booking",
    }
    product_name = _product_names.get(payload.locale or "", "Venue booking")

    print(locale)

    session = stripe_client.v1.checkout.sessions.create(
        params={
            "mode": "payment",
            "locale": cast(Literal["en", "bg", "auto"], locale),
            "line_items": [
                {
                    "price_data": {
                        "currency": currency,
                        "product_data": {
                            "name": product_name,
                            "description": (
                                f"Booking {str(payload.booking_id)[:8]}… "
                                f"| {str(booking.get('start_datetime', ''))[:16]}"
                            ),
                        },
                        "unit_amount": amount_cents,
                    },
                    "quantity": 1,
                }
            ],
            # client_reference_id lets us look up the booking in the webhook
            "client_reference_id": str(payload.booking_id),
            "metadata": {
                "booking_id": str(payload.booking_id),
                "user_id": str(current_user.id),
            },
            "success_url": success_url,
            "cancel_url": cancel_url,
            "expires_at": int(expires_at.timestamp()),
        }
    )

    payment = await payment_crud.create(
        booking_id=payload.booking_id,
        user_id=current_user.id,
        venue_owner_id=UUID(booking["venue_owner_id"]),
        stripe_session_id=session.id,
        amount=total_price,
        currency=booking.get("currency", "EUR").upper(),
    )

    return CheckoutResponse(
        checkout_url=session.url,
        session_id=session.id,
        payment_id=payment.id,
    )


# ---------------------------------------------------------------------------
# GET /payments/
# ---------------------------------------------------------------------------


@router.get("/", response_model=list[PaymentResponse])
async def list_payments(
    page: int = 1,
    page_size: int = 20,
    current_user: CurrentUser = Depends(can_read_payment),
) -> list[PaymentResponse]:
    """
    List payments.  Customers see only their own; admins see all.
    """
    is_admin = (
        PaymentScope.ADMIN in current_user.scopes
        or PaymentScope.ADMIN_READ in current_user.scopes
    )
    return await payment_crud.list_payments(
        page=page,
        page_size=page_size,
        user_id=None if is_admin else current_user.id,
    )


# ---------------------------------------------------------------------------
# GET /payments/booking/{booking_id}
# ---------------------------------------------------------------------------


@router.get("/booking/{booking_id}", response_model=PaymentResponse)
async def get_payment_by_booking(
    booking_id: UUID,
    current_user: CurrentUser = Depends(can_read_payment),
) -> PaymentResponse:
    """Return the most recent PAID payment for a booking."""
    payment = await payment_crud.get_by_booking_paid(booking_id)
    if payment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No paid payment found for this booking.",
        )

    is_admin = (
        PaymentScope.ADMIN in current_user.scopes
        or PaymentScope.ADMIN_READ in current_user.scopes
    )
    if not is_admin and payment.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own payments.",
        )

    return payment


# ---------------------------------------------------------------------------
# POST /payments/booking/{booking_id}/refund
# ---------------------------------------------------------------------------


@router.post("/booking/{booking_id}/refund", response_model=PaymentResponse)
async def refund_booking_payment(
    booking_id: UUID,
    current_user: CurrentUser = Depends(get_current_user),
    stripe_client: StripeClient = Depends(get_stripe_client),
) -> PaymentResponse:
    """
    Issue a full Stripe refund for a booking's payment.

    Authorised callers:
      - Admins (admin:payments:write or admin:scopes)
      - The venue owner (bookings-ms forwards their headers when they cancel)
    """
    payment = await payment_crud.get_by_booking_paid(booking_id)
    if payment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No paid payment found for this booking.",
        )

    is_admin = (
        PaymentScope.ADMIN in current_user.scopes
        or PaymentScope.ADMIN_WRITE in current_user.scopes
        or "admin:scopes" in current_user.scopes
    )
    is_venue_owner = current_user.id == payment.venue_owner_id

    if not (is_admin or is_venue_owner):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the venue owner or an admin can refund this payment.",
        )

    if not payment.stripe_payment_intent_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot refund: no payment intent on record.",
        )

    stripe_client.v1.refunds.create(
        params={"payment_intent": payment.stripe_payment_intent_id}
    )

    updated = await payment_crud.mark_refunded(payment.stripe_payment_intent_id)
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Refund issued but failed to update payment record.",
        )

    return PaymentResponse.model_validate(updated)


# ---------------------------------------------------------------------------
# POST /payments/webhook  (PUBLIC — no Traefik jwt-auth)
# ---------------------------------------------------------------------------


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    bookings_client: BookingsClient = Depends(get_bookings_client),
    stripe_client: StripeClient = Depends(get_stripe_client),
) -> dict:
    """
    Stripe webhook endpoint.

    Security:
      - Registered as a PUBLIC Traefik route (no forwardAuth).
      - Every event is verified via Stripe-Signature HMAC before processing.
      - Raw request bytes are used for verification — never the parsed body.
    """
    raw_body = await request.body()
    sig_header = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe_client.construct_event(
            raw_body, sig_header, settings.stripe_webhook_secret
        )
    except stripe.SignatureVerificationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Stripe signature.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid webhook payload.",
        ) from exc

    obj = event.data.object

    if event.type == "checkout.session.completed":
        await _handle_session_completed(obj)
    elif event.type == "checkout.session.expired":
        await _handle_session_expired(obj, bookings_client)
    elif event.type == "charge.refunded":
        await _handle_charge_refunded(obj)

    return {"received": True}


async def _handle_session_completed(session) -> None:  # type: ignore[type-arg]
    """Mark payment as PAID once Stripe confirms the Checkout Session."""
    payment_intent_id = session.payment_intent or ""
    await payment_crud.mark_paid(session.id, payment_intent_id)


async def _handle_session_expired(session, bookings_client: BookingsClient) -> None:  # type: ignore[type-arg]
    """
    Mark payment as FAILED and cancel the unpaid booking via bookings-ms.
    Failure to cancel the booking is logged but does not fail the webhook response
    (Stripe would retry, causing duplicate processing).
    """
    await payment_crud.mark_failed(session.id)

    booking_id_str = (session.metadata or {}).get(
        "booking_id"
    ) or session.client_reference_id
    if not booking_id_str:
        return

    try:
        booking_id = UUID(booking_id_str)
        await bookings_client.cancel_booking(booking_id, _get_system_admin())
    except (ValueError, Exception):
        # Silently swallow — in production, emit a structured log here
        pass


async def _handle_charge_refunded(charge) -> None:  # type: ignore[type-arg]
    """Sync refund status from Stripe.

    Also triggered by manual refunds issued via the Stripe Dashboard.
    """
    payment_intent_id = charge.payment_intent
    if payment_intent_id:
        await payment_crud.mark_refunded(payment_intent_id)


# ---------------------------------------------------------------------------
# POST /payments/{payment_id}/abandon
# ---------------------------------------------------------------------------


@router.post("/{payment_id}/abandon", status_code=status.HTTP_200_OK)
async def abandon_checkout(
    payment_id: UUID,
    current_user: CurrentUser = Depends(get_current_user),
    stripe_client: StripeClient = Depends(get_stripe_client),
) -> dict:
    """
    Immediately expire a PENDING Stripe Checkout Session that the user
    chose not to complete (e.g. clicked back).

    This triggers the checkout.session.expired webhook, which marks the
    payment as FAILED and cancels the booking via bookings-ms.
    """
    payment = await payment_crud.get_pending_by_id(payment_id)
    if payment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending payment not found.",
        )

    is_admin = (
        PaymentScope.ADMIN in current_user.scopes
        or PaymentScope.ADMIN_WRITE in current_user.scopes
    )
    if not is_admin and payment.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only abandon your own payments.",
        )

    try:
        stripe_client.v1.checkout.sessions.expire(payment.stripe_session_id)
    except stripe.InvalidRequestError:
        # Session already expired or completed — webhook will handle the rest
        pass

    return {"abandoned": True}


# ---------------------------------------------------------------------------
# DELETE /payments/{payment_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/{payment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(can_admin_delete_payment)],
)
async def delete_payment(payment_id: UUID) -> None:
    deleted = await payment_crud.delete_payment(payment_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Payment not found.",
        )
