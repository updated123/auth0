"""
Webhook receiver for Auth0 Action events.

POST /webhooks/idp-events

Auth0 Actions (Post-Login flow) POST events here with an HMAC-SHA256 signature
in the X-Auth0-Signature header.  We verify the signature using the shared
WEBHOOK_SECRET before processing.

Supported event types:
  - user.signup_complete    → create/update PlatformUser, run approval engine
  - user.login              → refresh idp_sub link if needed, log login
  - user.invited            → create pending PlatformUser record

Event payload shape (sent by auth0_action.js):
{
  "event_type": "user.signup_complete",
  "user": {
    "sub": "auth0|abc123",
    "email": "alice@example.com",
    "email_verified": true
  },
  "org_id": "org_acmecorp",          // optional — platform org ID
  "auth0_org_id": "org_auth0_abc",   // optional — Auth0 org ID
  "role_requested": "analyst",       // optional
  "timestamp": "2024-01-15T10:30:00Z"
}
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.services.user_service import create_invited_user, get_org, on_user_signup_complete

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def _verify_signature(body: bytes, signature_header: Optional[str]) -> bool:
    """
    Verify HMAC-SHA256 signature.

    Expected header format: sha256=<hex_digest>
    """
    if not signature_header:
        return False

    try:
        scheme, received_sig = signature_header.split("=", 1)
        if scheme != "sha256":
            return False
    except ValueError:
        return False

    expected_sig = hmac.new(
        settings.webhook_secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected_sig, received_sig)


# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

async def _handle_signup_complete(event: Dict[str, Any], db: AsyncSession) -> dict:
    """
    Process user.signup_complete event.

    Flow:
    1. Find platform user by sub or email.
    2. Link idp_sub.
    3. Advance status INVITED → PENDING_ROLE_ASSIGNMENT.

    Admin must now assign a role via POST /api/admin/users/{id}/assign-role.
    """
    user_data = event.get("user", {})
    sub = user_data.get("sub")
    email = user_data.get("email")
    email_verified = user_data.get("email_verified", False)
    org_id = event.get("org_id", "org_acmecorp")

    if not sub or not email:
        return {"status": "error", "message": "Missing sub or email in event."}

    user = await on_user_signup_complete(
        db=db,
        sub=sub,
        email=email,
        email_verified=email_verified,
        org_id=org_id,
    )

    return {
        "status": "ok",
        "event": "user.signup_complete",
        "platform_user_id": user.id,
        "user_status": user.status,
        "next_step": "Admin must assign a role via POST /api/admin/users/{id}/assign-role",
    }


async def _handle_login(event: Dict[str, Any], db: AsyncSession) -> dict:
    """
    Process user.login event — refresh the sub link if needed.
    """
    user_data = event.get("user", {})
    sub = user_data.get("sub")
    email = user_data.get("email")
    email_verified = user_data.get("email_verified", False)

    if not sub:
        return {"status": "error", "message": "Missing sub."}

    # Ensure the sub is linked
    if email:
        await link_idp_sub(db=db, email=email, sub=sub, email_verified=email_verified)

    logger.debug("user.login event processed for sub=%s", sub)
    return {"status": "ok", "event": "user.login"}


async def _handle_invited(event: Dict[str, Any], db: AsyncSession) -> dict:
    """
    Process user.invited event — create a pending PlatformUser record.
    """
    from app.services.user_service import create_invited_user

    invitee = event.get("invitee", {})
    email = invitee.get("email")
    org_id = event.get("org_id", "org_acmecorp")
    invited_by = event.get("invited_by", "system")

    if not email:
        return {"status": "error", "message": "Missing invitee email."}

    user = await create_invited_user(
        db=db,
        email=email,
        org_id=org_id,
        invited_by=invited_by,
    )
    return {
        "status": "ok",
        "event": "user.invited",
        "platform_user_id": user.id,
    }


# ---------------------------------------------------------------------------
# Webhook endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/idp-events",
    summary="Receive Auth0 Action webhook events",
    status_code=status.HTTP_200_OK,
)
async def receive_idp_event(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Entry point for Auth0 Actions webhook.

    Verifies HMAC-SHA256 signature, parses event type, and routes
    to the appropriate handler.
    """
    body = await request.body()
    signature = request.headers.get("X-Auth0-Signature")

    if not _verify_signature(body, signature):
        logger.warning(
            "Webhook signature verification failed. Header: %s",
            signature,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature.",
        )

    try:
        event: Dict[str, Any] = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {exc}",
        ) from exc

    event_type = event.get("event_type", "")
    logger.info("Received webhook event: %s", event_type)

    handlers = {
        "user.signup_complete": _handle_signup_complete,
        "user.login": _handle_login,
        "user.invited": _handle_invited,
    }

    handler = handlers.get(event_type)
    if handler is None:
        logger.info("Unhandled event type: %s", event_type)
        return {"status": "ignored", "event_type": event_type}

    try:
        result = await handler(event, db)
    except Exception as exc:
        logger.exception("Error processing webhook event %s: %s", event_type, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Event processing error: {exc}",
        ) from exc

    return result
