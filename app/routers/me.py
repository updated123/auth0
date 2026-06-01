"""
GET /api/me

Returns the thin IdP claims alongside the full platform context resolved from DB.
This endpoint illustrates the core architecture principle:
  - JWT carries only sub/email/email_verified  (IdP responsibility)
  - Role, org, entitlements come from the platform DB  (platform responsibility)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user_claims, require_active_user
from app.database import get_db
from app.models import PlatformUser

router = APIRouter(prefix="/api", tags=["me"])


@router.get(
    "/me",
    summary="Return thin JWT claims + resolved platform context",
    response_model=None,
)
async def get_me(
    claims: dict = Depends(get_current_user_claims),
    user: PlatformUser = Depends(require_active_user),
) -> dict:
    """
    Combines:
    - idp_claims: what the JWT asserts (sub, email, email_verified only)
    - platform_context: what our DB says about this user

    No business logic should ever read role/entitlements from the JWT.
    Always call this endpoint (or the equivalent DB lookup) instead.
    """
    return {
        "idp_claims": {
            "sub": claims.get("sub"),
            "email": claims.get("email"),
            "email_verified": claims.get("email_verified", False),
        },
        "platform_context": {
            "platform_user_id": user.id,
            "tenant_id": user.org_id,
            "role": user.role,
            "entitlements": user.entitlements if isinstance(user.entitlements, list) else [],
            "status": user.status,
        },
    }
