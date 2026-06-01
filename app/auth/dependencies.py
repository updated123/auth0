"""
FastAPI dependency injection for authentication and authorisation.

Provides:
  - get_current_user_claims()  — validates Bearer JWT, returns thin claims dict
  - require_active_user()      — validates JWT + checks platform DB for ACTIVE status
  - require_platform_admin()   — as above but also enforces platform_admin role
  - get_session_user()         — reads user info from cookie session (PKCE flow)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt_validator import TokenValidationError, extract_thin_claims, validate_token
from app.database import get_db
from app.models import PlatformUser, UserStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bearer token extraction
# ---------------------------------------------------------------------------

def _extract_bearer(request: Request) -> Optional[str]:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return None


# ---------------------------------------------------------------------------
# Dependency: validate Bearer JWT → thin claims
# ---------------------------------------------------------------------------

async def get_current_user_claims(request: Request) -> Dict[str, Any]:
    """
    FastAPI dependency that validates the Bearer JWT and returns thin claims.

    Raises HTTP 401 on any validation error.
    """
    token = _extract_bearer(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = await validate_token(token)
    except TokenValidationError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    return extract_thin_claims(payload)


# ---------------------------------------------------------------------------
# Dependency: JWT + platform DB lookup → PlatformUser
# ---------------------------------------------------------------------------

async def require_active_user(
    claims: Dict[str, Any] = Depends(get_current_user_claims),
    db: AsyncSession = Depends(get_db),
) -> PlatformUser:
    """
    Validates the JWT and looks up the corresponding PlatformUser.

    Raises:
      401 — token invalid
      403 — user not found in platform DB or not ACTIVE
    """
    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing 'sub'.")

    result = await db.execute(select(PlatformUser).where(PlatformUser.idp_sub == sub))
    user: Optional[PlatformUser] = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User not found in platform. Contact your administrator.",
        )

    if user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account not active (status: {user.status}). Access denied.",
        )

    return user


# ---------------------------------------------------------------------------
# Dependency: platform admin only
# ---------------------------------------------------------------------------

async def require_platform_admin(
    user: PlatformUser = Depends(require_active_user),
) -> PlatformUser:
    """Raises HTTP 403 if the authenticated user is not a platform_admin."""
    if user.role != "platform_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform admin role required.",
        )
    return user


# ---------------------------------------------------------------------------
# Session-based dependency (PKCE cookie flow for browser UI)
# ---------------------------------------------------------------------------

async def get_session_user(request: Request, db: AsyncSession = Depends(get_db)) -> Optional[PlatformUser]:
    """
    Reads 'user_sub' from the signed cookie session.
    Returns None if the user is not logged in (does not raise).
    """
    session = request.session
    sub = session.get("user_sub")
    if not sub:
        return None

    result = await db.execute(select(PlatformUser).where(PlatformUser.idp_sub == sub))
    return result.scalar_one_or_none()


async def require_session_user(request: Request, db: AsyncSession = Depends(get_db)) -> PlatformUser:
    """
    Accepts auth in priority order:
    1. Bearer token (Postman / API clients)
    2. Auth0 PKCE session cookie (browser)
    3. Legacy session cookie (legacy-login)
    """
    user = None

    # 1. Bearer token
    token = _extract_bearer(request)
    if token:
        try:
            from app.auth.jwt_validator import validate_token, extract_thin_claims
            payload = await validate_token(token)
            claims = extract_thin_claims(payload)
            sub = claims.get("sub")
            if sub:
                result = await db.execute(select(PlatformUser).where(PlatformUser.idp_sub == sub))
                user = result.scalar_one_or_none()
            # M2M token (no sub match) — look up by email claim
            if user is None:
                email = claims.get("email")
                if email:
                    result = await db.execute(select(PlatformUser).where(PlatformUser.email == email))
                    user = result.scalar_one_or_none()
        except Exception:
            pass

    # 2. Auth0 PKCE session
    if user is None:
        user = await get_session_user(request, db)

    # 3. Legacy session
    if user is None:
        legacy_id = request.session.get("legacy_user_id")
        if legacy_id:
            result = await db.execute(select(PlatformUser).where(PlatformUser.id == legacy_id))
            user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Provide a Bearer token or log in.",
        )
    if user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account not active (status: {user.status}).",
        )
    return user


async def require_session_admin(
    user: PlatformUser = Depends(require_session_user),
) -> PlatformUser:
    """Raises HTTP 403 if the session user is not an admin (any admin role)."""
    if user.role not in ("platform_admin", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required.",
        )
    return user
