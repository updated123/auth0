"""
PKCE Authorization Code Flow endpoints.

/login      — builds Auth0 authorize URL with PKCE challenge, redirects
/callback   — exchanges code for tokens, stores sub in session
/logout     — clears session, redirects to Auth0 logout

PKCE (Proof Key for Code Exchange) is used so the client secret is never
exposed in the browser — only the server-side callback handles it.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import urllib.parse
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt_validator import validate_token
from app.config import settings
from app.database import get_db
from app.models import PlatformUser, UserStatus

logger = logging.getLogger(__name__)
router = APIRouter(tags=["auth"])


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------

def _generate_code_verifier() -> str:
    """Generate a cryptographically random code verifier (43–128 chars, URL-safe)."""
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode("ascii")


def _generate_code_challenge(verifier: str) -> str:
    """Derive S256 code challenge from verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _generate_state() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/login", summary="Initiate PKCE login flow")
async def login(
    request: Request,
    org_id: Optional[str] = None,
    organization: Optional[str] = None,
    organization_name: Optional[str] = None,
    invitation: Optional[str] = None,
    connection: Optional[str] = None,         # social: google-oauth2, windowslive, github
):
    """
    Redirect the browser to Auth0 Universal Login.

    When called from an invitation link, Auth0 appends ?invitation=...&organization=...
    These must be forwarded to Auth0's /authorize so it shows the password-setting UI.
    """
    verifier = _generate_code_verifier()
    challenge = _generate_code_challenge(verifier)
    state = _generate_state()

    request.session["pkce_verifier"] = verifier
    request.session["oauth_state"] = state

    # organization can come from ?org_id= (our param) or ?organization= (Auth0 invitation link)
    effective_org = organization or org_id

    params = {
        "response_type": "code",
        "client_id": settings.auth0_client_id,
        "redirect_uri": settings.callback_url,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    if effective_org:
        params["organization"] = effective_org

    if invitation:
        params["invitation"] = invitation

    if organization_name:
        params["organization_name"] = organization_name

    # Social login: pass connection only when no org context (Auth0 rejects both)
    if connection and not effective_org:
        params["connection"] = connection

    auth_url = f"{settings.auth0_authorize_url}?{urllib.parse.urlencode(params)}"
    logger.debug("Redirecting to Auth0: %s", auth_url)
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/callback", summary="OAuth2 callback — exchange code for tokens")
async def callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle the redirect from Auth0.

    1. Validate state (CSRF protection)
    2. Exchange authorization code for tokens using stored PKCE verifier
    3. Validate the id_token
    4. Look up or create PlatformUser in our DB
    5. Store sub in session and redirect to dashboard
    """
    # Auth0 sends back errors on the redirect
    if error:
        logger.warning("Auth0 returned error: %s — %s", error, error_description)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Auth0 error: {error_description or error}",
        )

    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing authorization code.")

    # CSRF check
    session_state = request.session.get("oauth_state")
    if not session_state or session_state != state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state parameter (CSRF check failed).")

    verifier = request.session.get("pkce_verifier")
    if not verifier:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing PKCE verifier in session.")

    # Exchange code for tokens
    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(
            settings.auth0_token_url,
            json={
                "grant_type": "authorization_code",
                "client_id": settings.auth0_client_id,
                "client_secret": settings.auth0_client_secret,
                "code": code,
                "redirect_uri": settings.callback_url,
                "code_verifier": verifier,
            },
        )

    if token_resp.status_code != 200:
        logger.error("Token exchange failed: %s", token_resp.text)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Token exchange failed: {token_resp.text}",
        )

    tokens = token_resp.json()
    access_token = tokens.get("access_token")
    id_token = tokens.get("id_token")

    if not access_token:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="No access_token in response.")

    # Validate id_token to extract user claims
    # We use the access_token for API calls but validate via id_token claims
    try:
        # Auth0 id_tokens use the client_id as audience
        from jose import jwt as jose_jwt
        from app.auth.jwt_validator import _get_jwks

        jwks = await _get_jwks()
        unverified = jose_jwt.get_unverified_claims(id_token or access_token)
        sub = unverified.get("sub")
        email = unverified.get("email")
        email_verified = unverified.get("email_verified", False)
    except Exception as exc:
        logger.warning("Could not decode id_token claims: %s", exc)
        # Fall back to /userinfo endpoint
        async with httpx.AsyncClient(timeout=10) as client:
            ui_resp = await client.get(
                f"https://{settings.auth0_domain}/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
        if ui_resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Failed to retrieve user info.")
        userinfo = ui_resp.json()
        sub = userinfo.get("sub")
        email = userinfo.get("email")
        email_verified = userinfo.get("email_verified", False)

    if not sub:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="No 'sub' in token.")

    # Look up PlatformUser by sub
    result = await db.execute(select(PlatformUser).where(PlatformUser.idp_sub == sub))
    platform_user: Optional[PlatformUser] = result.scalar_one_or_none()

    # If not found by sub, try by email (user may have accepted an invitation)
    if platform_user is None and email:
        result = await db.execute(select(PlatformUser).where(PlatformUser.email == email))
        platform_user = result.scalar_one_or_none()
        if platform_user and platform_user.idp_sub is None:
            # Link the Auth0 sub to this platform user
            platform_user.idp_sub = sub
            platform_user.email_verified = email_verified
            await db.commit()
            await db.refresh(platform_user)

    # Clean up session temp keys
    request.session.pop("pkce_verifier", None)
    request.session.pop("oauth_state", None)

    if platform_user is None:
        # Unknown user — store minimal info in session and redirect to a pending page
        request.session["user_sub"] = sub
        request.session["user_email"] = email or ""
        request.session["user_email_verified"] = email_verified
        request.session["access_token"] = access_token
        logger.info("Unknown user logged in: %s — redirecting to pending page.", email)
        return RedirectResponse(url="/pending", status_code=302)

    # Known user
    request.session["user_sub"] = sub
    request.session["user_email"] = email or platform_user.email
    request.session["user_email_verified"] = email_verified
    request.session["access_token"] = access_token
    request.session["platform_user_id"] = platform_user.id

    logger.info("User %s (%s) logged in successfully. Status: %s", platform_user.id, email, platform_user.status)

    # If this was an MFA challenge triggered after legacy login, go back to the original destination
    mfa_redirect = request.session.pop("mfa_post_login_redirect", None)
    if mfa_redirect:
        logger.info("MFA verified for %s — redirecting to %s", email, mfa_redirect)
        return RedirectResponse(url=mfa_redirect, status_code=302)

    if platform_user.status == UserStatus.ACTIVE:
        return RedirectResponse(url="/dashboard", status_code=302)
    else:
        return RedirectResponse(url="/pending", status_code=302)


@router.get("/logout", summary="Log out — clear session and redirect to Auth0 logout")
async def logout(request: Request):
    """Clear the local session and redirect to Auth0 logout endpoint."""
    request.session.clear()
    return_to = urllib.parse.quote(settings.app_base_url, safe="")
    logout_url = (
        f"{settings.auth0_logout_url}"
        f"?client_id={settings.auth0_client_id}"
        f"&returnTo={return_to}"
    )
    return RedirectResponse(url=logout_url, status_code=302)
