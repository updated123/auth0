"""
Legacy login — simulates the existing Kinsta DB authentication.

POST /legacy-login  — validate email + bcrypt password from platform DB
GET  /legacy-login  — render login form
GET  /migrate-now   — trigger Auth0 migration for the logged-in legacy user
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import urllib.parse

import bcrypt
import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import MigrationStatus, Organization, PlatformUser, UserStatus

logger = logging.getLogger(__name__)
router = APIRouter(tags=["legacy-auth"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/legacy-login", response_class=HTMLResponse, include_in_schema=False)
async def legacy_login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("legacy_login.html", {"request": request, "error": None})


@router.post("/legacy-login", response_class=HTMLResponse, include_in_schema=False)
async def legacy_login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    result = await db.execute(select(PlatformUser).where(PlatformUser.email == email))
    user: PlatformUser | None = result.scalar_one_or_none()

    # Validate password against stored bcrypt hash
    if (
        user is None
        or user.password_hash is None
        or not bcrypt.checkpw(password.encode(), user.password_hash.encode())
        or user.status != UserStatus.ACTIVE
    ):
        return templates.TemplateResponse(
            "legacy_login.html",
            {"request": request, "error": "Invalid email or password."},
            status_code=401,
        )

    # Store legacy session
    request.session["legacy_user_id"] = user.id
    request.session["legacy_email"] = user.email
    request.session["legacy_role"] = user.role
    request.session["legacy_org_id"] = user.org_id

    logger.info("Legacy login: %s (role=%s, org=%s)", email, user.role, user.org_id)

    # TCS super-admin — no MFA step, goes straight to TCS dashboard
    TCS_ADMIN_EMAILS = {"utsav.patel@ignitedata.ai", "akash.bhandwalkar@ignitedata.ai"}
    if user.email in TCS_ADMIN_EMAILS:
        return RedirectResponse(url="/tcs/dashboard", status_code=302)

    # Check if org requires MFA
    org_result = await db.execute(select(Organization).where(Organization.id == user.org_id))
    org = org_result.scalars().first()

    if org and org.mfa_required:
        # Store where to redirect after MFA completes
        dest = "/org/dashboard" if user.role == "admin" else "/legacy-dashboard"
        request.session["mfa_post_login_redirect"] = dest

        # Build PKCE + MFA challenge redirect to Auth0
        verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
        state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
        request.session["pkce_verifier"] = verifier
        request.session["oauth_state"] = state

        params = {
            "response_type": "code",
            "client_id": settings.auth0_client_id,
            "redirect_uri": settings.callback_url,
            "scope": "openid profile email",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "login",
            "login_hint": user.email,
            "acr_values": "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
        }
        if org.auth0_org_id:
            params["organization"] = org.auth0_org_id

        auth_url = f"https://{settings.auth0_domain}/authorize?{urllib.parse.urlencode(params)}"
        logger.info("MFA required for %s — redirecting to Auth0 MFA challenge", email)
        return RedirectResponse(url=auth_url, status_code=302)

    # Org admins go to their org admin panel
    if user.role == "admin":
        return RedirectResponse(url="/org/dashboard", status_code=302)
    return RedirectResponse(url="/legacy-dashboard", status_code=302)


@router.get("/legacy-dashboard", response_class=HTMLResponse, include_in_schema=False)
async def legacy_dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    user_id = request.session.get("legacy_user_id")
    if not user_id:
        return RedirectResponse(url="/legacy-login", status_code=302)

    result = await db.execute(select(PlatformUser).where(PlatformUser.id == user_id))
    user: PlatformUser | None = result.scalar_one_or_none()
    if not user:
        return RedirectResponse(url="/legacy-login", status_code=302)

    return templates.TemplateResponse(
        "legacy_dashboard.html",
        {"request": request, "user": user},
    )


@router.get("/legacy-logout", include_in_schema=False)
async def legacy_logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/legacy-login", status_code=302)


@router.get("/forgot-password", response_class=HTMLResponse, include_in_schema=False)
async def forgot_password_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@router.post("/forgot-password", response_class=HTMLResponse, include_in_schema=False)
async def forgot_password_submit(
    request: Request,
    email: str = Form(...),
) -> HTMLResponse:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"https://{settings.auth0_domain}/dbconnections/change_password",
                json={
                    "client_id": settings.auth0_client_id,
                    "email": email,
                    "connection": "Username-Password-Authentication",
                },
            )
            resp.raise_for_status()

        return templates.TemplateResponse("forgot_password.html", {
            "request": request,
            "success": True,
            "email": email,
        })
    except Exception as exc:
        logger.error("Password reset failed for %s: %s", email, exc)
        return templates.TemplateResponse("forgot_password.html", {
            "request": request,
            "error": "Failed to send reset email. Please try again.",
            "email": email,
        }, status_code=500)
