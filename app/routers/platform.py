from pathlib import Path
"""
Platform-level routes — architecture overview, account recovery, document access demo.

GET  /architecture                      → architecture.html (standalone dark page)
GET  /account-recovery                  → account_recovery.html
GET  /documents                         → documents.html
POST /api/account/resend-verification   → Auth0 Management API: resend email verification
POST /api/account/unlock                → Auth0 Management API: unblock user
"""
from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr

from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["platform"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


# ---------------------------------------------------------------------------
# Auth0 Management API helpers (same M2M token pattern as tcs_admin.py)
# ---------------------------------------------------------------------------

async def _mgmt_token() -> str:
    """Obtain a Management API access token via client_credentials."""
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(
            f"https://{settings.auth0_domain}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": settings.auth0_mgmt_client_id,
                "client_secret": settings.auth0_mgmt_client_secret,
                "audience": f"https://{settings.auth0_domain}/api/v2/",
            },
        )
        r.raise_for_status()
        return r.json()["access_token"]


async def _get_user_by_email(token: str, email: str) -> dict | None:
    """Look up a single Auth0 user by email address."""
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(
            f"https://{settings.auth0_domain}/api/v2/users-by-email",
            headers={"Authorization": f"Bearer {token}"},
            params={"email": email},
        )
        r.raise_for_status()
        users = r.json()
        return users[0] if users else None


# ---------------------------------------------------------------------------
# Request/response schemas
# ---------------------------------------------------------------------------

class EmailRequest(BaseModel):
    email: str


# ---------------------------------------------------------------------------
# Template routes
# ---------------------------------------------------------------------------

@router.get("/architecture", response_class=HTMLResponse, include_in_schema=False)
async def architecture_page(request: Request) -> HTMLResponse:
    """Visual split-architecture overview — standalone dark page."""
    return templates.TemplateResponse("architecture.html", {"request": request})


@router.get("/account-recovery", response_class=HTMLResponse, include_in_schema=False)
async def account_recovery_page(request: Request) -> HTMLResponse:
    """Account recovery options — extends base.html."""
    return templates.TemplateResponse(
        "account_recovery.html",
        {"request": request, "hide_signin": True},
    )


@router.get("/documents", response_class=HTMLResponse, include_in_schema=False)
async def documents_page(request: Request) -> HTMLResponse:
    """Document access control demo — extends base.html."""
    return templates.TemplateResponse(
        "documents.html",
        {"request": request, "hide_signin": True},
    )


# ---------------------------------------------------------------------------
# Auth0 Management API endpoints
# ---------------------------------------------------------------------------

@router.post("/api/account/resend-verification", summary="Resend email verification")
async def resend_verification(body: EmailRequest) -> JSONResponse:
    """
    Trigger Auth0 to resend a verification email to the given address.

    Flow:
      1. Get M2M management token
      2. Look up user by email
      3. POST /api/v2/jobs/verification-email with user_id + client_id
    """
    try:
        token = await _mgmt_token()
    except Exception as exc:
        logger.error("Failed to obtain management token: %s", exc)
        raise HTTPException(status_code=502, detail="Could not connect to Auth0 Management API.")

    user = await _get_user_by_email(token, body.email)
    if not user:
        raise HTTPException(status_code=404, detail=f"No Auth0 user found for email: {body.email}")

    user_id = user["user_id"]

    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                f"https://{settings.auth0_domain}/api/v2/jobs/verification-email",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "user_id": user_id,
                    "client_id": settings.auth0_client_id,
                },
            )
            if r.status_code not in (200, 201):
                detail = r.json().get("message", r.text)
                logger.error("Auth0 resend-verification error %s: %s", r.status_code, detail)
                raise HTTPException(status_code=r.status_code, detail=detail)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("resend_verification failed for %s: %s", body.email, exc)
        raise HTTPException(status_code=502, detail=str(exc))

    logger.info("Verification email resent to %s (%s)", body.email, user_id)
    return JSONResponse({"message": f"Verification email sent to {body.email}.", "user_id": user_id})


@router.post("/api/account/unlock", summary="Unblock a blocked Auth0 user")
async def unlock_account(body: EmailRequest) -> JSONResponse:
    """
    Unblock a user account that Auth0 has blocked (too many failed attempts).

    Flow:
      1. Get M2M management token
      2. Look up user by email
      3. PATCH /api/v2/users/{user_id} with {"blocked": false}
    """
    try:
        token = await _mgmt_token()
    except Exception as exc:
        logger.error("Failed to obtain management token: %s", exc)
        raise HTTPException(status_code=502, detail="Could not connect to Auth0 Management API.")

    user = await _get_user_by_email(token, body.email)
    if not user:
        raise HTTPException(status_code=404, detail=f"No Auth0 user found for email: {body.email}")

    user_id = user["user_id"]

    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.patch(
                f"https://{settings.auth0_domain}/api/v2/users/{user_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"blocked": False},
            )
            if r.status_code not in (200, 201):
                detail = r.json().get("message", r.text)
                logger.error("Auth0 unblock error %s: %s", r.status_code, detail)
                raise HTTPException(status_code=r.status_code, detail=detail)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("unlock_account failed for %s: %s", body.email, exc)
        raise HTTPException(status_code=502, detail=str(exc))

    was_blocked = user.get("blocked", False)
    logger.info("Unblocked user %s (%s) — was_blocked=%s", body.email, user_id, was_blocked)
    return JSONResponse({
        "message": f"Account for {body.email} has been unblocked.",
        "user_id": user_id,
        "was_blocked": was_blocked,
    })
