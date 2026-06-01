"""
Ignite Data Platform — Auth0 / Okta CIC POC
============================================

Architecture: IdP = credentials only. Platform backend owns all tenant/role/
entitlement context. JWT is thin: sub, email, email_verified only.

Run:
    pip install -r requirements.txt
    cp .env.example .env        # fill in your Auth0 credentials
    python main.py

Or with uvicorn directly:
    uvicorn main:app --reload --port 8000
"""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import httpx
from app.auth.dependencies import get_session_user, require_session_admin, require_session_user
from app.config import settings
from app.database import AsyncSessionLocal, create_tables, get_db, seed_data
from app.models import Organization, PlatformUser
from app.routers import admin, approvals, auth, me, webhooks
from app.routers import legacy_auth, migration, tcs_admin, subscriptions
from app.routers import platform as platform_router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("main")


# ---------------------------------------------------------------------------
# Application lifespan (replaces deprecated @app.on_event)
# ---------------------------------------------------------------------------

async def _enable_org_connections() -> None:
    """Ensure Username-Password-Authentication is enabled for every Auth0 org."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Get M2M token
            r = await client.post(
                f"https://{settings.auth0_domain}/oauth/token",
                json={
                    "grant_type": "client_credentials",
                    "client_id": settings.auth0_mgmt_client_id,
                    "client_secret": settings.auth0_mgmt_client_secret,
                    "audience": f"https://{settings.auth0_domain}/api/v2/",
                },
            )
            r.raise_for_status()
            token = r.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            # Find the Username-Password-Authentication connection ID
            cr = await client.get(
                f"https://{settings.auth0_domain}/api/v2/connections",
                headers=headers,
                params={"name": "Username-Password-Authentication", "fields": "id,name"},
            )
            cr.raise_for_status()
            connections = cr.json()
            if not connections:
                logger.warning("Username-Password-Authentication connection not found in Auth0")
                return
            conn_id = connections[0]["id"]

            # Enable it on every org that has an auth0_org_id
            from sqlalchemy import select
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(Organization).where(Organization.auth0_org_id.isnot(None))
                )
                orgs = result.scalars().all()

            for org in orgs:
                # Check if already enabled
                existing = await client.get(
                    f"https://{settings.auth0_domain}/api/v2/organizations/{org.auth0_org_id}/enabled_connections",
                    headers=headers,
                )
                already = any(c["connection_id"] == conn_id for c in existing.json()) if existing.status_code == 200 else False
                if not already:
                    resp = await client.post(
                        f"https://{settings.auth0_domain}/api/v2/organizations/{org.auth0_org_id}/enabled_connections",
                        headers=headers,
                        json={"connection_id": conn_id, "assign_membership_on_login": False},
                    )
                    if resp.status_code in (200, 201):
                        logger.info("Enabled Username-Password-Authentication for org %s (%s)", org.name, org.auth0_org_id)
                    else:
                        logger.warning("Could not enable connection for org %s: %s", org.name, resp.text)
                else:
                    logger.info("Connection already enabled for org %s", org.name)
    except Exception as exc:
        logger.warning("_enable_org_connections skipped: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run startup/shutdown tasks."""
    logger.info("Starting up Auth0 POC — Ignite Data Platform")
    await create_tables()
    await seed_data()
    await _enable_org_connections()
    logger.info("Startup complete. Listening on %s", settings.app_base_url)
    yield
    logger.info("Shutting down.")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Ignite Data Platform — Auth0 POC",
    description=(
        "Demonstrates the IdP = credentials only architecture using Auth0 / Okta CIC. "
        "JWT carries only sub/email/email_verified; roles and entitlements are resolved "
        "from the platform database after token validation."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

# Session middleware — used for PKCE flow (stores code_verifier, user_sub)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="ignite_session",
    max_age=3600 * 8,  # 8 hours
    same_site="lax",
    https_only=settings.app_base_url.startswith("https://"),
)

# CORS — adjust origins for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

templates = Jinja2Templates(directory="app/templates")


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(auth.router)         # /login, /callback, /logout
app.include_router(me.router)           # /api/me
app.include_router(admin.router)        # /api/admin/...
app.include_router(approvals.router)    # /api/admin/approvals/...
app.include_router(webhooks.router)     # /webhooks/idp-events
app.include_router(legacy_auth.router)  # /legacy-login, /legacy-dashboard
app.include_router(migration.router)    # /api/migrate/...
app.include_router(tcs_admin.router)    # /tcs/dashboard, /api/tcs/migrate/...
app.include_router(subscriptions.router)  # /subscription/dashboard, /permissions/..., /mfa/...
app.include_router(platform_router.router)  # /architecture, /account-recovery, /documents, /api/account/...


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["system"], summary="Health check")
async def health() -> dict:
    """Returns service health status. No authentication required."""
    return {
        "status": "ok",
        "service": "ignite-data-platform-poc",
        "auth0_domain": settings.auth0_domain,
        "architecture": "thin-jwt",
    }


# ---------------------------------------------------------------------------
# Browser-facing template routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request, db=Depends(get_db)) -> HTMLResponse:
    """Landing page — shows login button if not authenticated."""
    user = await get_session_user(request, db)
    if user and user.status == "active":
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": user},
    )


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(
    request: Request,
    user: PlatformUser = Depends(require_session_user),
) -> HTMLResponse:
    """Post-login dashboard — requires active session."""
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "active_page": "dashboard",
        },
    )


@app.get("/me-page", response_class=HTMLResponse, include_in_schema=False)
async def me_page(
    request: Request,
    user: PlatformUser = Depends(require_session_user),
) -> HTMLResponse:
    """
    Template wrapper around /api/me — shows thin JWT claims vs platform context.
    Uses the session-stored claims so we don't need to re-validate the token.
    """
    idp_claims = {
        "sub": request.session.get("user_sub", user.idp_sub),
        "email": request.session.get("user_email", user.email),
        "email_verified": request.session.get("user_email_verified", user.email_verified),
    }
    platform_context = {
        "platform_user_id": user.id,
        "tenant_id": user.org_id,
        "role": user.role,
        "entitlements": user.entitlements if isinstance(user.entitlements, list) else [],
        "status": user.status,
    }
    full_response = {
        "idp_claims": idp_claims,
        "platform_context": platform_context,
    }
    return templates.TemplateResponse(
        "me.html",
        {
            "request": request,
            "user": user,
            "active_page": "me",
            "idp_claims": idp_claims,
            "platform_context": platform_context,
            "full_response": full_response,
        },
    )


@app.get("/approvals-page", response_class=HTMLResponse, include_in_schema=False)
async def approvals_page(
    request: Request,
    admin: PlatformUser = Depends(require_session_admin),
) -> HTMLResponse:
    """Approval queue admin page."""
    return templates.TemplateResponse(
        "approvals.html",
        {
            "request": request,
            "user": admin,
            "active_page": "approvals",
            "org_id": admin.org_id,
        },
    )


@app.get("/pending", response_class=HTMLResponse, include_in_schema=False)
async def pending_page(request: Request, db=Depends(get_db)) -> HTMLResponse:
    """Shown to users who have authenticated but whose account is not yet active."""
    from sqlalchemy import select
    from app.models import PlatformUser as PU

    user = await get_session_user(request, db)
    status_val = user.status if user else "pending_approval"

    return templates.TemplateResponse(
        "pending.html",
        {
            "request": request,
            "user": user,
            "status": status_val,
        },
    )


# ---------------------------------------------------------------------------
# Global exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(401)
async def unauthorized_handler(request: Request, exc) -> JSONResponse:
    # For browser requests, redirect to login
    if "text/html" in request.headers.get("accept", ""):
        return RedirectResponse(url="/login", status_code=302)
    return JSONResponse(
        status_code=401,
        content={"detail": "Authentication required."},
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.exception_handler(403)
async def forbidden_handler(request: Request, exc) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={"detail": str(exc.detail) if hasattr(exc, "detail") else "Forbidden."},
    )


# ---------------------------------------------------------------------------
# Dev server entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
