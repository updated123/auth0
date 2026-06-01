from pathlib import Path
"""
TCS Super-Admin routes.

TCS is the platform owner — they can see all organisations and trigger
bulk migration across all orgs at once.

GET  /tcs/dashboard          — HTML overview of all orgs + migration status
POST /api/tcs/migrate/org/{org_id}  — migrate all pending users in one org
POST /api/tcs/migrate/all    — migrate all pending users across all orgs
GET  /api/tcs/status         — JSON migration status per org
"""
from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import MigrationStatus, Organization, PlatformUser, UserStatus

logger = logging.getLogger(__name__)
router = APIRouter(tags=["tcs-admin"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


# ---------------------------------------------------------------------------
# Auth0 helpers
# ---------------------------------------------------------------------------

async def _mgmt_token() -> str:
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


async def _ensure_auth0_user(token: str, email: str) -> str:
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(
            f"https://{settings.auth0_domain}/api/v2/users",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "email": email,
                "email_verified": True,
                "connection": "Username-Password-Authentication",
                "password": f"TempMig!{email[:4]}9#Xz",
                "verify_email": False,
            },
        )
        if r.status_code == 409:
            sr = await c.get(
                f"https://{settings.auth0_domain}/api/v2/users-by-email",
                headers={"Authorization": f"Bearer {token}"},
                params={"email": email},
            )
            users = sr.json()
            return users[0]["user_id"] if users else ""
        r.raise_for_status()
        return r.json()["user_id"]


async def _send_reset_email(email: str) -> None:
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(
            f"https://{settings.auth0_domain}/dbconnections/change_password",
            json={
                "client_id": settings.auth0_client_id,
                "email": email,
                "connection": "Username-Password-Authentication",
            },
        )
        r.raise_for_status()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_org_stats(db: AsyncSession, org: Organization) -> dict:
    result = await db.execute(
        select(PlatformUser).where(PlatformUser.org_id == org.id)
    )
    all_users = list(result.scalars().all())
    legacy = [u for u in all_users if u.password_hash is not None]
    migrated = [u for u in legacy if u.idp_sub is not None]
    email_sent = [u for u in legacy if u.migration_status == MigrationStatus.EMAIL_SENT and u.idp_sub is None]
    pending = [u for u in legacy if u.migration_status == MigrationStatus.PENDING and u.idp_sub is None]
    new_users = [u for u in all_users if u.password_hash is None]

    return {
        "org": {"id": org.id, "name": org.name, "auth0_org_id": org.auth0_org_id},
        "total": len(all_users),
        "legacy_total": len(legacy),
        "migrated": len(migrated),
        "email_sent": len(email_sent),
        "pending": len(pending),
        "new_users": len(new_users),
        "pct": round(len(migrated) / len(legacy) * 100) if legacy else 100,
    }


async def _migrate_users(db: AsyncSession, users: list[PlatformUser]) -> list[dict]:
    if not users:
        return []

    token = await _mgmt_token()
    results = []

    for user in users:
        try:
            auth0_id = await _ensure_auth0_user(token, user.email)
            await _send_reset_email(user.email)
            user.migration_status = MigrationStatus.EMAIL_SENT
            db.add(user)
            results.append({"email": user.email, "status": "email_sent", "auth0_id": auth0_id})
            logger.info("Migration email sent: %s → %s", user.email, auth0_id)
        except Exception as exc:
            results.append({"email": user.email, "status": "error", "error": str(exc)})
            logger.error("Migration failed for %s: %s", user.email, exc)

    await db.commit()
    return results


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/demo", response_class=HTMLResponse, include_in_schema=False)
async def demo_home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("demo.html", {"request": request})


@router.get("/social-login", response_class=HTMLResponse, include_in_schema=False)
async def social_login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("social_login.html", {"request": request, "hide_signin": True})


@router.get("/tcs/login", response_class=HTMLResponse, include_in_schema=False)
async def tcs_login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("legacy_login.html", {
        "request": request,
        "error": None,
        "hint": "TCS Super Admin login — enter your TCS admin credentials.",
        "hide_signin": True,
    })


@router.get("/org/login", response_class=HTMLResponse, include_in_schema=False)
async def org_login_redirect(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("legacy_login.html", {
        "request": request,
        "error": None,
        "hint": "Log in as an Org Admin to manage your organisation's users.",
        "hide_signin": True,
    })


@router.get("/org/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def org_dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    user_id = request.session.get("legacy_user_id")
    if not user_id:
        return RedirectResponse(url="/org/login", status_code=302)

    result = await db.execute(select(PlatformUser).where(PlatformUser.id == user_id))
    admin: PlatformUser | None = result.scalar_one_or_none()
    if not admin or admin.role != "admin":
        return RedirectResponse(url="/org/login", status_code=302)

    result = await db.execute(select(Organization).where(Organization.id == admin.org_id))
    org: Organization | None = result.scalar_one_or_none()

    all_users_r = await db.execute(select(PlatformUser).where(PlatformUser.org_id == admin.org_id))
    all_users = list(all_users_r.scalars().all())

    pending = [u for u in all_users if u.status == "pending_role_assignment"]

    stats = {
        "total": len(all_users),
        "active": sum(1 for u in all_users if u.status == "active"),
        "pending": len(pending),
        "invited": sum(1 for u in all_users if u.status == "invited"),
    }

    return templates.TemplateResponse("org_dashboard.html", {
        "request": request,
        "user": admin,
        "admin": admin,
        "org": org,
        "users": [u.to_dict() for u in all_users],
        "pending_users": [u.to_dict() for u in pending],
        "stats": stats,
        "roles": ["admin", "member"],
        "active_page": "admin",
    })


TCS_ADMIN_EMAILS = {"utsav.patel@ignitedata.ai", "akash.bhandwalkar@ignitedata.ai"}


@router.get("/tcs/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def tcs_dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    # Require legacy session as TCS admin
    if request.session.get("legacy_email") not in TCS_ADMIN_EMAILS:
        return RedirectResponse(url="/tcs/login", status_code=302)

    result = await db.execute(select(Organization))
    orgs = list(result.scalars().all())

    org_stats = [await _get_org_stats(db, org) for org in orgs]

    total_legacy = sum(s["legacy_total"] for s in org_stats)
    total_migrated = sum(s["migrated"] for s in org_stats)
    total_pending = sum(s["pending"] for s in org_stats)
    total_email_sent = sum(s["email_sent"] for s in org_stats)

    return templates.TemplateResponse(
        "tcs_dashboard.html",
        {
            "request": request,
            "org_stats": org_stats,
            "total_legacy": total_legacy,
            "total_migrated": total_migrated,
            "total_pending": total_pending,
            "total_email_sent": total_email_sent,
            "overall_pct": round(total_migrated / total_legacy * 100) if total_legacy else 100,
        },
    )


@router.get("/api/tcs/status", summary="Migration status across all orgs")
async def tcs_status(db: AsyncSession = Depends(get_db)) -> dict:
    result = await db.execute(select(Organization))
    orgs = list(result.scalars().all())
    org_stats = [await _get_org_stats(db, org) for org in orgs]
    return {"organisations": org_stats}


@router.post("/api/tcs/migrate/org/{org_id}", summary="Migrate all pending users in one org")
async def migrate_org(
    org_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(PlatformUser).where(
            PlatformUser.org_id == org_id,
            PlatformUser.password_hash.isnot(None),
            PlatformUser.idp_sub.is_(None),
            PlatformUser.migration_status == MigrationStatus.PENDING,
        )
    )
    users = list(result.scalars().all())
    results = await _migrate_users(db, users)
    return {
        "org_id": org_id,
        "processed": len(results),
        "results": results,
    }


@router.post("/api/tcs/migrate/all", summary="Migrate ALL pending legacy users across ALL orgs")
async def migrate_all(db: AsyncSession = Depends(get_db)) -> dict:
    result = await db.execute(
        select(PlatformUser).where(
            PlatformUser.password_hash.isnot(None),
            PlatformUser.idp_sub.is_(None),
            PlatformUser.migration_status == MigrationStatus.PENDING,
        )
    )
    users = list(result.scalars().all())
    results = await _migrate_users(db, users)

    sent = [r for r in results if r["status"] == "email_sent"]
    errors = [r for r in results if r["status"] == "error"]

    return {
        "message": f"Migration triggered for {len(sent)} user(s) across all organisations.",
        "total_processed": len(results),
        "emails_sent": len(sent),
        "errors": len(errors),
        "results": results,
    }
