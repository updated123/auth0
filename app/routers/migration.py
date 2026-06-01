"""
Migration API — triggers Auth0 account creation + activation email for a legacy user.

POST /api/migrate/send-activation   — for the currently logged-in legacy user
POST /api/migrate/run-all           — bulk migrate all pending legacy users (admin)
"""
from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import MigrationStatus, PlatformUser

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/migrate", tags=["migration"])


async def _get_mgmt_token() -> str:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"https://{settings.auth0_domain}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": settings.auth0_mgmt_client_id,
                "client_secret": settings.auth0_mgmt_client_secret,
                "audience": f"https://{settings.auth0_domain}/api/v2/",
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


async def _create_auth0_user(token: str, email: str) -> str:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"https://{settings.auth0_domain}/api/v2/users",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "email": email,
                "email_verified": True,
                "connection": "Username-Password-Authentication",
                "password": f"TempMigrate!{email[:4]}9#",
                "verify_email": False,
            },
        )
        if resp.status_code == 409:
            # Already exists — fetch user_id
            search = await client.get(
                f"https://{settings.auth0_domain}/api/v2/users-by-email",
                headers={"Authorization": f"Bearer {token}"},
                params={"email": email},
            )
            users = search.json()
            return users[0]["user_id"] if users else ""
        resp.raise_for_status()
        return resp.json()["user_id"]


async def _send_password_reset(email: str) -> None:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"https://{settings.auth0_domain}/dbconnections/change_password",
            json={
                "client_id": settings.auth0_client_id,
                "email": email,
                "connection": "Username-Password-Authentication",
            },
        )
        resp.raise_for_status()


@router.post("/send-activation", summary="Send Auth0 activation email to current legacy user")
async def send_activation(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    user_id = request.session.get("legacy_user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not logged in via legacy login.")

    result = await db.execute(select(PlatformUser).where(PlatformUser.id == user_id))
    user: PlatformUser | None = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if user.idp_sub:
        return {"message": "Already migrated to Auth0.", "migrated": True}

    try:
        token = await _get_mgmt_token()
        auth0_user_id = await _create_auth0_user(token, user.email)
        await _send_password_reset(user.email)

        user.migration_status = MigrationStatus.EMAIL_SENT
        db.add(user)
        await db.commit()

        logger.info("Activation email sent to %s (auth0_id=%s)", user.email, auth0_user_id)
        return {
            "message": f"Activation email sent to {user.email}. Check your inbox to set your new Auth0 password.",
            "migrated": False,
        }
    except Exception as exc:
        logger.error("Migration failed for %s: %s", user.email, exc)
        raise HTTPException(status_code=502, detail=f"Migration failed: {exc}") from exc


@router.post("/run-all", summary="Bulk migrate all pending legacy users")
async def run_all(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(PlatformUser).where(
            PlatformUser.password_hash.isnot(None),
            PlatformUser.idp_sub.is_(None),
            PlatformUser.migration_status == MigrationStatus.PENDING,
        )
    )
    users = list(result.scalars().all())

    if not users:
        return {"message": "No pending users to migrate.", "count": 0}

    token = await _get_mgmt_token()
    results = []

    for user in users:
        try:
            auth0_user_id = await _create_auth0_user(token, user.email)
            await _send_password_reset(user.email)
            user.migration_status = MigrationStatus.EMAIL_SENT
            db.add(user)
            results.append({"email": user.email, "status": "email_sent", "auth0_id": auth0_user_id})
            logger.info("Migrated %s → %s", user.email, auth0_user_id)
        except Exception as exc:
            results.append({"email": user.email, "status": "error", "error": str(exc)})
            logger.error("Failed to migrate %s: %s", user.email, exc)

    await db.commit()
    return {"message": f"Processed {len(users)} user(s).", "count": len(users), "results": results}
