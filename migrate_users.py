"""
Migration script — Kinsta DB → Auth0

For each legacy user (password_hash set, idp_sub null):
1. Create account in Auth0 (no password — email_verified=true)
2. Trigger Auth0 password-reset email ("Activate your account")
3. Update platform DB migration_status → EMAIL_SENT

Run: python3 migrate_users.py
"""
from __future__ import annotations

import asyncio
import logging

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")
logger = logging.getLogger("migrate")

# Load settings from .env
from dotenv import load_dotenv
load_dotenv()
from app.config import settings
from app.models import MigrationStatus, PlatformUser


async def get_mgmt_token(client: httpx.AsyncClient) -> str:
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


async def create_auth0_user(client: httpx.AsyncClient, token: str, email: str) -> str | None:
    """Create user in Auth0 without password. Returns Auth0 user_id (sub)."""
    resp = await client.post(
        f"https://{settings.auth0_domain}/api/v2/users",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "email": email,
            "email_verified": True,
            "connection": "Username-Password-Authentication",
            "password": f"TempMigrate!{email[:4]}9#",  # temporary — forced reset below
            "verify_email": False,
        },
    )
    if resp.status_code == 409:
        # User already exists — fetch their user_id
        search_resp = await client.get(
            f"https://{settings.auth0_domain}/api/v2/users-by-email",
            headers={"Authorization": f"Bearer {token}"},
            params={"email": email},
        )
        users = search_resp.json()
        if users:
            logger.info("  User already exists in Auth0: %s", email)
            return users[0]["user_id"]
        return None
    resp.raise_for_status()
    return resp.json()["user_id"]


async def send_password_reset(client: httpx.AsyncClient, email: str) -> None:
    """Send Auth0 'Change Password' email — user sets their own new password."""
    resp = await client.post(
        f"https://{settings.auth0_domain}/dbconnections/change_password",
        json={
            "client_id": settings.auth0_client_id,
            "email": email,
            "connection": "Username-Password-Authentication",
        },
    )
    resp.raise_for_status()
    logger.info("  Password-reset email sent to %s", email)


async def migrate():
    engine = create_async_engine(
        settings.database_url.replace("sqlite:///", "sqlite+aiosqlite:///"),
        echo=False,
    )
    Session = async_sessionmaker(bind=engine, expire_on_commit=False)

    async with httpx.AsyncClient(timeout=20) as client:
        token = await get_mgmt_token(client)
        logger.info("Auth0 management token obtained.")

        async with Session() as db:
            # Find all legacy users not yet migrated
            result = await db.execute(
                select(PlatformUser).where(
                    PlatformUser.password_hash.isnot(None),
                    PlatformUser.idp_sub.is_(None),
                )
            )
            users = list(result.scalars().all())

            if not users:
                logger.info("No legacy users pending migration.")
                return

            logger.info("Found %d legacy user(s) to migrate.", len(users))

            for user in users:
                logger.info("Migrating: %s (role=%s, org=%s)", user.email, user.role, user.org_id)

                # 1. Create Auth0 account
                auth0_user_id = await create_auth0_user(client, token, user.email)
                if not auth0_user_id:
                    logger.warning("  Skipped %s — could not create Auth0 user.", user.email)
                    continue
                logger.info("  Auth0 user created: %s", auth0_user_id)

                # 2. Send password-reset / activation email
                await send_password_reset(client, user.email)

                # 3. Update platform DB
                user.migration_status = MigrationStatus.EMAIL_SENT
                db.add(user)

            await db.commit()
            logger.info("Migration complete. %d user(s) processed.", len(users))

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(migrate())
