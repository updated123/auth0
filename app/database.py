"""
Database session factory and seed data bootstrapper.

Uses SQLAlchemy async engine with SQLite for the POC.
Swap DATABASE_URL to postgresql+asyncpg://... for production.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.models import Base, MigrationStatus, Organization, PermissionProfile, PlatformUser, UserStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Engine — convert sync SQLite URL to the aiosqlite variant automatically
# ---------------------------------------------------------------------------

def _make_async_url(url: str) -> str:
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


_engine = create_async_engine(
    _make_async_url(settings.database_url),
    echo=False,  # set True for SQL debug logs
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
)

AsyncSessionLocal = async_sessionmaker(
    bind=_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------

async def get_db() -> AsyncSession:  # type: ignore[return]
    async with AsyncSessionLocal() as session:
        yield session


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

async def create_tables() -> None:
    """Create all tables (idempotent — skips existing)."""
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ready.")


async def seed_data() -> None:
    """
    Seed organisations that already exist in Auth0, plus a platform admin.
    Idempotent — safe to re-run.
    """
    async with AsyncSessionLocal() as session:
        # Real Auth0 organisations created in the dashboard
        orgs_to_seed = [
            {"id": "org_acmecorp",  "name": "Acme Corp",  "auth0_org_id": "org_fpQrKWcIZzkvSH4u", "domains": ["acmecorp.com"]},
            {"id": "org_globexinc", "name": "Globex Inc", "auth0_org_id": "org_IYVMR8RqFOhiVayY", "domains": ["globex.com"]},
            {"id": "org_utsav",     "name": "Utsav",      "auth0_org_id": "org_IKELHMWEuAe7hAHC", "domains": []},
        ]

        # Subscription tier / add-on defaults per org
        org_subscription_defaults = {
            "org_acmecorp":  {"tier": "professional", "add_ons": ["analytics"],              "mfa_required": True},
            "org_globexinc": {"tier": "free",         "add_ons": [],                         "mfa_required": False},
            "org_utsav":     {"tier": "enterprise",   "add_ons": ["analytics", "api_access"], "mfa_required": True},
        }

        for o in orgs_to_seed:
            result = await session.execute(select(Organization).where(Organization.id == o["id"]))
            existing = result.scalars().first()
            sub = org_subscription_defaults.get(o["id"], {})
            if not existing:
                org = Organization(
                    id=o["id"],
                    name=o["name"],
                    auth0_org_id=o["auth0_org_id"],
                    approved_domains=o["domains"],
                    subscription_tier=sub.get("tier", "free"),
                    add_ons=sub.get("add_ons", []),
                    mfa_required=sub.get("mfa_required", False),
                )
                session.add(org)
                logger.info("Seeded organization: %s (%s)", o["name"], o["auth0_org_id"])
            else:
                # Update auth0_org_id if missing
                if existing.auth0_org_id != o["auth0_org_id"]:
                    existing.auth0_org_id = o["auth0_org_id"]
                # Backfill subscription tier if still default
                if existing.subscription_tier == "free" and sub.get("tier") != "free":
                    existing.subscription_tier = sub.get("tier", "free")
                    existing.add_ons = sub.get("add_ons", [])
                # Always sync mfa_required from seed config
                existing.mfa_required = sub.get("mfa_required", False)
                session.add(existing)
                logger.info("Organization already seeded: %s", o["name"])

        # --- Platform Admins ---
        platform_admins = [
            {"email": "utsav.patel@ignitedata.ai",   "org_id": "org_acmecorp"},
            {"email": "akash.bhandwalkar@ignitedata.ai", "org_id": "org_acmecorp"},
        ]
        for pa in platform_admins:
            result = await session.execute(
                select(PlatformUser).where(PlatformUser.email == pa["email"])
            )
            existing_admin = result.scalars().first()
            if not existing_admin:
                admin = PlatformUser(
                    email=pa["email"],
                    org_id=pa["org_id"],
                    role="admin",
                    entitlements=["*"],
                    status=UserStatus.ACTIVE,
                    invited_by="system",
                    invited_at=datetime.now(timezone.utc),
                    approved_at=datetime.now(timezone.utc),
                )
                session.add(admin)
                logger.info("Seeded platform admin: %s", pa["email"])
            else:
                logger.info("Platform admin already seeded: %s", pa["email"])

        # --- Legacy Kinsta DB users (demo migration) ---
        import bcrypt
        legacy_users = [
            # Acme Corp users
            {
                "email": "utsavpatel8696@gmail.com",
                "org_id": "org_acmecorp",
                "role": "member",
                "entitlements": ["reports:read", "dashboards:read", "data:read"],
            },
            {
                "email": "utsav.patel@ignitedata.ai",
                "org_id": "org_acmecorp",
                "role": "admin",
                "entitlements": ["*"],
            },
            {
                "email": "akash.bhandwalkar@ignitedata.ai",
                "org_id": "org_acmecorp",
                "role": "admin",
                "entitlements": ["*"],
            },
            # Globex Inc users
            {
                "email": "alice@globex.com",
                "org_id": "org_globexinc",
                "role": "member",
                "entitlements": ["reports:read", "dashboards:read"],
            },
            {
                "email": "bob@globex.com",
                "org_id": "org_globexinc",
                "role": "admin",
                "entitlements": ["*"],
            },
            # Utsav org users
            {
                "email": "demo@utsav.dev",
                "org_id": "org_utsav",
                "role": "member",
                "entitlements": ["dashboards:read"],
            },
        ]
        pw_hash = bcrypt.hashpw(b"Utsav@123", bcrypt.gensalt()).decode()

        for lu in legacy_users:
            result = await session.execute(
                select(PlatformUser).where(PlatformUser.email == lu["email"])
            )
            existing = result.scalars().first()
            if not existing:
                user = PlatformUser(
                    email=lu["email"],
                    org_id=lu["org_id"],
                    role=lu["role"],
                    entitlements=lu["entitlements"],
                    status=UserStatus.ACTIVE,
                    password_hash=pw_hash,
                    migration_status=MigrationStatus.PENDING,
                    invited_by="kinsta-import",
                    invited_at=datetime.now(timezone.utc),
                    approved_at=datetime.now(timezone.utc),
                )
                session.add(user)
                logger.info("Seeded legacy user: %s (role=%s)", lu["email"], lu["role"])
            else:
                if existing.password_hash is None:
                    existing.password_hash = pw_hash
                    existing.migration_status = MigrationStatus.PENDING
                    session.add(existing)
                logger.info("Legacy user already seeded: %s", lu["email"])

        # --- Default Permission Profiles ---
        default_profiles_spec = [
            {"name": "viewer",  "default_grants": ["reports:read", "dashboards:read"],                                                      "is_default": False},
            {"name": "member",  "default_grants": ["reports:read", "dashboards:read", "data:read"],                                          "is_default": True},
            {"name": "analyst", "default_grants": ["reports:read", "dashboards:read", "data:read", "data:export", "analytics:read"],          "is_default": False},
            {"name": "admin",   "default_grants": ["*"],                                                                                     "is_default": False},
        ]

        for org_id in ["org_acmecorp", "org_globexinc", "org_utsav"]:
            for spec in default_profiles_spec:
                result = await session.execute(
                    select(PermissionProfile).where(
                        PermissionProfile.org_id == org_id,
                        PermissionProfile.name == spec["name"],
                    )
                )
                existing_profile = result.scalars().first()
                if not existing_profile:
                    profile = PermissionProfile(
                        org_id=org_id,
                        name=spec["name"],
                        default_grants=spec["default_grants"],
                        exclusions=[],
                        is_default=spec["is_default"],
                    )
                    session.add(profile)
                    logger.info("Seeded permission profile: %s for org %s", spec["name"], org_id)
                else:
                    logger.info("Permission profile already seeded: %s for org %s", spec["name"], org_id)

        await session.commit()
