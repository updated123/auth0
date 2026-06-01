"""
UserService — platform-side user management operations.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Organization, PlatformUser, UserStatus

logger = logging.getLogger(__name__)


async def create_invited_user(
    *,
    db: AsyncSession,
    email: str,
    org_id: str,
    invited_by: str,
) -> PlatformUser:
    """
    Create a PlatformUser in INVITED state (no role yet — admin assigns after signup).
    Idempotent: returns existing record if already invited.
    """
    result = await db.execute(
        select(PlatformUser).where(
            PlatformUser.email == email,
            PlatformUser.org_id == org_id,
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        logger.info("User %s already exists in org %s (status=%s).", email, org_id, existing.status)
        return existing

    user = PlatformUser(
        email=email,
        org_id=org_id,
        role=None,  # role is assigned later by admin
        status=UserStatus.INVITED,
        invited_by=invited_by,
        invited_at=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("Created invited user %s in org %s — awaiting acceptance.", email, org_id)
    return user


async def on_user_signup_complete(
    *,
    db: AsyncSession,
    sub: str,
    email: str,
    email_verified: bool,
    org_id: str,
) -> PlatformUser:
    """
    Called when Auth0 fires the signup_complete webhook.

    Finds the platform user by email (from the invite) or sub,
    links the Auth0 sub, and moves status → PENDING_ROLE_ASSIGNMENT.
    Admin must now assign a role to activate the user.
    """
    # Try by sub first
    result = await db.execute(select(PlatformUser).where(PlatformUser.idp_sub == sub))
    user: Optional[PlatformUser] = result.scalar_one_or_none()

    if user is None:
        # Try by email (normal path — invited user completing signup)
        result2 = await db.execute(
            select(PlatformUser).where(
                PlatformUser.email == email,
                PlatformUser.org_id == org_id,
            )
        )
        user = result2.scalar_one_or_none()

    if user is None:
        # Self-signup with no prior invite — create the record
        user = PlatformUser(
            idp_sub=sub,
            email=email,
            email_verified=email_verified,
            org_id=org_id,
            status=UserStatus.PENDING_ROLE_ASSIGNMENT,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        logger.info("Self-signup: created PlatformUser for %s → pending_role_assignment.", email)
        return user

    # Link sub and advance state
    if user.idp_sub is None:
        user.idp_sub = sub
    user.email_verified = email_verified

    if user.status == UserStatus.INVITED:
        user.status = UserStatus.PENDING_ROLE_ASSIGNMENT
        logger.info("User %s accepted invite → pending_role_assignment.", email)

    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def assign_role(
    *,
    db: AsyncSession,
    user_id: str,
    role: str,
    entitlements: List[str],
    assigned_by: str,
) -> PlatformUser:
    """
    Admin assigns a role to a user in PENDING_ROLE_ASSIGNMENT state.
    Moves the user to ACTIVE.
    """
    result = await db.execute(select(PlatformUser).where(PlatformUser.id == user_id))
    user: Optional[PlatformUser] = result.scalar_one_or_none()

    if user is None:
        raise ValueError(f"User {user_id} not found.")

    if user.status not in (UserStatus.PENDING_ROLE_ASSIGNMENT, UserStatus.INVITED):
        raise ValueError(
            f"Cannot assign role: user is in status '{user.status}'. "
            "Expected 'pending_role_assignment'."
        )

    user.role = role
    user.entitlements = entitlements
    user.status = UserStatus.ACTIVE
    user.approved_at = datetime.now(timezone.utc)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("Role '%s' assigned to user %s by %s → ACTIVE.", role, user.email, assigned_by)
    return user


async def get_pending_role_assignment(
    *,
    db: AsyncSession,
    org_id: str,
) -> List[PlatformUser]:
    """Return users waiting for admin to assign a role."""
    result = await db.execute(
        select(PlatformUser).where(
            PlatformUser.org_id == org_id,
            PlatformUser.status == UserStatus.PENDING_ROLE_ASSIGNMENT,
        ).order_by(PlatformUser.updated_at.desc())
    )
    return list(result.scalars().all())


async def get_org_users(
    *,
    db: AsyncSession,
    org_id: str,
    status_filter: Optional[str] = None,
) -> List[PlatformUser]:
    query = select(PlatformUser).where(PlatformUser.org_id == org_id)
    if status_filter:
        query = query.where(PlatformUser.status == status_filter)
    result = await db.execute(query)
    return list(result.scalars().all())


async def get_user_by_sub(*, db: AsyncSession, sub: str) -> Optional[PlatformUser]:
    result = await db.execute(select(PlatformUser).where(PlatformUser.idp_sub == sub))
    return result.scalar_one_or_none()


async def get_user_by_email(*, db: AsyncSession, email: str) -> Optional[PlatformUser]:
    result = await db.execute(select(PlatformUser).where(PlatformUser.email == email))
    return result.scalar_one_or_none()


async def get_org(*, db: AsyncSession, org_id: str) -> Optional[Organization]:
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    return result.scalar_one_or_none()
