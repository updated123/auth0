"""
Approval Workflow Engine

States:
  PENDING_ACCEPT → PENDING_APPROVAL → IN_REVIEW → ACTIVE / REJECTED / EXPIRED

Auto-approve rules (evaluated in order):
  1. Email domain is in the org's approved_domains list → auto-approve + default role
  2. Role requested is Admin or Finance → manual review (high privilege)
  3. Role requested is Viewer or Read-only → auto-approve
  4. Email domain is external (not in any org domain) → manual review
  5. User was admin-invited (invited_by is set) → auto-approve
  6. Default → manual review

This module contains pure business logic — no HTTP calls, no FastAPI.
Auth0 API calls are delegated to AuthService after approval.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Approval, ApprovalStatus, Organization, PlatformUser, UserStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Role definitions
# ---------------------------------------------------------------------------

HIGH_PRIVILEGE_ROLES = {"admin", "finance", "platform_admin", "super_admin"}
VIEWER_ROLES = {"viewer", "read_only", "reader", "guest"}

DEFAULT_ENTITLEMENTS_BY_ROLE = {
    "admin": ["*"],
    "platform_admin": ["*"],
    "finance": ["reports:read", "finance:read", "finance:write", "dashboards:read"],
    "analyst": ["reports:read", "dashboards:read", "data:read"],
    "viewer": ["dashboards:read"],
    "read_only": ["dashboards:read"],
    "reader": ["dashboards:read"],
    "guest": ["dashboards:read"],
}

DEFAULT_ROLE = "viewer"


# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------

class ApprovalDecision:
    AUTO_APPROVE = "auto_approve"
    MANUAL_REVIEW = "manual_review"


def _get_domain(email: str) -> str:
    """Extract domain from an email address."""
    parts = email.rsplit("@", 1)
    return parts[1].lower() if len(parts) == 2 else ""


def evaluate_auto_approve(
    *,
    email: str,
    role_requested: Optional[str],
    org: Organization,
    invited_by: Optional[str],
) -> Tuple[str, str, str]:
    """
    Evaluate whether a signup should be auto-approved.

    Returns:
        (decision, reason, effective_role)
        where decision is ApprovalDecision.AUTO_APPROVE or .MANUAL_REVIEW
    """
    domain = _get_domain(email)
    role_lower = (role_requested or DEFAULT_ROLE).lower()

    approved_domains: List[str] = (
        org.approved_domains if isinstance(org.approved_domains, list) else []
    )

    # Rule 1: Domain whitelist
    if domain and domain in approved_domains:
        logger.info("Auto-approve rule 1 matched: domain %s in whitelist for org %s", domain, org.id)
        return (
            ApprovalDecision.AUTO_APPROVE,
            f"Domain '{domain}' is on the org's approved domain list.",
            role_lower or DEFAULT_ROLE,
        )

    # Rule 2: High-privilege role → always manual
    if role_lower in HIGH_PRIVILEGE_ROLES:
        logger.info("Manual review rule 2: high-privilege role '%s' requested.", role_lower)
        return (
            ApprovalDecision.MANUAL_REVIEW,
            f"High-privilege role '{role_lower}' requires manual approval.",
            role_lower,
        )

    # Rule 3: Viewer/read-only role → auto-approve
    if role_lower in VIEWER_ROLES:
        logger.info("Auto-approve rule 3 matched: viewer/read-only role '%s'.", role_lower)
        return (
            ApprovalDecision.AUTO_APPROVE,
            f"Read-only role '{role_lower}' is auto-approved.",
            role_lower,
        )

    # Rule 5: Admin-invited — checked before external domain rule
    # so that admins can invite users from any domain without manual review
    if invited_by:
        logger.info("Auto-approve rule 5: user was invited by %s.", invited_by)
        return (
            ApprovalDecision.AUTO_APPROVE,
            f"User was invited by '{invited_by}' (admin-invite auto-approval).",
            role_lower or DEFAULT_ROLE,
        )

    # Rule 4: External domain
    if domain and domain not in approved_domains:
        logger.info("Manual review rule 4: external domain '%s'.", domain)
        return (
            ApprovalDecision.MANUAL_REVIEW,
            f"External domain '{domain}' requires manual review.",
            role_lower,
        )

    # Rule 6: Default → manual
    logger.info("Default manual review for %s.", email)
    return (
        ApprovalDecision.MANUAL_REVIEW,
        "Default policy: manual review required.",
        role_lower or DEFAULT_ROLE,
    )


# ---------------------------------------------------------------------------
# Engine entry points
# ---------------------------------------------------------------------------

async def process_signup(
    *,
    db: AsyncSession,
    platform_user: PlatformUser,
    org: Organization,
    role_requested: Optional[str] = None,
) -> Approval:
    """
    Called when a user completes signup (webhook event: user.signup_complete).

    Creates an Approval record and advances state machine based on auto-approve rules.
    """
    decision, reason, effective_role = evaluate_auto_approve(
        email=platform_user.email,
        role_requested=role_requested,
        org=org,
        invited_by=platform_user.invited_by,
    )

    approval = Approval(
        user_id=platform_user.id,
        org_id=org.id,
        status=ApprovalStatus.PENDING_APPROVAL,
        role_requested=role_requested or effective_role,
        reason=reason,
        auto_approved=(decision == ApprovalDecision.AUTO_APPROVE),
    )
    db.add(approval)

    if decision == ApprovalDecision.AUTO_APPROVE:
        entitlements = DEFAULT_ENTITLEMENTS_BY_ROLE.get(effective_role, ["dashboards:read"])
        approval.status = ApprovalStatus.APPROVED
        approval.entitlements_granted = entitlements
        approval.reviewed_by = "system:auto-approve"
        approval.reviewed_at = datetime.now(timezone.utc)

        platform_user.status = UserStatus.ACTIVE
        platform_user.role = effective_role
        platform_user.entitlements = entitlements
        platform_user.approved_at = datetime.now(timezone.utc)
        logger.info(
            "User %s auto-approved with role '%s' and %d entitlements.",
            platform_user.email,
            effective_role,
            len(entitlements),
        )
    else:
        approval.status = ApprovalStatus.IN_REVIEW
        platform_user.status = UserStatus.IN_REVIEW
        logger.info(
            "User %s placed in manual review queue. Reason: %s",
            platform_user.email,
            reason,
        )

    db.add(platform_user)
    await db.commit()
    await db.refresh(approval)
    return approval


async def approve_user(
    *,
    db: AsyncSession,
    approval_id: str,
    reviewed_by: str,
    role: Optional[str] = None,
    entitlements: Optional[List[str]] = None,
) -> Approval:
    """
    Manual approval action — called by admin via POST /api/admin/approvals/{id}/approve.

    Updates Approval record, activates PlatformUser.
    Caller is responsible for calling AuthService.unblock_user() afterwards.
    """
    result = await db.execute(select(Approval).where(Approval.id == approval_id))
    approval: Optional[Approval] = result.scalar_one_or_none()
    if approval is None:
        raise ValueError(f"Approval {approval_id} not found.")

    if approval.status not in (ApprovalStatus.PENDING_APPROVAL, ApprovalStatus.IN_REVIEW):
        raise ValueError(f"Approval {approval_id} is in terminal state '{approval.status}' and cannot be approved.")

    effective_role = role or approval.role_requested or DEFAULT_ROLE
    effective_entitlements = entitlements or DEFAULT_ENTITLEMENTS_BY_ROLE.get(effective_role, ["dashboards:read"])

    approval.status = ApprovalStatus.APPROVED
    approval.reviewed_by = reviewed_by
    approval.reviewed_at = datetime.now(timezone.utc)
    approval.entitlements_granted = effective_entitlements

    # Activate the platform user
    result2 = await db.execute(select(PlatformUser).where(PlatformUser.id == approval.user_id))
    user: Optional[PlatformUser] = result2.scalar_one_or_none()
    if user:
        user.status = UserStatus.ACTIVE
        user.role = effective_role
        user.entitlements = effective_entitlements
        user.approved_at = datetime.now(timezone.utc)
        db.add(user)

    db.add(approval)
    await db.commit()
    await db.refresh(approval)
    return approval


async def deny_user(
    *,
    db: AsyncSession,
    approval_id: str,
    reviewed_by: str,
    reason: str,
) -> Approval:
    """
    Manual denial action — called by admin via POST /api/admin/approvals/{id}/deny.
    """
    result = await db.execute(select(Approval).where(Approval.id == approval_id))
    approval: Optional[Approval] = result.scalar_one_or_none()
    if approval is None:
        raise ValueError(f"Approval {approval_id} not found.")

    if approval.status not in (ApprovalStatus.PENDING_APPROVAL, ApprovalStatus.IN_REVIEW):
        raise ValueError(f"Approval {approval_id} is in terminal state '{approval.status}'.")

    approval.status = ApprovalStatus.DENIED
    approval.reviewed_by = reviewed_by
    approval.reviewed_at = datetime.now(timezone.utc)
    approval.reason = reason

    # Mark the platform user as rejected
    result2 = await db.execute(select(PlatformUser).where(PlatformUser.id == approval.user_id))
    user: Optional[PlatformUser] = result2.scalar_one_or_none()
    if user:
        user.status = UserStatus.REJECTED
        db.add(user)

    db.add(approval)
    await db.commit()
    await db.refresh(approval)
    return approval
