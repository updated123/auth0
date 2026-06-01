"""
Approval workflow endpoints.

GET  /api/admin/approvals              — list approvals (with optional filters)
POST /api/admin/approvals/{id}/approve — manually approve a user
POST /api/admin/approvals/{id}/deny    — deny a user
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_session_admin
from app.auth.service import auth_service
from app.database import get_db
from app.models import Approval, ApprovalStatus, PlatformUser
from app.services.approval_engine import approve_user, deny_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin/approvals", tags=["approvals"])


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class ApproveRequest(BaseModel):
    role: Optional[str] = None
    entitlements: Optional[List[str]] = None


class DenyRequest(BaseModel):
    reason: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get(
    "",
    summary="List approvals for an org",
)
async def list_approvals(
    org_id: Optional[str] = None,
    status_filter: Optional[str] = None,
    admin: PlatformUser = Depends(require_session_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    List approval records.

    - If org_id is omitted, defaults to the admin's own org.
    - status_filter can be: pending_approval, in_review, approved, denied
    """
    effective_org_id = org_id or admin.org_id
    query = select(Approval).where(Approval.org_id == effective_org_id)

    if status_filter:
        # Accept both "pending" shorthand and full status strings
        if status_filter == "pending":
            from sqlalchemy import or_
            query = query.where(
                or_(
                    Approval.status == ApprovalStatus.PENDING_APPROVAL,
                    Approval.status == ApprovalStatus.IN_REVIEW,
                )
            )
        else:
            query = query.where(Approval.status == status_filter)

    query = query.order_by(Approval.created_at.desc())
    result = await db.execute(query)
    approvals = list(result.scalars().all())

    return {
        "approvals": [a.to_dict() for a in approvals],
        "total": len(approvals),
        "org_id": effective_org_id,
    }


@router.post(
    "/{approval_id}/approve",
    summary="Manually approve a pending user",
)
async def approve(
    approval_id: str,
    body: ApproveRequest,
    admin: PlatformUser = Depends(require_session_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Approve a user in the review queue.

    1. Updates approval status to APPROVED in platform DB.
    2. Activates the PlatformUser (status → ACTIVE).
    3. Calls Auth0 Management API to unblock the user (if idp_sub is set).

    Returns the updated approval record.
    """
    try:
        approval = await approve_user(
            db=db,
            approval_id=approval_id,
            reviewed_by=admin.email,
            role=body.role,
            entitlements=body.entitlements,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # Unblock in Auth0 if the user has an idp_sub
    result = await db.execute(select(PlatformUser).where(PlatformUser.id == approval.user_id))
    platform_user: Optional[PlatformUser] = result.scalar_one_or_none()

    if platform_user and platform_user.idp_sub:
        try:
            await auth_service.unblock_user(platform_user.idp_sub)
            logger.info("Auth0 user %s unblocked after approval.", platform_user.idp_sub)
        except Exception as exc:
            logger.error("Failed to unblock Auth0 user %s: %s", platform_user.idp_sub, exc)
            # Don't fail the request — the platform DB is already updated

    return {
        "message": "User approved successfully.",
        "approval": approval.to_dict(),
        "user": platform_user.to_dict() if platform_user else None,
    }


@router.post(
    "/{approval_id}/deny",
    summary="Deny a pending user",
)
async def deny(
    approval_id: str,
    body: DenyRequest,
    admin: PlatformUser = Depends(require_session_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Deny a user in the review queue.

    1. Updates approval status to DENIED in platform DB.
    2. Sets PlatformUser status to REJECTED.
    3. Calls Auth0 Management API to block the user (if idp_sub is set).

    Returns the updated approval record.
    """
    try:
        approval = await deny_user(
            db=db,
            approval_id=approval_id,
            reviewed_by=admin.email,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # Block in Auth0 if the user has an idp_sub
    result = await db.execute(select(PlatformUser).where(PlatformUser.id == approval.user_id))
    platform_user: Optional[PlatformUser] = result.scalar_one_or_none()

    if platform_user and platform_user.idp_sub:
        try:
            await auth_service.block_user(platform_user.idp_sub)
            logger.info("Auth0 user %s blocked after denial.", platform_user.idp_sub)
        except Exception as exc:
            logger.error("Failed to block Auth0 user %s: %s", platform_user.idp_sub, exc)

    return {
        "message": "User denied.",
        "approval": approval.to_dict(),
        "user": platform_user.to_dict() if platform_user else None,
    }
