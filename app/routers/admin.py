from pathlib import Path
"""
Admin API endpoints.

POST /api/admin/invite                     — invite user (no role yet)
POST /api/admin/users/{id}/assign-role     — admin assigns role after user signs up
GET  /api/admin/users                      — list platform users for an org
GET  /api/admin/pending                    — list users awaiting role assignment
GET  /api/admin/panel                      — admin HTML page
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_session_admin
from app.auth.service import Auth0ManagementError, auth_service
from app.database import get_db
from app.models import PlatformUser
from app.services.user_service import (
    assign_role,
    create_invited_user,
    get_org,
    get_org_users,
    get_pending_role_assignment,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin", tags=["admin"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

ROLE_ENTITLEMENTS = {
    "admin":  ["*"],
    "member": ["reports:read", "dashboards:read", "data:read"],
}


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class InviteRequest(BaseModel):
    email: EmailStr
    org_id: str


class InviteResponse(BaseModel):
    message: str
    platform_user_id: str
    invitation_id: Optional[str] = None


class AssignRoleRequest(BaseModel):
    role: str
    entitlements: Optional[List[str]] = None  # if omitted, defaults come from ROLE_ENTITLEMENTS


class UserListResponse(BaseModel):
    users: List[dict]
    total: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "/invite",
    response_model=InviteResponse,
    summary="Invite a user — email sent, no role assigned yet",
)
async def invite_user(
    body: InviteRequest,
    request: Request,
    admin: PlatformUser = Depends(require_session_admin),
    db: AsyncSession = Depends(get_db),
) -> InviteResponse:
    """
    Step 1 of the onboarding flow:
    1. Create a PlatformUser record in INVITED state (no role).
    2. Call Auth0 Management API to send an invitation email to the user.

    The user will receive an email, set their password, and their status
    will advance to PENDING_ROLE_ASSIGNMENT via the Auth0 webhook.
    Admin then assigns a role to activate them.
    """
    org = await get_org(db=db, org_id=body.org_id)
    if org is None:
        raise HTTPException(status_code=404, detail=f"Organisation '{body.org_id}' not found.")

    platform_user = await create_invited_user(
        db=db,
        email=body.email,
        org_id=body.org_id,
        invited_by=admin.email,
    )

    invitation_id: Optional[str] = None

    if org.auth0_org_id:
        try:
            invitation = await auth_service.create_invitation(
                auth0_org_id=org.auth0_org_id,
                invitee_email=body.email,
                inviter_name=admin.email,
                roles=None,  # no role at invite time
            )
            invitation_id = invitation.get("id")
            logger.info("Auth0 invitation %s sent to %s.", invitation_id, body.email)
        except Auth0ManagementError as exc:
            logger.error("Auth0 invitation failed: %s", exc)
    else:
        logger.info(
            "Org %s has no auth0_org_id — platform record created, no Auth0 invite sent. "
            "Set org.auth0_org_id to enable Auth0 invitations.",
            body.org_id,
        )

    return InviteResponse(
        message=f"Invitation sent to {body.email}. Role will be assigned after they sign up.",
        platform_user_id=platform_user.id,
        invitation_id=invitation_id,
    )


@router.post(
    "/users/{user_id}/assign-role",
    summary="Assign role to a user who has completed signup",
)
async def assign_role_to_user(
    user_id: str,
    body: AssignRoleRequest,
    admin: PlatformUser = Depends(require_session_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Step 3 of the onboarding flow (after user accepted invite and set password):

    Admin assigns a role → user status moves to ACTIVE.
    If entitlements are not provided, defaults for the role are applied.
    Also unblocks the user in Auth0 if they were blocked.
    """
    effective_entitlements = body.entitlements or ROLE_ENTITLEMENTS.get(body.role, ["dashboards:read"])

    try:
        user = await assign_role(
            db=db,
            user_id=user_id,
            role=body.role,
            entitlements=effective_entitlements,
            assigned_by=admin.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Unblock in Auth0 if the user already has an idp_sub (they completed signup)
    if user.idp_sub:
        try:
            await auth_service.unblock_user(user.idp_sub)
            logger.info("Auth0 user %s unblocked after role assignment.", user.idp_sub)
        except Exception as exc:
            logger.warning("Could not unblock Auth0 user %s: %s", user.idp_sub, exc)

    return {
        "message": f"Role '{body.role}' assigned to {user.email}. User is now ACTIVE.",
        "user": user.to_dict(),
    }


@router.get(
    "/pending",
    summary="List users awaiting role assignment",
)
async def list_pending_role_assignment(
    org_id: Optional[str] = None,
    admin: PlatformUser = Depends(require_session_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return users who accepted their invite but haven't been assigned a role yet."""
    effective_org_id = org_id or admin.org_id
    users = await get_pending_role_assignment(db=db, org_id=effective_org_id)
    return {
        "users": [u.to_dict() for u in users],
        "total": len(users),
        "org_id": effective_org_id,
    }


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List all platform users for an org",
)
async def list_users(
    org_id: Optional[str] = None,
    status_filter: Optional[str] = None,
    admin: PlatformUser = Depends(require_session_admin),
    db: AsyncSession = Depends(get_db),
) -> UserListResponse:
    effective_org_id = org_id or admin.org_id
    users = await get_org_users(db=db, org_id=effective_org_id, status_filter=status_filter)
    return UserListResponse(users=[u.to_dict() for u in users], total=len(users))


@router.get(
    "/panel",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def admin_panel(
    request: Request,
    admin: PlatformUser = Depends(require_session_admin),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    users = await get_org_users(db=db, org_id=admin.org_id)
    pending = await get_pending_role_assignment(db=db, org_id=admin.org_id)
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "user": admin,
            "users": [u.to_dict() for u in users],
            "pending_users": [u.to_dict() for u in pending],
            "org_id": admin.org_id,
            "roles": list(ROLE_ENTITLEMENTS.keys()),
        },
    )
