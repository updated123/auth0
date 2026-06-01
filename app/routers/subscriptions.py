"""
Subscription, Permission Profiles, and MFA management routes.

Session 5 — Subscription + Permissions

Routes
------
Subscription (TCS admin only):
  GET  /subscription/dashboard
  POST /api/subscription/org/{org_id}/tier
  POST /api/subscription/org/{org_id}/addon

Permissions (org admin):
  GET  /permissions/{org_id}
  POST /api/permissions/{org_id}/profiles
  POST /api/permissions/{org_id}/users/{user_id}/override

MFA:
  GET  /mfa/setup
  POST /api/mfa/org/{org_id}/require
  GET  /mfa/enroll
"""
from __future__ import annotations
from pathlib import Path
import base64
import hashlib
import logging
import os
import urllib.parse
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import Organization, PermissionProfile, PlatformUser

logger = logging.getLogger(__name__)
router = APIRouter(tags=["subscriptions"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

TCS_ADMIN_EMAIL = "utsav.patel@ignitedata.ai"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TIER_FEATURES: dict[str, dict[str, Any]] = {
    "free": {
        "label": "Free",
        "price": "£0/mo",
        "color": "secondary",
        "max_users": 5,
        "features": ["reports:read", "dashboards:read"],
        "mfa": False,
        "sso": False,
        "api": False,
    },
    "professional": {
        "label": "Professional",
        "price": "£49/mo",
        "color": "primary",
        "max_users": 50,
        "features": ["reports:read", "dashboards:read", "data:read", "data:export", "analytics:read"],
        "mfa": True,
        "sso": False,
        "api": False,
    },
    "enterprise": {
        "label": "Enterprise",
        "price": "Custom",
        "color": "success",
        "max_users": -1,
        "features": [
            "reports:read",
            "dashboards:read",
            "data:read",
            "data:export",
            "analytics:read",
            "api:access",
            "sso:enabled",
            "mfa:required",
        ],
        "mfa": True,
        "sso": True,
        "api": True,
    },
}

AVAILABLE_ADDONS: dict[str, dict[str, Any]] = {
    "analytics":   {"label": "Advanced Analytics", "price": "£19/mo", "grants": ["analytics:read", "analytics:export"]},
    "data_export": {"label": "Bulk Data Export",   "price": "£9/mo",  "grants": ["data:export:bulk"]},
    "api_access":  {"label": "API Access",          "price": "£29/mo", "grants": ["api:full"]},
    "sso":         {"label": "SSO / SAML",          "price": "£39/mo", "grants": ["sso:enabled"]},
}

DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
    "viewer":  {"default_grants": ["reports:read", "dashboards:read"], "description": "Read-only"},
    "member":  {"default_grants": ["reports:read", "dashboards:read", "data:read"], "description": "Standard access"},
    "analyst": {"default_grants": ["reports:read", "dashboards:read", "data:read", "data:export", "analytics:read"], "description": "Full data access"},
    "admin":   {"default_grants": ["*"], "description": "Full access + user management"},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_tcs_admin(request: Request) -> None:
    if request.session.get("legacy_email") != TCS_ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="TCS admin access required.")


def _require_org_admin(request: Request) -> None:
    if request.session.get("legacy_role") != "admin":
        raise HTTPException(status_code=403, detail="Org admin access required.")


async def _get_org_or_404(db: AsyncSession, org_id: str) -> Organization:
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail=f"Organisation '{org_id}' not found.")
    return org


def _effective_permissions(profile: PermissionProfile | None, user: PlatformUser) -> list[str]:
    """Compute effective permissions = profile grants - profile exclusions - user overrides."""
    if profile is None:
        grants = list(user.entitlements or [])
    else:
        grants = list(profile.default_grants or [])
        # Remove profile-level exclusions
        exclusions = set(profile.exclusions or [])
        grants = [g for g in grants if g not in exclusions]
    # Remove user-level permission_overrides (user exclusions)
    user_excl = set(user.permission_overrides or [])
    grants = [g for g in grants if g not in user_excl]
    return grants


# ---------------------------------------------------------------------------
# Subscription routes (TCS admin only)
# ---------------------------------------------------------------------------

@router.get("/subscription/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def subscription_dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    if request.session.get("legacy_email") != TCS_ADMIN_EMAIL:
        return RedirectResponse(url="/tcs/login", status_code=302)

    result = await db.execute(select(Organization))
    orgs = list(result.scalars().all())

    org_data = []
    for org in orgs:
        users_result = await db.execute(
            select(PlatformUser).where(PlatformUser.org_id == org.id)
        )
        users = list(users_result.scalars().all())
        tier_info = TIER_FEATURES.get(org.subscription_tier, TIER_FEATURES["free"])
        addon_list = []
        for addon_key in (org.add_ons or []):
            if addon_key in AVAILABLE_ADDONS:
                addon_list.append({"key": addon_key, **AVAILABLE_ADDONS[addon_key]})

        org_data.append({
            "id": org.id,
            "name": org.name,
            "tier": org.subscription_tier,
            "tier_info": tier_info,
            "add_ons": org.add_ons or [],
            "addon_list": addon_list,
            "user_count": len(users),
            "mfa_required": org.mfa_required or False,
            "auth0_org_id": org.auth0_org_id,
        })

    return templates.TemplateResponse(
        "subscription_dashboard.html",
        {
            "request": request,
            "org_data": org_data,
            "tier_features": TIER_FEATURES,
            "available_addons": AVAILABLE_ADDONS,
            "tcs_email": TCS_ADMIN_EMAIL,
        },
    )


@router.post("/api/subscription/org/{org_id}/tier")
async def update_org_tier(
    org_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    _require_tcs_admin(request)

    body = await request.json()
    new_tier = body.get("tier", "").lower()
    if new_tier not in TIER_FEATURES:
        raise HTTPException(status_code=400, detail=f"Invalid tier '{new_tier}'. Choose from: {list(TIER_FEATURES.keys())}")

    org = await _get_org_or_404(db, org_id)
    old_tier = org.subscription_tier
    org.subscription_tier = new_tier
    db.add(org)
    await db.commit()

    users_result = await db.execute(select(PlatformUser).where(PlatformUser.org_id == org_id))
    user_count = len(list(users_result.scalars().all()))

    logger.info("Subscription tier updated: org=%s %s → %s", org_id, old_tier, new_tier)
    return JSONResponse({
        "ok": True,
        "org_id": org_id,
        "org_name": org.name,
        "old_tier": old_tier,
        "new_tier": new_tier,
        "tier_info": TIER_FEATURES[new_tier],
        "user_count": user_count,
        "add_ons": org.add_ons or [],
        "mfa_required": org.mfa_required or False,
    })


@router.post("/api/subscription/org/{org_id}/addon")
async def toggle_org_addon(
    org_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    _require_tcs_admin(request)

    body = await request.json()
    addon_key = body.get("addon", "")
    enabled = bool(body.get("enabled", True))

    if addon_key not in AVAILABLE_ADDONS:
        raise HTTPException(status_code=400, detail=f"Unknown add-on '{addon_key}'.")

    org = await _get_org_or_404(db, org_id)
    current_addons: list[str] = list(org.add_ons or [])

    if enabled and addon_key not in current_addons:
        current_addons.append(addon_key)
    elif not enabled and addon_key in current_addons:
        current_addons.remove(addon_key)

    org.add_ons = current_addons
    db.add(org)
    await db.commit()

    logger.info("Add-on toggle: org=%s addon=%s enabled=%s", org_id, addon_key, enabled)
    return JSONResponse({
        "ok": True,
        "org_id": org_id,
        "addon": addon_key,
        "enabled": enabled,
        "add_ons": org.add_ons,
    })


# ---------------------------------------------------------------------------
# Permission Profile routes (org admin)
# ---------------------------------------------------------------------------

@router.get("/permissions/{org_id}", response_class=HTMLResponse, include_in_schema=False)
async def permission_profiles_page(
    org_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    # Allow TCS admin or any logged-in org admin for their org
    legacy_email = request.session.get("legacy_email")
    legacy_role = request.session.get("legacy_role")
    legacy_org = request.session.get("legacy_org_id")

    if not legacy_email:
        return RedirectResponse(url="/legacy-login", status_code=302)

    # TCS admin can view any org; org admin can only view their own org
    if legacy_email != TCS_ADMIN_EMAIL and (legacy_role != "admin" or legacy_org != org_id):
        raise HTTPException(status_code=403, detail="Access denied.")

    org = await _get_org_or_404(db, org_id)

    profiles_result = await db.execute(
        select(PermissionProfile).where(PermissionProfile.org_id == org_id)
    )
    profiles = list(profiles_result.scalars().all())

    users_result = await db.execute(
        select(PlatformUser).where(PlatformUser.org_id == org_id)
    )
    users = list(users_result.scalars().all())

    # Map role → profile for display
    role_profile_map: dict[str, PermissionProfile | None] = {}
    for profile in profiles:
        role_profile_map[profile.name] = profile

    users_data = []
    for user in users:
        matched_profile = role_profile_map.get(user.role)
        effective = _effective_permissions(matched_profile, user)
        users_data.append({
            "user": user.to_dict(),
            "profile": matched_profile.to_dict() if matched_profile else None,
            "effective_permissions": effective,
            "mfa_enrolled": bool(user.idp_sub),  # proxy: migrated to Auth0 = enrolled
        })

    return templates.TemplateResponse(
        "permission_profiles.html",
        {
            "request": request,
            "org": org,
            "profiles": [p.to_dict() for p in profiles],
            "users_data": users_data,
            "default_profiles": DEFAULT_PROFILES,
            "tier_features": TIER_FEATURES,
        },
    )


@router.post("/api/permissions/{org_id}/profiles")
async def upsert_permission_profile(
    org_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    legacy_email = request.session.get("legacy_email")
    legacy_role = request.session.get("legacy_role")
    legacy_org = request.session.get("legacy_org_id")

    if not legacy_email:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if legacy_email != TCS_ADMIN_EMAIL and (legacy_role != "admin" or legacy_org != org_id):
        raise HTTPException(status_code=403, detail="Access denied.")

    await _get_org_or_404(db, org_id)

    body = await request.json()
    profile_name = body.get("name", "").strip()
    default_grants = body.get("default_grants", [])
    exclusions = body.get("exclusions", [])
    is_default = bool(body.get("is_default", False))

    if not profile_name:
        raise HTTPException(status_code=400, detail="Profile name is required.")

    result = await db.execute(
        select(PermissionProfile).where(
            PermissionProfile.org_id == org_id,
            PermissionProfile.name == profile_name,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.default_grants = default_grants
        existing.exclusions = exclusions
        existing.is_default = is_default
        db.add(existing)
        await db.commit()
        return JSONResponse({"ok": True, "action": "updated", "profile": existing.to_dict()})
    else:
        profile = PermissionProfile(
            org_id=org_id,
            name=profile_name,
            default_grants=default_grants,
            exclusions=exclusions,
            is_default=is_default,
        )
        db.add(profile)
        await db.commit()
        return JSONResponse({"ok": True, "action": "created", "profile": profile.to_dict()})


@router.post("/api/permissions/{org_id}/users/{user_id}/override")
async def set_user_permission_overrides(
    org_id: str,
    user_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    legacy_email = request.session.get("legacy_email")
    legacy_role = request.session.get("legacy_role")
    legacy_org = request.session.get("legacy_org_id")

    if not legacy_email:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if legacy_email != TCS_ADMIN_EMAIL and (legacy_role != "admin" or legacy_org != org_id):
        raise HTTPException(status_code=403, detail="Access denied.")

    result = await db.execute(
        select(PlatformUser).where(
            PlatformUser.id == user_id,
            PlatformUser.org_id == org_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found in this organisation.")

    body = await request.json()
    overrides = body.get("overrides", [])

    user.permission_overrides = overrides
    db.add(user)
    await db.commit()

    logger.info("Permission overrides set: user=%s overrides=%s", user_id, overrides)
    return JSONResponse({
        "ok": True,
        "user_id": user_id,
        "permission_overrides": overrides,
    })


# ---------------------------------------------------------------------------
# MFA routes
# ---------------------------------------------------------------------------

@router.get("/mfa/setup", response_class=HTMLResponse, include_in_schema=False)
async def mfa_setup_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    legacy_email = request.session.get("legacy_email")
    legacy_org_id = request.session.get("legacy_org_id")

    org = None
    if legacy_org_id:
        result = await db.execute(select(Organization).where(Organization.id == legacy_org_id))
        org = result.scalar_one_or_none()

    return templates.TemplateResponse(
        "mfa_setup.html",
        {
            "request": request,
            "org": org,
            "auth0_domain": settings.auth0_domain,
            "auth0_client_id": settings.auth0_client_id,
            "app_base_url": settings.app_base_url,
        },
    )


@router.post("/api/mfa/org/{org_id}/require")
async def toggle_org_mfa(
    org_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    legacy_email = request.session.get("legacy_email")
    legacy_role = request.session.get("legacy_role")
    legacy_org = request.session.get("legacy_org_id")

    if not legacy_email:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if legacy_email != TCS_ADMIN_EMAIL and (legacy_role != "admin" or legacy_org != org_id):
        raise HTTPException(status_code=403, detail="Access denied.")

    org = await _get_org_or_404(db, org_id)

    body = await request.json()
    required = bool(body.get("required", False))

    org.mfa_required = required
    db.add(org)
    await db.commit()

    logger.info("MFA requirement updated: org=%s required=%s", org_id, required)
    return JSONResponse({
        "ok": True,
        "org_id": org_id,
        "mfa_required": required,
    })


@router.get("/mfa/enroll", include_in_schema=False)
async def mfa_enroll_redirect(request: Request) -> RedirectResponse:
    """Redirect the user to Auth0 login with MFA enforcement via PKCE."""
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()

    request.session["pkce_verifier"] = verifier
    request.session["oauth_state"] = state

    # Map internal org_id → Auth0 org_id to bypass the org-prompt screen
    _org_map = {
        "org_acmecorp":  "org_fpQrKWcIZzkvSH4u",
        "org_globexinc": "org_IYVMR8RqFOhiVayY",
        "org_utsav":     "org_IKELHMWEuAe7hAHC",
    }
    legacy_org = request.session.get("legacy_org_id", "")
    auth0_org = _org_map.get(legacy_org)

    params: dict = {
        "response_type": "code",
        "client_id": settings.auth0_client_id,
        "redirect_uri": settings.callback_url,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "acr_values": "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
    }

    if auth0_org:
        # Passing org bypasses the org-prompt and avoids the connection conflict
        params["organization"] = auth0_org
    else:
        # No org in session — force db connection directly
        params["connection"] = "Username-Password-Authentication"

    url = f"https://{settings.auth0_domain}/authorize?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url=url, status_code=302)
