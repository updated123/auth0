"""
AuthService — wraps all Auth0 Management API calls.

Keeps a cached Management API access token (expires in 24 h).
All HTTP calls use httpx.AsyncClient for full async compatibility.

Swap the implementation of each method to point at a different IdP
without touching any business logic.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class Auth0ManagementError(Exception):
    """Raised when the Auth0 Management API returns an error."""

    def __init__(self, message: str, status_code: int = 500) -> None:
        super().__init__(message)
        self.status_code = status_code


class AuthService:
    """
    Thin async wrapper around the Auth0 Management API v2.

    Instance-level token cache: the same AuthService instance (registered as
    a FastAPI dependency singleton) holds one management token, refreshed
    automatically before expiry.
    """

    def __init__(self) -> None:
        self._mgmt_token: Optional[str] = None
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get_mgmt_token(self) -> str:
        """Return a valid Management API bearer token, refreshing if needed."""
        if self._mgmt_token and time.monotonic() < self._token_expires_at - 60:
            return self._mgmt_token

        logger.info("Fetching new Auth0 Management API token.")
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                settings.auth0_token_url,
                json={
                    "grant_type": "client_credentials",
                    "client_id": settings.auth0_mgmt_client_id,
                    "client_secret": settings.auth0_mgmt_client_secret,
                    "audience": f"https://{settings.auth0_domain}/api/v2/",
                },
            )
            if resp.status_code != 200:
                raise Auth0ManagementError(
                    f"Failed to obtain Management API token: {resp.text}", resp.status_code
                )
            data = resp.json()

        self._mgmt_token = data["access_token"]
        # expires_in is in seconds; default 86400 (24 h)
        self._token_expires_at = time.monotonic() + data.get("expires_in", 86400)
        logger.info("Management API token obtained (expires in %ds).", data.get("expires_in", 86400))
        return self._mgmt_token

    async def _mgmt_request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Any:
        """Make an authenticated request to the Management API."""
        token = await self._get_mgmt_token()
        url = f"{settings.auth0_mgmt_base}{path}"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.request(
                method,
                url,
                headers={"Authorization": f"Bearer {token}"},
                json=json,
                params=params,
            )

        if resp.status_code in (200, 201, 204):
            if resp.content:
                return resp.json()
            return {}

        error_body = resp.text
        logger.error("Management API error %s %s → %d: %s", method, path, resp.status_code, error_body)
        raise Auth0ManagementError(
            f"Management API error ({resp.status_code}): {error_body}",
            resp.status_code,
        )

    # ------------------------------------------------------------------
    # Organizations
    # ------------------------------------------------------------------

    async def create_organization(self, name: str, display_name: str) -> dict:
        """Create an Auth0 Organization."""
        return await self._mgmt_request(
            "POST",
            "/organizations",
            json={"name": name, "display_name": display_name},
        )

    async def get_organization(self, org_id: str) -> dict:
        """Fetch an Auth0 Organization by its Auth0 org ID."""
        return await self._mgmt_request("GET", f"/organizations/{org_id}")

    async def list_organization_members(self, auth0_org_id: str, page: int = 0, per_page: int = 50) -> dict:
        """List members of an Auth0 Organization."""
        return await self._mgmt_request(
            "GET",
            f"/organizations/{auth0_org_id}/members",
            params={"page": page, "per_page": per_page, "include_totals": "true"},
        )

    # ------------------------------------------------------------------
    # Invitations
    # ------------------------------------------------------------------

    async def create_invitation(
        self,
        auth0_org_id: str,
        invitee_email: str,
        inviter_name: str,
        roles: Optional[List[str]] = None,
        connection_id: Optional[str] = None,
        ttl_sec: int = 604800,  # 7 days
    ) -> dict:
        """
        Send an invitation via Auth0 Organizations Invitation API.

        Returns the created invitation object.
        """
        payload: Dict[str, Any] = {
            "inviter": {"name": inviter_name},
            "invitee": {"email": invitee_email},
            "client_id": settings.auth0_client_id,
            "ttl_sec": ttl_sec,
            "send_invitation_email": True,
        }
        if roles:
            payload["roles"] = roles
        if connection_id:
            payload["connection_id"] = connection_id

        return await self._mgmt_request(
            "POST",
            f"/organizations/{auth0_org_id}/invitations",
            json=payload,
        )

    async def list_invitations(self, auth0_org_id: str) -> list:
        """List pending invitations for an Auth0 Organization."""
        result = await self._mgmt_request(
            "GET",
            f"/organizations/{auth0_org_id}/invitations",
            params={"per_page": 100},
        )
        # Response can be a list directly or wrapped
        if isinstance(result, list):
            return result
        return result.get("invitations", result)

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    async def get_user(self, user_id: str) -> dict:
        """Fetch a user by Auth0 user_id (e.g. auth0|abc123)."""
        return await self._mgmt_request("GET", f"/users/{user_id}")

    async def block_user(self, user_id: str) -> dict:
        """Block a user (prevents login)."""
        return await self._mgmt_request(
            "PATCH", f"/users/{user_id}", json={"blocked": True}
        )

    async def unblock_user(self, user_id: str) -> dict:
        """Unblock a user (re-enables login after approval)."""
        return await self._mgmt_request(
            "PATCH", f"/users/{user_id}", json={"blocked": False}
        )

    async def update_user_metadata(self, user_id: str, app_metadata: dict) -> dict:
        """
        Write key/value pairs to a user's app_metadata.
        Note: per architecture principle, we write minimal metadata here;
        the platform DB is the source of truth for roles/entitlements.
        """
        return await self._mgmt_request(
            "PATCH",
            f"/users/{user_id}",
            json={"app_metadata": app_metadata},
        )

    async def search_users_by_email(self, email: str) -> list:
        """Search for Auth0 users with a given email address."""
        result = await self._mgmt_request(
            "GET",
            "/users",
            params={"q": f'email:"{email}"', "search_engine": "v3"},
        )
        if isinstance(result, list):
            return result
        return result.get("users", [])


# ---------------------------------------------------------------------------
# Singleton — import this in dependencies.py
# ---------------------------------------------------------------------------
auth_service = AuthService()
