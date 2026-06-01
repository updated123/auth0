"""
JWKS-based JWT validation with an in-process, TTL-aware cache.

Design:
- Public keys are downloaded once per hour from Auth0's JWKS endpoint.
- The cache lives in module-level state (no Redis required for a POC).
- Validation uses python-jose which handles RS256 automatically.
- We only extract sub/email/email_verified — the JWT stays thin.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

import httpx
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError

from app.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# JWKS Cache
# ---------------------------------------------------------------------------

_JWKS_TTL_SECONDS = 3600  # 1 hour

_jwks_cache: Dict[str, Any] = {
    "keys": None,
    "fetched_at": 0.0,
}


async def _get_jwks() -> dict:
    """Return cached JWKS, refreshing if stale."""
    now = time.monotonic()
    if _jwks_cache["keys"] is None or (now - _jwks_cache["fetched_at"]) > _JWKS_TTL_SECONDS:
        logger.info("Fetching JWKS from %s", settings.auth0_jwks_uri)
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(settings.auth0_jwks_uri)
            response.raise_for_status()
        _jwks_cache["keys"] = response.json()
        _jwks_cache["fetched_at"] = now
        logger.info("JWKS refreshed — %d key(s) cached.", len(_jwks_cache["keys"].get("keys", [])))
    return _jwks_cache["keys"]


def invalidate_jwks_cache() -> None:
    """Force the next validation to re-download JWKS (useful in tests)."""
    _jwks_cache["keys"] = None
    _jwks_cache["fetched_at"] = 0.0


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------

class TokenValidationError(Exception):
    """Raised when JWT validation fails for any reason."""

    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


async def validate_token(token: str) -> Dict[str, Any]:
    """
    Validate a Bearer JWT and return its payload.

    Raises TokenValidationError on any failure.

    Returns a dict with at minimum:
        sub, email, email_verified
    """
    try:
        jwks = await _get_jwks()
    except httpx.HTTPError as exc:
        logger.error("Failed to fetch JWKS: %s", exc)
        raise TokenValidationError("Unable to fetch token signing keys.", 503) from exc

    # Decode header to get kid
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise TokenValidationError(f"Invalid token header: {exc}") from exc

    kid = unverified_header.get("kid")
    if not kid:
        raise TokenValidationError("Token header missing 'kid'.")

    # Find matching key
    rsa_key: Optional[dict] = None
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key.get("use"),
                "n": key["n"],
                "e": key["e"],
            }
            break

    if rsa_key is None:
        # Key not found — could be a key rotation; refresh cache once and retry
        invalidate_jwks_cache()
        try:
            jwks = await _get_jwks()
        except httpx.HTTPError as exc:
            raise TokenValidationError("Unable to refresh token signing keys.", 503) from exc

        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key.get("use"),
                    "n": key["n"],
                    "e": key["e"],
                }
                break

        if rsa_key is None:
            raise TokenValidationError("Token signing key not found in JWKS.")

    # Validate the token
    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=settings.auth0_audience,
            issuer=settings.auth0_issuer,
            options={"verify_at_hash": False},
        )
    except ExpiredSignatureError as exc:
        raise TokenValidationError("Token has expired.") from exc
    except JWTError as exc:
        raise TokenValidationError(f"Token validation failed: {exc}") from exc

    return payload


def extract_thin_claims(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return only the thin claims we allow the IdP to assert.
    All business context is fetched from the platform DB separately.
    """
    return {
        "sub": payload.get("sub"),
        "email": payload.get("email"),
        "email_verified": payload.get("email_verified", False),
    }
