"""
SQLAlchemy ORM models for the Platform database.

Design principle: Auth0 (IdP) stores credentials only.
All tenant, role, and entitlement context lives here.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# JSON helper — SQLite does not have a native JSON column type, so we store
# JSON-serialised text and expose it as a Python list / dict.
# ---------------------------------------------------------------------------

class JsonList(TypeDecorator):
    """Custom type that transparently serialises/deserialises JSON lists."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: D401
        if value is None:
            return "[]"
        if isinstance(value, str):
            return value  # already serialised
        return json.dumps(value)

    def process_result_value(self, value, dialect):  # noqa: D401
        if value is None:
            return []
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(64), primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    # Auth0 Organization ID — set after the org is created in Auth0
    auth0_org_id = Column(String(64), nullable=True, unique=True)
    # JSON list of approved email domains, e.g. ["acmecorp.com"]
    approved_domains = Column(JsonList, nullable=False, default=list)
    # Subscription fields
    subscription_tier = Column(String(32), nullable=False, default="free")
    add_ons = Column(JsonList, nullable=False, default=list)
    mfa_required = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    users = relationship("PlatformUser", back_populates="organization")
    approvals = relationship("Approval", back_populates="organization")
    permission_profiles = relationship("PermissionProfile", back_populates="organization", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Organization id={self.id} name={self.name!r}>"


# ---------------------------------------------------------------------------
# Platform Users
# ---------------------------------------------------------------------------

class UserStatus(str):
    INVITED = "invited"                            # Admin sent invite, user hasn't accepted yet
    PENDING_ROLE_ASSIGNMENT = "pending_role_assignment"  # User accepted + set password, waiting for admin to assign role
    ACTIVE = "active"                              # Role assigned, fully onboarded
    REJECTED = "rejected"                          # Admin denied
    EXPIRED = "expired"                            # Invitation expired


class MigrationStatus(str):
    PENDING   = "pending"    # legacy user, not yet migrated to Auth0
    EMAIL_SENT = "email_sent" # Auth0 account created, activation email sent
    COMPLETED  = "completed"  # user clicked link, idp_sub linked, migration done


class PlatformUser(Base):
    __tablename__ = "platform_users"

    id = Column(String(64), primary_key=True, default=_uuid)
    # Auth0 subject — e.g. "auth0|abc123". Null for legacy users not yet migrated.
    idp_sub = Column(String(255), nullable=True, unique=True)
    email = Column(String(255), nullable=False)
    email_verified = Column(Boolean, default=False)
    org_id = Column(String(64), ForeignKey("organizations.id"), nullable=False)
    role = Column(String(64), nullable=True)
    entitlements = Column(JsonList, nullable=False, default=list)
    permission_overrides = Column(JsonList, nullable=False, default=list)
    status = Column(String(32), nullable=False, default=UserStatus.INVITED)
    # Legacy password hash (bcrypt) — present for Kinsta-migrated users, null for new Auth0 users
    password_hash = Column(String(255), nullable=True)
    # Tracks migration state for legacy users
    migration_status = Column(String(32), nullable=True)
    invited_by = Column(String(255), nullable=True)
    invited_at = Column(DateTime(timezone=True), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    organization = relationship("Organization", back_populates="users")
    approvals = relationship("Approval", back_populates="user")

    __table_args__ = (
        UniqueConstraint("email", "org_id", name="uq_email_org"),
    )

    def __repr__(self) -> str:
        return f"<PlatformUser id={self.id} email={self.email!r} status={self.status!r}>"

    @property
    def is_legacy(self) -> bool:
        """True if this user was imported from Kinsta DB (has password_hash)."""
        return self.password_hash is not None

    @property
    def is_migrated(self) -> bool:
        """True if legacy user has completed Auth0 migration."""
        return self.idp_sub is not None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "idp_sub": self.idp_sub,
            "email": self.email,
            "email_verified": self.email_verified,
            "org_id": self.org_id,
            "role": self.role,
            "entitlements": self.entitlements if isinstance(self.entitlements, list) else [],
            "status": self.status,
            "is_legacy": self.is_legacy,
            "is_migrated": self.is_migrated,
            "migration_status": self.migration_status,
            "invited_by": self.invited_by,
            "invited_at": self.invited_at.isoformat() if self.invited_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------

class ApprovalStatus(str):
    PENDING_APPROVAL = "pending_approval"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    DENIED = "denied"


class Approval(Base):
    __tablename__ = "approvals"

    id = Column(String(64), primary_key=True, default=_uuid)
    user_id = Column(String(64), ForeignKey("platform_users.id"), nullable=False)
    org_id = Column(String(64), ForeignKey("organizations.id"), nullable=False)
    status = Column(String(32), nullable=False, default=ApprovalStatus.PENDING_APPROVAL)
    role_requested = Column(String(64), nullable=True)
    # Free-text notes from reviewer or auto-approval engine
    reason = Column(Text, nullable=True)
    reviewed_by = Column(String(255), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    # JSON list of entitlements granted on approval
    entitlements_granted = Column(JsonList, nullable=False, default=list)
    auto_approved = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    user = relationship("PlatformUser", back_populates="approvals")
    organization = relationship("Organization", back_populates="approvals")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "org_id": self.org_id,
            "status": self.status,
            "role_requested": self.role_requested,
            "reason": self.reason,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "entitlements_granted": self.entitlements_granted if isinstance(self.entitlements_granted, list) else [],
            "auto_approved": self.auto_approved,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ---------------------------------------------------------------------------
# Permission Profiles
# ---------------------------------------------------------------------------

class PermissionProfile(Base):
    __tablename__ = "permission_profiles"

    id = Column(String(64), primary_key=True, default=_uuid)
    org_id = Column(String(64), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(64), nullable=False)          # viewer, member, analyst, admin
    default_grants = Column(JsonList, nullable=False, default=list)
    exclusions = Column(JsonList, nullable=False, default=list)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    organization = relationship("Organization", back_populates="permission_profiles")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "name": self.name,
            "default_grants": self.default_grants if isinstance(self.default_grants, list) else [],
            "exclusions": self.exclusions if isinstance(self.exclusions, list) else [],
            "is_default": self.is_default,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
