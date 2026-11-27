"""Scans of submitted links, messages, emails and QR codes, with their evidence.

A scan belongs to one person. When it was submitted inside an organisation workspace it also
carries ``organisation_id``; personal scans have none and are never visible to an employer,
even when the person signed up with a work email address.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDPrimaryKey


class Scan(UUIDPrimaryKey, Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_user_created", "user_id", "created_at"),
        Index("ix_scans_org_created", "organisation_id", "created_at"),
        Index("ix_scans_status", "status"),
    )

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")
    )
    organisation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE")
    )
    # Business API key that submitted it (no person involved).
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("api_keys.id", ondelete="SET NULL")
    )
    batch_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    # url | message | email | qr
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # web | mobile | extension | api | share | bulk
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="web")
    # queued | running | completed | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    # A short, redacted label for lists: the URL, an email subject or the start of a message.
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Redacted submitted content, Fernet-encrypted, erased after the retention period.
    content_encrypted: Mapped[str | None] = mapped_column(Text)
    content_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    allow_external_lookup: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # low | caution | suspicious | high | critical | unknown
    verdict: Mapped[str | None] = mapped_column(String(16))
    risk_score: Mapped[int | None] = mapped_column(Integer)
    # low | medium | high
    confidence: Mapped[str | None] = mapped_column(String(8))
    headline: Mapped[str | None] = mapped_column(String(200))
    summary: Mapped[str | None] = mapped_column(Text)
    recommendations: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Scam category the engine thinks fits best (momo, bank, government, delivery, ...).
    category: Mapped[str | None] = mapped_column(String(32))
    # Technical details: canonical URL, redirect chain, DNS, TLS, page facts, email headers,
    # extracted indicators. Never contains raw message text.
    artifacts: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(String(300))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanEvidence(UUIDPrimaryKey, Base):
    """One reason behind a verdict, with where it came from and how reliable it is."""

    __tablename__ = "scan_evidence"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    # Copied from the scan for Row-Level Security.
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    organisation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # reputation | domain | website | message | email | community | positive
    layer: Mapped[str] = mapped_column(String(16), nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    # info | low | medium | high | critical
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # model (our own rules) | verified_intel | external_provider | community | observed
    source_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    source_name: Mapped[str] = mapped_column(String(120), nullable=False)
    # low | medium | high: how reliable this one piece of evidence is.
    reliability: Mapped[str] = mapped_column(String(8), nullable=False, default="medium")
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    weight: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ScanFeedback(UUIDPrimaryKey, Base):
    """A person telling us a verdict was wrong (or right). Analysts review the wrong ones."""

    __tablename__ = "scan_feedback"
    __table_args__ = (UniqueConstraint("scan_id", "user_id"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    organisation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE")
    )
    # false_positive | false_negative | correct
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    comment: Mapped[str | None] = mapped_column(String(2000))
    # open | accepted | dismissed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    resolution: Mapped[str | None] = mapped_column(String(2000))
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Domain(UUIDPrimaryKey, Base):
    """Cached facts about a registrable domain (registration date, DNS), shared across scans."""

    __tablename__ = "domains"

    name: Mapped[str] = mapped_column(String(253), unique=True, nullable=False)
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    registrar: Mapped[str | None] = mapped_column(String(200))
    rdap_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dns: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    dns_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
