"""Scam reports from the public and from organisations, and the analyst decisions on them.

Every report starts ``unverified``. A report never makes a phone number, domain or person
publicly "a scammer" by itself; only an analyst review can turn what it names into a verified
indicator.
"""

import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, Timestamps, UUIDPrimaryKey


class ScamReport(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "scam_reports"
    __table_args__ = (
        UniqueConstraint("reporter_id", "idempotency_key"),
        Index("ix_scam_reports_status_created", "status", "created_at"),
    )

    reporter_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    organisation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(80))
    # momo | bank | government | delivery | recruitment | investment | ecommerce |
    # social_engineering | impersonation | crypto | university | romance | other
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    # sms | whatsapp | email | website | social | phone_call | other
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    url: Mapped[str | None] = mapped_column(String(2048))
    # Personal data: the phone number is stored encrypted, with a hash for duplicate matching.
    phone_encrypted: Mapped[str | None] = mapped_column(Text)
    phone_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    phone_display: Mapped[str | None] = mapped_column(String(40))
    sender: Mapped[str | None] = mapped_column(String(320))
    # Redacted message text, encrypted.
    message_encrypted: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_on: Mapped[date | None] = mapped_column(Date)
    money_lost: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    contact_email: Mapped[str | None] = mapped_column(String(320))
    consent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # unverified | under_review | verified | rejected | duplicate
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unverified")
    duplicate_of: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scam_reports.id", ondelete="SET NULL")
    )
    # Indicators extracted from the report (ids), all unverified at first.
    indicator_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    public_note: Mapped[str | None] = mapped_column(String(1000))


class ReportEvidence(UUIDPrimaryKey, Base):
    __tablename__ = "report_evidence"

    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scam_reports.id", ondelete="CASCADE"), index=True
    )
    # Copied for Row-Level Security.
    reporter_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    organisation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    storage_key: Mapped[str] = mapped_column(String(200), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AnalystReview(UUIDPrimaryKey, Base):
    __tablename__ = "analyst_reviews"

    report_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scam_reports.id", ondelete="CASCADE"), index=True
    )
    indicator_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    # verify | reject | duplicate | request_info | revoke | downgrade
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
