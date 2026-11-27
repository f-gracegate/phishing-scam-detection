"""Shared threat intelligence: sources, indicators, observations, campaigns and brands.

Raw submissions, extracted indicators and *verified* indicators are kept apart on purpose:
a community report only ever creates an ``unverified`` indicator, which a scan may mention as
"reported, not verified" but never treats as proof. Only an analyst decision (or a licensed
source with a recorded licence) makes an indicator ``verified``.
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

from app.models.base import Base, Timestamps, UUIDPrimaryKey


class IntelligenceSource(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "intelligence_sources"

    code: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # internal | community | feed | commercial
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    licence: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    permitted_use: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    # What may be shared onward (e.g. "never resell raw indicators").
    sharing_restrictions: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # low | medium | high
    default_confidence: Mapped[str] = mapped_column(String(8), nullable=False, default="medium")
    # How often indicators from this source must be rechecked, in days.
    recheck_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    configuration: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class ThreatCampaign(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "threat_campaigns"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # active | dormant | closed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    # A public warning may be shown on the home page. It must never contain private message
    # content or personal phone numbers.
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    public_title: Mapped[str | None] = mapped_column(String(200))
    public_summary: Mapped[str | None] = mapped_column(String(1000))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class Indicator(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("type", "value_hash"),
        Index("ix_indicators_status", "status"),
    )

    # url | domain | ip | phone | email | sender_id | momo_number | wallet
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    # Normalised value for URLs, domains, IPs and email addresses. Phone numbers and wallet
    # identifiers are personal data: only the hash and a masked form are stored.
    value: Mapped[str | None] = mapped_column(String(2048))
    value_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    display_value: Mapped[str] = mapped_column(String(300), nullable=False)
    # unverified | verified | rejected | revoked | expired
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unverified")
    # low | medium | high
    confidence: Mapped[str] = mapped_column(String(8), nullable=False, default="low")
    category: Mapped[str | None] = mapped_column(String(32))
    # malicious | suspicious (verified indicators only carry these)
    disposition: Mapped[str] = mapped_column(String(16), nullable=False, default="malicious")
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("intelligence_sources.id", ondelete="SET NULL")
    )
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_campaigns.id", ondelete="SET NULL"), index=True
    )
    report_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_summary: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    notes: Mapped[str | None] = mapped_column(Text)


class IndicatorObservation(UUIDPrimaryKey, Base):
    __tablename__ = "indicator_observations"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("intelligence_sources.id", ondelete="SET NULL")
    )
    report_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scam_reports.id", ondelete="SET NULL")
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class IndicatorHistory(UUIDPrimaryKey, Base):
    __tablename__ = "indicator_history"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    actor_label: Mapped[str | None] = mapped_column(String(320))
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str] = mapped_column(String(16), nullable=False)
    from_confidence: Mapped[str | None] = mapped_column(String(8))
    to_confidence: Mapped[str] = mapped_column(String(8), nullable=False)
    reason: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class IndicatorRelationship(UUIDPrimaryKey, Base):
    __tablename__ = "indicator_relationships"
    __table_args__ = (UniqueConstraint("from_id", "to_id", "relation"),)

    from_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    to_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    # hosts | redirects_to | resolves_to | seen_with
    relation: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class BrandProfile(UUIDPrimaryKey, Timestamps, Base):
    """A brand people may be tricked into trusting, with the domains it really uses.

    ``organisation_id`` is empty for the platform catalogue (banks, MoMo operators, agencies);
    a business may add its own brand so impersonation of it is flagged in its scans.
    """

    __tablename__ = "brand_profiles"

    organisation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organisations.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # momo | bank | government | delivery | ecommerce | telecom | education | other
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    official_domains: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Words that indicate the brand in a hostname or message ("momo", "gcb", "ssnit").
    keywords: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # Official SMS sender IDs, when known.
    sender_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    official_contact: Mapped[str | None] = mapped_column(String(300))
    # Catalogue entries should be checked by an analyst before they are relied on.
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
