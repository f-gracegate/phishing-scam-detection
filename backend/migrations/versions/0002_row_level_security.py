"""Row-Level Security: a second, database-enforced boundary around private data.

The API already scopes every query. These policies make sure that even a missed filter cannot
return another organisation's records, or another person's personal scans, to the application
role. Personal scans (no organisation) are visible only to their owner: an employer never sees
them, even when the person uses a work email address.

Shared threat intelligence (indicators, sources, campaigns, the platform brand catalogue) is
platform data without tenant rows; the API restricts who may read or change it.

Revision ID: 0002
Revises: 0001
"""

import os
from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = os.environ.get("APP_DB_USER", "psd_app")

ORG = "current_setting('app.current_org', true)"
USER = "current_setting('app.current_user', true)"
BYPASS = "current_setting('app.rls_bypass', true) = 'on'"

# Tables that belong to exactly one organisation.
TENANT_TABLES = (
    "departments",
    "invitations",
    "subscriptions",
    "payments",
    "cases",
    "case_events",
    "api_usage",
    "webhook_endpoints",
    "webhook_deliveries",
    "data_exports",
)
# Records owned by an organisation when submitted in a workspace, otherwise by one person.
OWNED = {
    "scans": "user_id",
    "scan_evidence": "user_id",
    "scan_feedback": "user_id",
    "scam_reports": "reporter_id",
    "report_evidence": "reporter_id",
    "api_keys": "user_id",
}

ALL = (
    *TENANT_TABLES,
    *OWNED,
    "memberships",
    "organisations",
    "audit_logs",
    "notifications",
    "brand_profiles",
    "user_consents",
    "push_devices",
)


def _enable(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")


def upgrade() -> None:
    for table in TENANT_TABLES:
        _enable(table)
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (organisation_id::text = {ORG} OR {BYPASS})"
        )

    for table, owner in OWNED.items():
        _enable(table)
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING ("
            f"(organisation_id IS NOT NULL AND organisation_id::text = {ORG}) "
            f"OR (organisation_id IS NULL AND {owner}::text = {USER}) OR {BYPASS})"
        )

    _enable("memberships")
    op.execute(
        "CREATE POLICY tenant_isolation ON memberships "
        f"USING (organisation_id::text = {ORG} OR user_id::text = {USER} OR {BYPASS}) "
        f"WITH CHECK (organisation_id::text = {ORG} OR {BYPASS})"
    )

    _enable("organisations")
    op.execute(
        "CREATE POLICY tenant_isolation ON organisations "
        f"USING (id::text = {ORG} OR {BYPASS} OR EXISTS ("
        "  SELECT 1 FROM memberships m WHERE m.organisation_id = organisations.id"
        f"  AND m.user_id::text = {USER} AND m.status = 'active')) "
        f"WITH CHECK (id::text = {ORG} OR {BYPASS})"
    )

    _enable("audit_logs")
    op.execute(
        "CREATE POLICY tenant_isolation ON audit_logs "
        f"USING (organisation_id::text = {ORG} OR {BYPASS} "
        f"OR (organisation_id IS NULL AND actor_id::text = {USER}))"
    )
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM {APP_ROLE}")

    for table in ("notifications", "user_consents", "push_devices"):
        _enable(table)
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING (user_id::text = {USER} OR {BYPASS})"
        )

    # Everyone may read the platform brand catalogue; organisation brands stay private, and
    # only system (staff) code paths may change the catalogue.
    _enable("brand_profiles")
    op.execute(
        "CREATE POLICY tenant_isolation ON brand_profiles "
        f"USING (organisation_id IS NULL OR organisation_id::text = {ORG} OR {BYPASS}) "
        f"WITH CHECK ((organisation_id IS NOT NULL AND organisation_id::text = {ORG}) "
        f"OR {BYPASS})"
    )

    # Payment records are kept for accounting: the application can never delete them.
    op.execute(f"REVOKE DELETE, TRUNCATE ON payments FROM {APP_ROLE}")
    # Indicator history is an append-only trail for the application.
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON indicator_history FROM {APP_ROLE}")
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON analyst_reviews FROM {APP_ROLE}")


def downgrade() -> None:
    op.execute(
        f"GRANT UPDATE, DELETE ON audit_logs, indicator_history, analyst_reviews TO {APP_ROLE}"
    )
    for table in ALL:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
