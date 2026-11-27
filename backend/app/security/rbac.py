"""Role-based access control, enforced in the API layer for every request.

Two kinds of role exist:

* organisation roles (a membership in a business workspace), and
* platform roles for GraceGate staff who curate the shared threat intelligence.

A consumer is simply a signed-in user acting outside any organisation.
"""

from enum import StrEnum


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    REVIEWER = "reviewer"
    EMPLOYEE = "employee"


ROLE_LABELS = {
    Role.OWNER: "Organisation Owner",
    Role.ADMIN: "Organisation Administrator",
    Role.SECURITY_ANALYST: "Security Analyst",
    Role.REVIEWER: "Reviewer",
    Role.EMPLOYEE: "Employee",
}


class Perm(StrEnum):
    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    MEMBERS_READ = "members:read"
    MEMBERS_MANAGE = "members:manage"
    DEPARTMENTS_MANAGE = "departments:manage"
    AUDIT_READ = "audit:read"
    BILLING_READ = "billing:read"
    BILLING_MANAGE = "billing:manage"
    # Submit scans and see your own.
    SCANS_SUBMIT = "scans:submit"
    # See every scan in the organisation.
    SCANS_READ_ALL = "scans:read_all"
    SCANS_BULK = "scans:bulk"
    REPORTS_READ = "reports:read"
    CASES_READ = "cases:read"
    CASES_MANAGE = "cases:manage"
    ANALYTICS_READ = "analytics:read"
    API_MANAGE = "api:manage"
    WEBHOOKS_MANAGE = "webhooks:manage"
    BRANDS_MANAGE = "brands:manage"


_ALL = frozenset(Perm)

ROLE_PERMISSIONS: dict[Role, frozenset[Perm]] = {
    Role.OWNER: _ALL,
    Role.ADMIN: _ALL - {Perm.BILLING_MANAGE},
    Role.SECURITY_ANALYST: frozenset(
        {
            Perm.ORG_READ,
            Perm.MEMBERS_READ,
            Perm.SCANS_SUBMIT,
            Perm.SCANS_READ_ALL,
            Perm.SCANS_BULK,
            Perm.REPORTS_READ,
            Perm.CASES_READ,
            Perm.CASES_MANAGE,
            Perm.ANALYTICS_READ,
            Perm.BRANDS_MANAGE,
        }
    ),
    Role.REVIEWER: frozenset(
        {
            Perm.ORG_READ,
            Perm.MEMBERS_READ,
            Perm.SCANS_SUBMIT,
            Perm.SCANS_READ_ALL,
            Perm.REPORTS_READ,
            Perm.CASES_READ,
            Perm.ANALYTICS_READ,
        }
    ),
    Role.EMPLOYEE: frozenset({Perm.ORG_READ, Perm.SCANS_SUBMIT}),
}

# What a business API key may do (it acts for the organisation, not for a person).
API_KEY_PERMISSIONS = frozenset({Perm.ORG_READ, Perm.SCANS_SUBMIT, Perm.SCANS_READ_ALL})


def permissions_for(role: str) -> frozenset[Perm]:
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return frozenset()


def can_assign_role(actor_role: str, target_role: str) -> bool:
    """Only owners can grant or remove the owner role. Admins manage every other role."""
    if actor_role == Role.OWNER:
        return True
    if actor_role == Role.ADMIN:
        return target_role != Role.OWNER
    return False


# --- Platform (threat intelligence) roles ------------------------------------------------------


class PlatformRole(StrEnum):
    ANALYST = "analyst"
    REVIEWER = "reviewer"


class IntelPerm(StrEnum):
    # See indicators, the report queue and false-positive feedback.
    READ = "intel:read"
    # Review community reports and feedback; propose indicator changes.
    REVIEW = "intel:review"
    # Verify, publish, revoke indicators; manage campaigns.
    PUBLISH = "intel:publish"
    # Manage intelligence sources and the brand catalogue.
    ADMIN = "intel:admin"


PLATFORM_PERMISSIONS: dict[str, frozenset[IntelPerm]] = {
    PlatformRole.REVIEWER: frozenset({IntelPerm.READ, IntelPerm.REVIEW}),
    PlatformRole.ANALYST: frozenset({IntelPerm.READ, IntelPerm.REVIEW, IntelPerm.PUBLISH}),
}


def intel_permissions(is_platform_admin: bool, platform_role: str) -> frozenset[IntelPerm]:
    if is_platform_admin:
        return frozenset(IntelPerm)
    return PLATFORM_PERMISSIONS.get(platform_role, frozenset())
