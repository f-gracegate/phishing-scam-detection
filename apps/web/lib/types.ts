export type User = {
  id: string;
  email: string;
  username: string | null;
  full_name: string;
  is_platform_admin: boolean;
  platform_role: string;
  must_change_password: boolean;
  mfa_enabled: boolean;
  email_verified_at: string | null;
  last_login_at: string | null;
  created_at: string;
};

export type MembershipSummary = {
  organisation_id: string;
  organisation_name: string;
  role: string;
  role_label: string;
  permissions: string[];
  require_mfa: boolean;
};

export type Me = {
  user: User;
  memberships: MembershipSummary[];
  intel_permissions: string[];
  personal_plan: "free" | "plus";
};

export type LoginResponse = { status: "ok" | "mfa_required"; mfa_token?: string; me?: Me };

export type Organisation = {
  id: string;
  name: string;
  industry: string | null;
  size: string | null;
  country: string;
  timezone: string;
  phone: string | null;
  address: string | null;
  website: string | null;
  status: string;
  require_mfa: boolean;
  content_retention_days: number;
  deletion_scheduled_for: string | null;
  created_at: string;
};

export type Member = {
  id: string;
  user_id: string;
  email: string;
  full_name: string;
  role: string;
  role_label: string;
  status: "active" | "suspended";
  department_id: string | null;
  department_name: string | null;
  mfa_enabled: boolean;
  last_login_at: string | null;
  joined_at: string;
  is_you: boolean;
};

export type Invitation = {
  id: string;
  email: string;
  role: string;
  created_at: string;
  expires_at: string;
  invited_by_email: string | null;
};

export type Department = { id: string; name: string; created_at: string };
export type RoleInfo = { value: string; label: string; permissions: string[] };

export type Page<T> = { items: T[]; total: number; page: number; page_size: number };

export type AuditEntry = {
  id: string;
  action: string;
  actor_label: string | null;
  resource_type: string | null;
  resource_id: string | null;
  details: Record<string, unknown>;
  ip_address: string | null;
  created_at: string;
};

export type Plan = {
  code: string;
  name: string;
  monthly_price_ghs: number | null;
  annual_price_ghs: number | null;
  member_limit: number | null;
  monthly_scans: number | null;
  api_access: boolean;
  webhooks: boolean;
  features: string[];
};

export type SubscriptionStatus = "trialing" | "active" | "past_due" | "expired" | "cancelled";

export type Subscription = {
  plan: Plan;
  status: SubscriptionStatus;
  billing_period: "monthly" | "annual";
  current_period_end: string | null;
  grace_until: string | null;
  days_left: number | null;
  members_used: number;
  scans_this_month: number;
  available_plans: Plan[];
  payment_provider: string;
  has_paid: boolean;
  annual_months_charged: number;
  contact_email: string;
};

export type PaymentChannel = "mobile_money" | "card";

export type Payment = {
  id: string;
  reference: string;
  plan_code: string;
  plan_name: string;
  billing_period: "monthly" | "annual";
  amount_minor: number;
  currency: string;
  channel: PaymentChannel;
  status: "pending" | "success" | "failed" | "abandoned";
  failure_reason: string | null;
  payment_method: { brand?: string; last4?: string; network?: string; phone?: string };
  receipt: string | null;
  credit_days: number;
  period_start: string | null;
  period_end: string | null;
  paid_at: string | null;
  created_at: string;
};

export type CheckoutResult = {
  reference: string;
  authorization_url: string;
  amount_minor: number;
  currency: string;
};

export type PushDevice = {
  id: string;
  platform: "android" | "ios";
  device_name: string | null;
  app_version: string | null;
  enabled: boolean;
  this_device: boolean;
  created_at: string;
  last_seen_at: string;
  last_error: string | null;
};

export type PlatformOrganisation = {
  id: string;
  name: string;
  industry: string | null;
  status: string;
  plan_code: string | null;
  members: number;
  scans_total: number;
  created_at: string;
};

export type AppNotification = {
  id: string;
  kind: string;
  severity: string;
  title: string;
  body: string;
  link: string | null;
  read: boolean;
  created_at: string;
  organisation_id: string | null;
};

export type NotificationList = { items: AppNotification[]; unread: number };

export type Retention = { content_retention_days: number; max_days: number | null };

export type DataExport = {
  id: string;
  status: "ready" | "failed" | "expired";
  size_bytes: number | null;
  sha256: string | null;
  summary: string | null;
  requested_by_name: string | null;
  created_at: string;
  expires_at: string;
};

// --- Scanning ----------------------------------------------------------------------------

export type ScanKind = "url" | "message" | "email" | "qr";
export type Verdict = "low" | "caution" | "suspicious" | "high" | "critical" | "unknown";
export type Confidence = "low" | "medium" | "high";

export type Scan = {
  id: string;
  kind: ScanKind;
  source: string;
  status: "queued" | "running" | "completed" | "failed";
  title: string;
  verdict: Verdict | null;
  verdict_label: string | null;
  risk_score: number | null;
  confidence: Confidence | null;
  headline: string | null;
  summary: string | null;
  category: string | null;
  category_label: string | null;
  recommendations: string[];
  error: string | null;
  created_at: string;
  completed_at: string | null;
  organisation_id: string | null;
  submitted_by: string | null;
};

export type Evidence = {
  layer: string;
  code: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
  source_kind: "model" | "verified_intel" | "external_provider" | "community" | "observed";
  source_label: string;
  source_name: string;
  reliability: Confidence;
  weight: number;
  observed_at: string;
  data: Record<string, unknown>;
};

export type LinkDetail = {
  url?: string;
  display_host?: string;
  domain?: string;
  scheme?: string;
  error?: string;
  final_domain?: string;
  intelligence?: { provider: string; status: string }[];
  registration?: { domain: string; registered_at?: string; age_days?: number; registrar?: string };
  website?: {
    reachable: boolean;
    final_url?: string | null;
    status?: number | null;
    title?: string;
    error?: string;
    forms?: number;
    password_fields?: number;
    sensitive_fields?: string[];
    server?: string | null;
    redirects?: { url: string; status: number; to: string | null }[];
    tls?: {
      trusted: boolean;
      issuer?: string | null;
      valid_from?: string | null;
      valid_to?: string | null;
      error?: string | null;
      age_days?: number;
    };
  };
};

export type ScanArtifacts = {
  link?: LinkDetail;
  extracted?: {
    links: LinkDetail[];
    phones: string[];
    dial_codes: string[];
    amounts: string[];
    transaction_ids: string[];
    emails: string[];
    brands_mentioned: string[];
    removed_secrets: string[];
  };
  email?: {
    from: string | null;
    reply_to: string | null;
    return_path: string | null;
    subject: string | null;
    date: string | null;
    received_hops: number;
    authentication: Record<string, string>;
    attachments: { filename: string; content_type: string; size: number }[];
    headers_provided: boolean;
  };
  qr?: { decoded_as: "url" | "text" };
};

export type ScanDetail = Scan & {
  artifacts: ScanArtifacts;
  evidence: Evidence[];
  feedback: string | null;
  content_available: boolean;
};

export type Quota = { scope: "personal" | "organisation"; limit: number | null; used: number; period: string };

export type Warning = {
  id: string;
  title: string;
  summary: string;
  category: string;
  category_label: string;
  published_at: string;
};

export type ScamReport = {
  id: string;
  category: string;
  category_label: string;
  channel: string;
  url: string | null;
  phone: string | null;
  sender: string | null;
  description: string;
  occurred_on: string | null;
  money_lost: boolean;
  status: "unverified" | "under_review" | "verified" | "rejected" | "duplicate";
  status_label: string;
  public_note: string | null;
  created_at: string;
  updated_at: string;
  evidence: { id: string; filename: string; content_type: string; size_bytes: number; created_at: string }[];
  organisation_id: string | null;
};

// --- Business -----------------------------------------------------------------------------

export type Analytics = {
  days: number;
  total_scans: number;
  high_risk: number;
  suspicious: number;
  phishing_detections: number;
  by_verdict: Record<string, number>;
  by_kind: Record<string, number>;
  categories: { category: string; label: string; count: number }[];
  trend: { day: string; scans: number; high_risk: number }[];
  suspicious_domains: { domain: string; count: number }[];
  employee_reports: number;
  active_investigations: number;
  api_calls: number;
};

export type Case = {
  id: string;
  reference: string;
  title: string;
  description: string;
  status: "open" | "investigating" | "closed";
  severity: "low" | "medium" | "high" | "critical";
  category: string | null;
  category_label: string | null;
  assignee_id: string | null;
  assignee: string | null;
  created_by: string | null;
  scan_ids: string[];
  report_ids: string[];
  outcome: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
};

export type CaseDetail = Case & {
  events: { id: string; kind: string; message: string; actor: string | null; created_at: string }[];
  scans: Scan[];
};

export type ApiKey = {
  id: string;
  name: string;
  prefix: string;
  status: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  secret?: string;
};

export type Webhook = {
  id: string;
  url: string;
  description: string;
  events: string[];
  active: boolean;
  consecutive_failures: number;
  created_at: string;
  last_delivery: { status: string; response_status: number | null; error: string | null; at: string } | null;
  secret?: string;
};

export type Brand = {
  id: string;
  name: string;
  category: string;
  official_domains: string[];
  keywords: string[];
  sender_ids: string[];
  official_contact: string | null;
  verified: boolean;
  active: boolean;
  organisation_id: string | null;
};

// --- Threat intelligence -------------------------------------------------------------------

export type Indicator = {
  id: string;
  type: string;
  display_value: string;
  status: "unverified" | "verified" | "rejected" | "revoked" | "expired";
  confidence: Confidence;
  disposition: string;
  category: string | null;
  category_label: string | null;
  report_count: number;
  campaign_id: string | null;
  source: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_verified_at: string | null;
  expires_at: string | null;
  evidence_summary: string | null;
  references: string[];
  notes: string | null;
};

export type QueueReport = {
  id: string;
  category: string;
  category_label: string;
  channel: string;
  url: string | null;
  phone: string | null;
  sender: string | null;
  description: string;
  status: string;
  money_lost: boolean;
  organisation_report: boolean;
  created_at: string;
};

export type Campaign = {
  id: string;
  name: string;
  category: string;
  category_label: string;
  description: string;
  status: "active" | "dormant" | "closed";
  published: boolean;
  public_title: string | null;
  public_summary: string | null;
  published_at: string | null;
  indicators: number;
  created_at: string;
  updated_at: string;
};

export type IntelSource = {
  code: string;
  name: string;
  kind: string;
  licence: string;
  permitted_use: string;
  sharing_restrictions: string;
  enabled: boolean;
  default_confidence: Confidence;
  recheck_days: number;
  indicators: number;
  credentials_configured: boolean | null;
  last_synced_at: string | null;
};
