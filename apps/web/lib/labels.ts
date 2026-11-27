// Plain-language labels. People should never have to decode internal identifiers.

export const INDUSTRIES = [
  { value: "retail", label: "Retail" },
  { value: "ecommerce", label: "Ecommerce" },
  { value: "hospitality", label: "Hotels & hospitality" },
  { value: "education", label: "Schools & education" },
  { value: "healthcare", label: "Clinics & healthcare" },
  { value: "professional_services", label: "Professional services (legal, accounting)" },
  { value: "finance", label: "Banking, fintech & financial services" },
  { value: "telecom", label: "Telecommunications" },
  { value: "government", label: "Government" },
  { value: "technology", label: "Technology" },
  { value: "logistics", label: "Logistics & delivery" },
  { value: "ngo", label: "NGO / non-profit" },
  { value: "other", label: "Other" },
];

export const SIZES = ["1-10", "11-50", "51-200", "201-500", "500+"];

export type Tone = "neutral" | "info" | "success" | "warning" | "high" | "critical" | "primary";

// --- Verdicts --------------------------------------------------------------------------------

export const VERDICTS: Record<string, { label: string; tone: Tone; short: string }> = {
  critical: { label: "Critical risk", tone: "critical", short: "Critical" },
  high: { label: "High risk", tone: "critical", short: "High risk" },
  suspicious: { label: "Suspicious", tone: "high", short: "Suspicious" },
  caution: { label: "Caution", tone: "warning", short: "Caution" },
  low: { label: "Low risk", tone: "success", short: "Low risk" },
  unknown: { label: "Unknown — insufficient evidence", tone: "neutral", short: "Unknown" },
};

export const verdictTone = (v: string | null | undefined): Tone =>
  (v && VERDICTS[v]?.tone) || "neutral";

export const CONFIDENCE: Record<string, string> = {
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence",
};

export const SEVERITY_TONE: Record<string, Tone> = {
  critical: "critical",
  high: "high",
  medium: "warning",
  low: "info",
  info: "neutral",
};

export const SOURCE_TONE: Record<string, Tone> = {
  verified_intel: "critical",
  external_provider: "high",
  model: "primary",
  community: "warning",
  observed: "neutral",
};

export const SCAN_KINDS: Record<string, string> = {
  url: "Link",
  message: "Message",
  email: "Email",
  qr: "QR code",
};

export const SCAM_CATEGORIES: { value: string; label: string; example: string }[] = [
  { value: "momo", label: "Mobile money scam", example: "Fake reversal, 'sent by mistake', PIN requests" },
  { value: "bank", label: "Bank impersonation", example: "Fake account verification or security alert" },
  { value: "government", label: "Government impersonation", example: "Fake GRA, SSNIT, DVLA or NIA notice" },
  { value: "delivery", label: "Delivery scam", example: "Parcel held, pay a customs fee" },
  { value: "recruitment", label: "Job / recruitment scam", example: "Job offer that needs a registration fee" },
  { value: "investment", label: "Investment scam", example: "Guaranteed returns, double your money" },
  { value: "ecommerce", label: "Online shopping scam", example: "Fake shop, goods never delivered" },
  { value: "social_engineering", label: "OTP / PIN request", example: "Someone asks for your code or PIN" },
  { value: "impersonation", label: "Impersonation", example: "Fake profile of a person or business" },
  { value: "crypto", label: "Cryptocurrency scam", example: "Fake exchange, giveaway or wallet link" },
  { value: "university", label: "Admission / scholarship scam", example: "Pay an acceptance or processing fee" },
  { value: "romance", label: "Romance or emergency scam", example: "Someone you met online needs money" },
  { value: "prize", label: "Prize or lottery scam", example: "You won a promotion you never entered" },
  { value: "other", label: "Something else", example: "" },
];

export const categoryLabel = (c: string | null | undefined) =>
  SCAM_CATEGORIES.find((x) => x.value === c)?.label ?? c ?? "";

export const CHANNELS: { value: string; label: string }[] = [
  { value: "sms", label: "SMS / text message" },
  { value: "whatsapp", label: "WhatsApp" },
  { value: "email", label: "Email" },
  { value: "website", label: "Website" },
  { value: "social", label: "Social media" },
  { value: "phone_call", label: "Phone call" },
  { value: "other", label: "Other" },
];

export const REPORT_STATUS: Record<string, { label: string; tone: Tone }> = {
  unverified: { label: "Unverified", tone: "neutral" },
  under_review: { label: "Under review", tone: "info" },
  verified: { label: "Verified", tone: "critical" },
  rejected: { label: "Not confirmed", tone: "neutral" },
  duplicate: { label: "Duplicate", tone: "neutral" },
};

export const INDICATOR_STATUS: Record<string, { label: string; tone: Tone }> = {
  unverified: { label: "Unverified", tone: "warning" },
  verified: { label: "Verified", tone: "critical" },
  rejected: { label: "Rejected", tone: "neutral" },
  revoked: { label: "Revoked", tone: "neutral" },
  expired: { label: "Expired", tone: "neutral" },
};

export const CASE_STATUS: Record<string, { label: string; tone: Tone }> = {
  open: { label: "Open", tone: "warning" },
  investigating: { label: "Investigating", tone: "info" },
  closed: { label: "Closed", tone: "neutral" },
};

export const CASE_OUTCOMES = [
  { value: "true_positive", label: "Confirmed phishing / scam" },
  { value: "false_positive", label: "False alarm" },
  { value: "benign", label: "Legitimate" },
  { value: "inconclusive", label: "Inconclusive" },
];

export const SEVERITIES = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

export const WEBHOOK_EVENTS: { value: string; label: string }[] = [
  { value: "scan.completed", label: "Every completed scan" },
  { value: "scan.high_risk", label: "High or critical results" },
  { value: "case.created", label: "Case opened" },
  { value: "case.closed", label: "Case closed" },
  { value: "report.status_changed", label: "Scam report status changed" },
];

export const SECRET_LABELS: Record<string, string> = {
  one_time_code: "one-time code",
  password: "password",
  card_number: "card number",
};

// --- Audit -----------------------------------------------------------------------------------

export const AUDIT_ACTIONS: Record<string, string> = {
  "auth.login": "Signed in",
  "auth.login_failed": "Failed sign-in attempt",
  "auth.mfa_failed": "Failed MFA code",
  "auth.logout": "Signed out",
  "auth.refresh_reuse_detected": "Session ended: token reuse detected",
  "user.registered": "Account created",
  "user.seeded": "Administrator account created",
  "user.password_changed": "Password changed",
  "user.password_reset_requested": "Password reset requested",
  "user.password_reset": "Password reset",
  "user.mfa_enabled": "MFA turned on",
  "user.mfa_disabled": "MFA turned off",
  "user.data_exported": "Personal data exported",
  "user.account_deleted": "Account deleted",
  "organisation.created": "Organisation created",
  "organisation.updated": "Organisation settings changed",
  "member.invited": "Member invited",
  "member.invitation_revoked": "Invitation revoked",
  "member.joined": "Member joined",
  "member.updated": "Member updated",
  "member.removed": "Member removed",
  "department.created": "Department created",
  "department.deleted": "Department deleted",
  "case.created": "Case opened",
  "case.updated": "Case updated",
  "api_key.created": "API key created",
  "api_key.revoked": "API key revoked",
  "webhook.created": "Webhook added",
  "webhook.deleted": "Webhook removed",
  "brand.created": "Protected brand added",
  "billing.checkout_started": "Checkout started",
  "billing.payment_succeeded": "Payment received",
  "user.push_device_registered": "Phone registered for notifications",
  "user.push_device_removed": "Phone removed from notifications",
};

export const auditLabel = (a: string) => AUDIT_ACTIONS[a] ?? a;
