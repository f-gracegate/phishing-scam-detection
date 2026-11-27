"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { useSession } from "@/components/session";
import { Badge, Card, EmptyState, cn } from "@/components/ui";
import { api } from "@/lib/api";
import { CONFIDENCE, INDICATOR_STATUS, REPORT_STATUS, type Tone } from "@/lib/labels";
import type { Campaign, Confidence } from "@/lib/types";

// Shared building blocks for the threat-intelligence analyst console (/intel).

export const INTEL_KEY = "intel";

export const INDICATOR_TYPES: { value: string; label: string; placeholder: string }[] = [
  { value: "url", label: "Link (URL)", placeholder: "https://example.test/login" },
  { value: "domain", label: "Domain", placeholder: "example.test" },
  { value: "phone", label: "Phone number", placeholder: "024 000 0000" },
  { value: "email", label: "Email address", placeholder: "support@example.test" },
  { value: "sender_id", label: "SMS sender ID", placeholder: "MOMO-ALERT" },
  { value: "ip", label: "IP address", placeholder: "203.0.113.10" },
  { value: "wallet", label: "Crypto wallet", placeholder: "bc1q…" },
];

export const indicatorTypeLabel = (t: string) =>
  INDICATOR_TYPES.find((x) => x.value === t)?.label ?? t;

export const CONFIDENCE_OPTIONS: { value: Confidence; label: string }[] = [
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

export const DISPOSITIONS: Record<string, { label: string; tone: Tone }> = {
  malicious: { label: "Malicious", tone: "critical" },
  suspicious: { label: "Suspicious", tone: "high" },
};

export const CAMPAIGN_STATUS: Record<string, { label: string; tone: Tone }> = {
  active: { label: "Active", tone: "critical" },
  dormant: { label: "Dormant", tone: "warning" },
  closed: { label: "Closed", tone: "neutral" },
};

export const REVIEW_DECISIONS: Record<string, string> = {
  start_review: "Started review",
  verify: "Verified",
  reject: "Rejected",
  duplicate: "Marked as duplicate",
  request_info: "Requested more information",
  revoke: "Revoked",
  downgrade: "Downgraded",
  reactivate: "Reactivated",
};

/** Split a textarea into trimmed, non-empty lines (or comma-separated values). */
export function splitList(text: string, commas = false): string[] {
  return text
    .split(commas ? /[\n,]/ : /\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function IndicatorStatusBadge({ status }: { status: string }) {
  const s = INDICATOR_STATUS[status];
  return (
    <Badge tone={s?.tone ?? "neutral"} dot>
      {s?.label ?? status}
    </Badge>
  );
}

export function ReportStatusBadge({ status }: { status: string }) {
  const s = REPORT_STATUS[status];
  return <Badge tone={s?.tone ?? "neutral"}>{s?.label ?? status.replace(/_/g, " ")}</Badge>;
}

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  const tone: Tone = confidence === "high" ? "primary" : confidence === "medium" ? "info" : "neutral";
  return <Badge tone={tone}>{CONFIDENCE[confidence] ?? confidence}</Badge>;
}

export function DispositionBadge({ disposition }: { disposition: string }) {
  const d = DISPOSITIONS[disposition];
  return <Badge tone={d?.tone ?? "neutral"}>{d?.label ?? disposition}</Badge>;
}

/** Gate a console page on an intelligence permission. */
export function IntelGate({ perm = "intel:read", children }: { perm?: string; children: ReactNode }) {
  const { intel } = useSession();
  if (intel(perm)) return <>{children}</>;
  const staff = intel("intel:read");
  return (
    <Card>
      <EmptyState
        icon={<ShieldAlert className="size-5" />}
        title={staff ? "You don't have access to this part of the console" : "Threat-intelligence staff only"}
        description={
          staff
            ? "Your intelligence role doesn't include this. Ask a platform administrator if you need it."
            : "The analyst console is for GraceGate threat-intelligence staff. If you think you should have access, contact a platform administrator."
        }
      />
    </Card>
  );
}

export function BackLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link
      href={href}
      className="mb-3 inline-flex items-center gap-1.5 text-sm text-muted hover:text-fg"
    >
      <ArrowLeft className="size-4" />
      {children}
    </Link>
  );
}

/** Compact definition list for detail pages. */
export function Facts({ items, className }: { items: [string, ReactNode][]; className?: string }) {
  return (
    <dl className={cn("grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2", className)}>
      {items.map(([label, value]) => (
        <div key={label} className="min-w-0">
          <dt className="text-xs font-medium tracking-wide text-subtle uppercase">{label}</dt>
          <dd className="mt-0.5 break-words text-fg">{value ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function useCampaigns(enabled = true) {
  return useQuery({
    queryKey: [INTEL_KEY, "campaigns"],
    queryFn: () => api<Campaign[]>("/intelligence/campaigns", { org: false }),
    enabled,
    staleTime: 30_000,
  });
}
