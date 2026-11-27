"use client";

import { useQuery } from "@tanstack/react-query";
import {
  ChevronRight,
  Database,
  Inbox,
  Megaphone,
  ShieldCheck,
  ShieldQuestion,
  ThumbsDown,
} from "lucide-react";
import Link from "next/link";
import { INTEL_KEY, IntelGate } from "@/components/intel-ui";
import {
  Badge,
  Callout,
  Card,
  CardHeader,
  EmptyState,
  PageHeader,
  Skeleton,
  StatCard,
} from "@/components/ui";
import { api, errorMessage } from "@/lib/api";
import { VERDICTS } from "@/lib/labels";

type Overview = {
  indicators: Record<string, number>;
  report_queue: number;
  open_feedback: number;
  scans_today: Record<string, number>;
  report_categories: { category: string; label: string; count: number }[];
  active_campaigns: number;
};

const VERDICT_ORDER = ["critical", "high", "suspicious", "caution", "low", "unknown"];

const QUICK_LINKS = [
  { href: "/intel/queue", label: "Report queue", hint: "Triage community scam reports", icon: Inbox },
  { href: "/intel/indicators", label: "Indicators", hint: "Search, add and review indicators", icon: Database },
  { href: "/intel/feedback", label: "Disputed results", hint: "False positives and false negatives", icon: ThumbsDown },
  { href: "/intel/campaigns", label: "Campaigns", hint: "Group indicators and publish warnings", icon: Megaphone },
  { href: "/intel/sources", label: "Sources & brands", hint: "Feeds, licences, brand catalogue, staff", icon: ShieldCheck },
];

function Bars({ rows }: { rows: { key: string; label: string; count: number; tone?: string }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <ul className="space-y-2.5">
      {rows.map((r) => (
        <li key={r.key} className="grid grid-cols-[9rem_1fr_3rem] items-center gap-3 text-sm">
          <span className="truncate text-muted">{r.label}</span>
          <span className="h-2 overflow-hidden rounded-full bg-surface-2">
            <span
              className={`block h-full rounded-full ${r.tone ?? "bg-primary"}`}
              style={{ width: `${(r.count / max) * 100}%` }}
            />
          </span>
          <span className="text-right font-medium tabular-nums text-fg">{r.count}</span>
        </li>
      ))}
    </ul>
  );
}

const VERDICT_BAR: Record<string, string> = {
  critical: "bg-critical",
  high: "bg-critical",
  suspicious: "bg-high",
  caution: "bg-warning",
  low: "bg-success",
  unknown: "bg-border-strong",
};

function OverviewView() {
  const { data, isPending, error } = useQuery({
    queryKey: [INTEL_KEY, "overview"],
    queryFn: () => api<Overview>("/intelligence/overview", { org: false }),
    refetchInterval: 60_000,
  });

  const scanRows = data
    ? VERDICT_ORDER.filter((v) => (data.scans_today[v] ?? 0) > 0 || v !== "unknown").map((v) => ({
        key: v,
        label: VERDICTS[v]?.short ?? v,
        count: data.scans_today[v] ?? 0,
        tone: VERDICT_BAR[v],
      }))
    : [];
  const pendingScans = data?.scans_today["null"] ?? data?.scans_today[""] ?? 0;
  const scansTotal = data ? Object.values(data.scans_today).reduce((a, b) => a + b, 0) : 0;

  return (
    <>
      <PageHeader
        title="Threat intelligence"
        description="What needs attention across the platform. Verified indicators are used by every scan, so review carefully."
      />
      {error && <Callout tone="critical">{errorMessage(error)}</Callout>}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
        {isPending || !data ? (
          Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-28" />)
        ) : (
          <>
            <Link href="/intel/queue" className="rounded-[var(--radius-card)] focus-visible:ring-4 focus-visible:ring-[var(--ring)] focus-visible:outline-none">
              <StatCard label="Open report queue" value={data.report_queue} hint="Unverified or under review" icon={<Inbox className="size-4" />} tone="warning" />
            </Link>
            <Link href="/intel/feedback" className="rounded-[var(--radius-card)] focus-visible:ring-4 focus-visible:ring-[var(--ring)] focus-visible:outline-none">
              <StatCard label="Open disputed results" value={data.open_feedback} hint="False positive or negative" icon={<ThumbsDown className="size-4" />} tone="high" />
            </Link>
            <Link href="/intel/indicators?status=verified" className="rounded-[var(--radius-card)] focus-visible:ring-4 focus-visible:ring-[var(--ring)] focus-visible:outline-none">
              <StatCard label="Verified indicators" value={data.indicators.verified ?? 0} hint="Published to every scan" icon={<ShieldCheck className="size-4" />} tone="critical" />
            </Link>
            <Link href="/intel/indicators?status=unverified" className="rounded-[var(--radius-card)] focus-visible:ring-4 focus-visible:ring-[var(--ring)] focus-visible:outline-none">
              <StatCard label="Unverified indicators" value={data.indicators.unverified ?? 0} hint="Awaiting analyst review" icon={<ShieldQuestion className="size-4" />} tone="info" />
            </Link>
            <Link href="/intel/campaigns" className="rounded-[var(--radius-card)] focus-visible:ring-4 focus-visible:ring-[var(--ring)] focus-visible:outline-none">
              <StatCard label="Active campaigns" value={data.active_campaigns} icon={<Megaphone className="size-4" />} tone="primary" />
            </Link>
          </>
        )}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="Scans today by verdict"
            description={data ? `${scansTotal} scans since midnight (UTC)` : "Since midnight (UTC)"}
          />
          {isPending ? (
            <Skeleton className="h-40" />
          ) : scansTotal === 0 ? (
            <EmptyState title="No scans yet today" />
          ) : (
            <>
              <Bars rows={scanRows} />
              {pendingScans > 0 && (
                <p className="mt-3 text-xs text-subtle">{pendingScans} still running or failed without a verdict.</p>
              )}
            </>
          )}
        </Card>
        <Card>
          <CardHeader title="Top report categories" description="All community reports, by scam type" />
          {isPending ? (
            <Skeleton className="h-40" />
          ) : !data?.report_categories.length ? (
            <EmptyState title="No reports yet" />
          ) : (
            <Bars
              rows={data.report_categories.map((c) => ({ key: c.category, label: c.label, count: c.count }))}
            />
          )}
        </Card>
      </div>

      {data && (
        <Card className="mt-4">
          <CardHeader title="Indicators by status" />
          <div className="flex flex-wrap gap-2">
            {Object.entries(data.indicators).length === 0 ? (
              <p className="text-sm text-muted">No indicators yet.</p>
            ) : (
              Object.entries(data.indicators).map(([status, n]) => (
                <Link key={status} href={`/intel/indicators?status=${status}`}>
                  <Badge tone="neutral" className="px-2.5 py-1 hover:bg-surface">
                    <span className="capitalize">{status}</span>
                    <span className="font-semibold text-fg tabular-nums">{n}</span>
                  </Badge>
                </Link>
              ))
            )}
          </div>
        </Card>
      )}

      <h2 className="mt-8 mb-3 text-[15px] font-semibold text-fg">Quick links</h2>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {QUICK_LINKS.map(({ href, label, hint, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className="group flex items-center gap-3 rounded-[var(--radius-card)] border border-border bg-surface p-4 shadow-[var(--shadow-card)] hover:border-border-strong"
          >
            <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary-soft text-primary-text">
              <Icon className="size-4" />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-medium text-fg">{label}</span>
              <span className="block truncate text-xs text-muted">{hint}</span>
            </span>
            <ChevronRight className="size-4 text-subtle group-hover:text-fg" />
          </Link>
        ))}
      </div>
    </>
  );
}

export default function IntelOverviewPage() {
  return (
    <IntelGate>
      <OverviewView />
    </IntelGate>
  );
}
