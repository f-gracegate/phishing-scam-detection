"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  Activity,
  Download,
  Flag,
  FolderSearch,
  KeyRound,
  ScanSearch,
  ShieldAlert,
  TriangleAlert,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { BarRow, NoAccess } from "@/components/business-ui";
import { useToast } from "@/components/providers";
import { ScanRow } from "@/components/scan-ui";
import { useOrgKey, useSession } from "@/components/session";
import { Button, Card, CardHeader, EmptyState, PageHeader, Select, Skeleton, StatCard } from "@/components/ui";
import { api, downloadFile, errorMessage } from "@/lib/api";
import { VERDICTS } from "@/lib/labels";
import type { Analytics, Page, Scan } from "@/lib/types";

const PERIODS = [
  { value: 7, label: "Last 7 days" },
  { value: 30, label: "Last 30 days" },
  { value: 90, label: "Last 90 days" },
];

const VERDICT_ORDER = ["critical", "high", "suspicious", "caution", "low", "unknown", "pending"];
const VERDICT_BAR: Record<string, string> = {
  critical: "bg-critical",
  high: "bg-critical",
  suspicious: "bg-high",
  caution: "bg-warning",
  low: "bg-success",
  unknown: "bg-border-strong",
  pending: "bg-border-strong",
};

const n = (v: number) => v.toLocaleString("en-GB");

/** One entry per day in the period, so quiet days show as gaps rather than disappearing. */
function fillDays(trend: Analytics["trend"], days: number) {
  const byDay = new Map(trend.map((t) => [t.day, t]));
  const out: Analytics["trend"] = [];
  const today = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i));
    const key = d.toISOString().slice(0, 10);
    out.push(byDay.get(key) ?? { day: key, scans: 0, high_risk: 0 });
  }
  return out;
}

function dayLabel(iso: string) {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-GB", {
    day: "numeric",
    month: "short",
    timeZone: "UTC",
  });
}

function TrendChart({ trend, days }: { trend: Analytics["trend"]; days: number }) {
  const series = useMemo(() => fillDays(trend, days), [trend, days]);
  const max = Math.max(1, ...series.map((s) => s.scans));
  const totalScans = series.reduce((a, s) => a + s.scans, 0);
  const totalHigh = series.reduce((a, s) => a + s.high_risk, 0);
  const labelEvery = days <= 7 ? 1 : days <= 30 ? 5 : 15;

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-4 text-xs text-muted">
        <span className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm bg-primary/25" aria-hidden /> Items analysed
        </span>
        <span className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm bg-critical" aria-hidden /> High risk
        </span>
        <span className="ml-auto tabular-nums">Peak {n(max)} a day</span>
      </div>
      <p className="sr-only">
        {n(totalScans)} items analysed and {n(totalHigh)} high-risk results over the last {days} days.
      </p>
      <div className="relative h-48 border-b border-border" aria-hidden>
        <div className="pointer-events-none absolute inset-x-0 top-0 border-t border-dashed border-border" />
        <div className="pointer-events-none absolute inset-x-0 top-1/2 border-t border-dashed border-border" />
        <div className={days > 30 ? "flex h-full items-end gap-px" : "flex h-full items-end gap-1"}>
          {series.map((s) => (
            <div
              key={s.day}
              className="group relative flex h-full flex-1 items-end"
              title={`${dayLabel(s.day)}: ${n(s.scans)} analysed, ${n(s.high_risk)} high risk`}
            >
              <div
                className="relative w-full rounded-t-sm bg-primary/25 transition-colors group-hover:bg-primary/40"
                style={{ height: `${(s.scans / max) * 100}%` }}
              >
                {s.high_risk > 0 && (
                  <div
                    className="absolute inset-x-0 bottom-0 rounded-t-sm bg-critical"
                    style={{ height: `${(s.high_risk / Math.max(1, s.scans)) * 100}%` }}
                  />
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className={`mt-1.5 flex text-[11px] text-subtle ${days > 30 ? "gap-px" : "gap-1"}`} aria-hidden>
        {series.map((s, i) => (
          <span key={s.day} className="w-0 flex-1 overflow-visible text-center whitespace-nowrap">
            {i % labelEvery === 0 || i === series.length - 1 ? dayLabel(s.day) : ""}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function BusinessDashboardPage() {
  const { can, membership } = useSession();
  const toast = useToast();
  const allowed = can("analytics:read");
  const [days, setDays] = useState(30);
  const [downloading, setDownloading] = useState(false);

  const analytics = useQuery({
    queryKey: useOrgKey("business", "analytics", days),
    queryFn: () => api<Analytics>("/business/analytics", { query: { days } }),
    placeholderData: keepPreviousData,
    enabled: allowed,
  });
  const recent = useQuery({
    queryKey: useOrgKey("scans", "recent-high-risk"),
    queryFn: () => api<Page<Scan>>("/scans", { query: { verdict: "high_risk", page_size: 8 } }),
    enabled: allowed,
  });

  if (!allowed) return <NoAccess what="security analytics" />;

  async function downloadReport() {
    setDownloading(true);
    try {
      await downloadFile("/business/report.pdf", "security-report.pdf");
    } catch (err) {
      toast("error", errorMessage(err));
    } finally {
      setDownloading(false);
    }
  }

  const a = analytics.data;
  const verdicts = a
    ? VERDICT_ORDER.filter((v) => a.by_verdict[v]).map((v) => ({
        key: v,
        label: v === "pending" ? "Still being checked" : (VERDICTS[v]?.label ?? v),
        count: a.by_verdict[v],
      }))
    : [];
  const verdictMax = Math.max(0, ...verdicts.map((v) => v.count));
  const catMax = Math.max(0, ...(a?.categories.map((c) => c.count) ?? []));
  const domMax = Math.max(0, ...(a?.suspicious_domains.map((d) => d.count) ?? []));

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security overview"
        description={`How phishing and scams are reaching ${membership?.organisation_name ?? "your workspace"}, and what your team has caught.`}
        actions={
          <>
            <Select
              aria-label="Period"
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              className="w-40"
            >
              {PERIODS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </Select>
            <Button variant="secondary" onClick={downloadReport} loading={downloading}>
              {!downloading && <Download className="size-4" aria-hidden />}
              Download monthly report (PDF)
            </Button>
          </>
        }
      />

      {analytics.isError && !a ? (
        <Card>
          <EmptyState title="We couldn't load your analytics" description={errorMessage(analytics.error)} />
        </Card>
      ) : !a ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <StatCard
            label="Items analysed"
            value={n(a.total_scans)}
            icon={<ScanSearch className="size-4" />}
            tone="primary"
            hint="Links, messages, emails and QR codes"
          />
          <StatCard
            label="High risk"
            value={n(a.high_risk)}
            icon={<ShieldAlert className="size-4" />}
            tone="critical"
            hint="High or critical results"
          />
          <StatCard
            label="Phishing detections"
            value={n(a.phishing_detections)}
            icon={<TriangleAlert className="size-4" />}
            tone="high"
            hint={`Includes ${n(a.suspicious)} suspicious`}
          />
          <StatCard
            label="Employee reports"
            value={n(a.employee_reports)}
            icon={<Flag className="size-4" />}
            tone="warning"
            hint="Scams reported by your team"
          />
          <StatCard
            label="Active investigations"
            value={n(a.active_investigations)}
            icon={<FolderSearch className="size-4" />}
            tone="info"
            hint={
              <Link href="/business/cases" className="text-primary-text hover:underline">
                View cases
              </Link>
            }
          />
          <StatCard
            label="API calls"
            value={n(a.api_calls)}
            icon={<KeyRound className="size-4" />}
            tone="neutral"
            hint="From your integrations"
          />
        </div>
      )}

      <Card>
        <CardHeader
          title="Activity"
          description="Items analysed each day, with high-risk results highlighted."
        />
        {a ? (
          a.total_scans === 0 ? (
            <EmptyState
              icon={<Activity className="size-5" />}
              title="Nothing analysed yet in this period"
              description="Results will appear here as your team checks links and messages."
            />
          ) : (
            <TrendChart trend={a.trend} days={a.days} />
          )
        ) : (
          <Skeleton className="h-56" />
        )}
      </Card>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card>
          <CardHeader title="Top scam types" description="Among suspicious and high-risk results." />
          {!a ? (
            <Skeleton className="h-40" />
          ) : a.categories.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted">No scam types detected in this period.</p>
          ) : (
            <ul className="space-y-3">
              {a.categories.map((c) => (
                <BarRow key={c.category} label={c.label} value={c.count} max={catMax} barClass="bg-high" />
              ))}
            </ul>
          )}
        </Card>
        <Card>
          <CardHeader title="Suspicious domains" description="Sender and link domains seen most often." />
          {!a ? (
            <Skeleton className="h-40" />
          ) : a.suspicious_domains.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted">No suspicious domains in this period.</p>
          ) : (
            <ul className="space-y-3">
              {a.suspicious_domains.map((d) => (
                <BarRow
                  key={d.domain}
                  label={d.domain}
                  value={d.count}
                  max={domMax}
                  barClass="bg-critical"
                  mono
                />
              ))}
            </ul>
          )}
        </Card>
        <Card>
          <CardHeader title="Results by verdict" description="Every item analysed in this period." />
          {!a ? (
            <Skeleton className="h-40" />
          ) : verdicts.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted">No results yet.</p>
          ) : (
            <ul className="space-y-3">
              {verdicts.map((v) => (
                <BarRow
                  key={v.key}
                  label={v.label}
                  value={v.count}
                  max={verdictMax}
                  barClass={VERDICT_BAR[v.key] ?? "bg-primary"}
                />
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card padded={false}>
        <div className="p-5 pb-3">
          <CardHeader
            title="Recent high-risk submissions"
            description="The latest high and critical results across your workspace."
            action={
              <Link href="/scans" className="text-sm font-medium text-primary-text hover:underline">
                All scans
              </Link>
            }
          />
        </div>
        {recent.isPending ? (
          <div className="space-y-2 px-5 pb-5">
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
          </div>
        ) : !recent.data?.items.length ? (
          <EmptyState
            icon={<ShieldAlert className="size-5" />}
            title="No high-risk submissions"
            description="Nice. Nothing high risk has been caught recently."
          />
        ) : (
          <div className="divide-y divide-border border-t border-border">
            {recent.data.items.map((s) => (
              <ScanRow key={s.id} scan={s} href={`/scans/${s.id}`} />
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
