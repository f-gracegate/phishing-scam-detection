"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Flag, Mail, Megaphone, MessageSquareWarning, QrCode, ShieldCheck } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { LinkCheckForm } from "@/components/check-forms";
import { ScanRow } from "@/components/scan-ui";
import { useOrgKey, useSession } from "@/components/session";
import { Badge, Card, CardHeader, Skeleton } from "@/components/ui";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/format";
import type { Page, Quota, Scan, Warning } from "@/lib/types";

function Action({ href, icon, title, text }: { href: string; icon: ReactNode; title: string; text: string }) {
  return (
    <Link
      href={href}
      className="group flex items-start gap-3 rounded-xl border border-border bg-surface p-4 shadow-[var(--shadow)] transition-colors hover:border-primary/40 hover:bg-primary-soft/30"
    >
      <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary-soft text-primary-text">{icon}</span>
      <span className="min-w-0">
        <span className="flex items-center gap-1 font-medium text-fg">
          {title}
          <ArrowRight className="size-3.5 opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
        </span>
        <span className="block text-sm text-muted">{text}</span>
      </span>
    </Link>
  );
}

const TIPS = [
  "No bank, MoMo agent or company will ever ask for your PIN or one-time code.",
  "You never need to enter your PIN to receive money.",
  "Money \"sent by mistake\"? Check your real balance in your MoMo menu before doing anything.",
  "Government agencies don't collect fines or fees through SMS links.",
  "If a job, loan or prize needs a fee first, it's almost certainly a scam.",
];

export default function HomePage() {
  const { me, orgId, membership } = useSession();
  const recentKey = useOrgKey("scans", "recent");
  const recent = useQuery({
    queryKey: recentKey,
    queryFn: () => api<Page<Scan>>("/scans", { query: { page_size: 5, mine: true } }),
  });
  const quota = useQuery({ queryKey: useOrgKey("quota"), queryFn: () => api<Quota>("/scans/quota") });
  const warnings = useQuery({
    queryKey: ["warnings"],
    queryFn: () => api<Warning[]>("/public/warnings", { org: false }),
    staleTime: 5 * 60_000,
  });
  const firstName = (me.user.full_name || "").split(" ")[0];

  return (
    <div className="space-y-8">
      <section className="overflow-hidden rounded-2xl bg-navy p-6 text-white shadow-lg sm:p-8 dark:bg-surface dark:ring-1 dark:ring-border">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="flex items-center gap-2 text-sm text-slate-300">
            <ShieldCheck className="size-4 text-green-400" aria-hidden />
            {orgId ? `${membership?.organisation_name} workspace` : "Personal protection"}
          </p>
          {quota.data && quota.data.limit != null && (
            <p className="text-xs text-slate-400">
              {Math.max(0, quota.data.limit - quota.data.used)} of {quota.data.limit.toLocaleString()} checks left{" "}
              {quota.data.period === "day" ? "today" : "this month"}
            </p>
          )}
        </div>
        <h1 className="mt-3 font-heading text-2xl font-bold sm:text-3xl">
          {firstName ? `Hi ${firstName}, ` : ""}got a suspicious link?
        </h1>
        <p className="mt-1 mb-6 max-w-2xl text-slate-300">
          Check it before you click. We&apos;ll show the risk, the evidence and what to do next.
        </p>
        <div className="rounded-xl bg-white p-4 text-fg dark:bg-surface-2">
          <LinkCheckForm large />
        </div>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Action href="/check/message" icon={<MessageSquareWarning className="size-5" />} title="Check a message" text="SMS, WhatsApp or social media" />
        <Action href="/check/email" icon={<Mail className="size-5" />} title="Check an email" text="Sender, links and attachments" />
        <Action href="/check/qr" icon={<QrCode className="size-5" />} title="Scan a QR code" text="See where it really leads" />
        <Action href="/report" icon={<Flag className="size-5" />} title="Report a scam" text="Help us warn others" />
      </section>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_24rem]">
        <Card padded={false}>
          <div className="p-5 pb-0">
            <CardHeader
              title="Your recent checks"
              action={
                <Link href="/scans" className="text-sm font-medium text-primary-text">
                  View all
                </Link>
              }
            />
          </div>
          {recent.isPending ? (
            <div className="space-y-2 p-5">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-12" />
              ))}
            </div>
          ) : recent.data && recent.data.items.length > 0 ? (
            <div className="divide-y divide-border border-t border-border">
              {recent.data.items.map((s) => (
                <ScanRow key={s.id} scan={s} href={`/scans/${s.id}`} />
              ))}
            </div>
          ) : (
            <p className="p-5 pt-0 text-sm text-muted">Nothing yet. Paste a link above to run your first check.</p>
          )}
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader title="Current scam warnings" description="Verified by our analysts." />
            {warnings.isPending ? (
              <Skeleton className="h-24" />
            ) : warnings.data && warnings.data.length > 0 ? (
              <ul className="space-y-4">
                {warnings.data.slice(0, 4).map((w) => (
                  <li key={w.id} className="flex gap-3">
                    <Megaphone className="mt-0.5 size-4 shrink-0 text-high" aria-hidden />
                    <div>
                      <p className="text-sm font-medium">{w.title}</p>
                      <p className="text-sm text-muted">{w.summary}</p>
                      <p className="mt-1 flex items-center gap-2 text-xs text-subtle">
                        <Badge>{w.category_label}</Badge> {formatDate(w.published_at)}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">No active warnings right now.</p>
            )}
          </Card>
          <Card>
            <CardHeader title="Stay safe" />
            <ul className="space-y-2.5 text-sm text-muted">
              {TIPS.map((t) => (
                <li key={t} className="flex gap-2">
                  <ShieldCheck className="mt-0.5 size-4 shrink-0 text-success" aria-hidden />
                  {t}
                </li>
              ))}
            </ul>
            <Link href="/safety" className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-primary-text">
              Safety centre <ArrowRight className="size-3.5" />
            </Link>
          </Card>
        </div>
      </div>
    </div>
  );
}
