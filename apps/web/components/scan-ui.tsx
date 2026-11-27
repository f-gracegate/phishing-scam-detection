"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertOctagon,
  ArrowRight,
  CheckCircle2,
  ExternalLink,
  Flag,
  HelpCircle,
  Info,
  Link2,
  Mail,
  MessageSquare,
  QrCode,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ThumbsDown,
  ThumbsUp,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { useToast } from "@/components/providers";
import { useOrgKey } from "@/components/session";
import { Badge, Button, ButtonLink, Card, CardHeader, Skeleton, Spinner, cn } from "@/components/ui";
import { api, errorMessage } from "@/lib/api";
import { formatDateTime, timeAgo } from "@/lib/format";
import {
  CONFIDENCE,
  SCAN_KINDS,
  SECRET_LABELS,
  SEVERITY_TONE,
  SOURCE_TONE,
  VERDICTS,
  verdictTone,
} from "@/lib/labels";
import type { Evidence, LinkDetail, Scan, ScanDetail, Verdict } from "@/lib/types";

// --- Verdict visuals ---------------------------------------------------------------------------

const RING: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--critical)",
  suspicious: "var(--high)",
  caution: "var(--warning)",
  low: "var(--success)",
  unknown: "var(--text-subtle)",
};

export function VerdictIcon({ verdict, className }: { verdict: string | null; className?: string }) {
  if (verdict === "critical" || verdict === "high") return <AlertOctagon className={className} aria-hidden />;
  if (verdict === "suspicious" || verdict === "caution") return <ShieldAlert className={className} aria-hidden />;
  if (verdict === "low") return <ShieldCheck className={className} aria-hidden />;
  return <HelpCircle className={className} aria-hidden />;
}

export function VerdictBadge({ verdict, score }: { verdict: string | null; score?: number | null }) {
  if (!verdict) return <Badge>Checking…</Badge>;
  return (
    <Badge tone={verdictTone(verdict)} dot>
      {VERDICTS[verdict]?.short ?? verdict}
      {score != null && verdict !== "unknown" && <span className="tabular-nums opacity-80"> · {score}</span>}
    </Badge>
  );
}

export function KindIcon({ kind, className }: { kind: string; className?: string }) {
  const Icon = kind === "email" ? Mail : kind === "message" ? MessageSquare : kind === "qr" ? QrCode : Link2;
  return <Icon className={className} aria-hidden />;
}

function ScoreRing({ score, verdict }: { score: number; verdict: Verdict }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const shown = verdict === "unknown" ? 0 : score;
  return (
    <div className="relative size-36 shrink-0">
      <svg viewBox="0 0 120 120" className="size-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="var(--surface-3)" strokeWidth="10" />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          stroke={RING[verdict]}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${(shown / 100) * c} ${c}`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {verdict === "unknown" ? (
          <HelpCircle className="size-10 text-subtle" aria-hidden />
        ) : (
          <>
            <span className="font-heading text-4xl font-bold tabular-nums text-fg">{score}</span>
            <span className="text-xs text-subtle">/ 100</span>
          </>
        )}
      </div>
    </div>
  );
}

// --- Polling ---------------------------------------------------------------------------------

export function useScan(id: string) {
  const key = useOrgKey("scan", id);
  return useQuery({
    queryKey: key,
    queryFn: () => api<ScanDetail>(`/scans/${id}`),
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s === "queued" || s === "running" ? 1200 : false;
    },
  });
}

// --- Result ------------------------------------------------------------------------------------

function groupEvidence(evidence: Evidence[]) {
  const risky = evidence.filter((e) => e.weight > 0);
  const positive = evidence.filter((e) => e.layer === "positive");
  const context = evidence.filter((e) => e.weight <= 0 && e.layer !== "positive");
  return { risky, positive, context };
}

function EvidenceItem({ e }: { e: Evidence }) {
  return (
    <li className="flex gap-3 py-3">
      <span
        className={cn(
          "mt-1 size-2.5 shrink-0 rounded-full",
          e.severity === "critical" || e.severity === "high"
            ? "bg-critical"
            : e.severity === "medium"
              ? "bg-high"
              : e.severity === "low"
                ? "bg-warning"
                : "bg-border-strong",
        )}
        aria-hidden
      />
      <div className="min-w-0 flex-1">
        <p className="font-medium text-fg">{e.title}</p>
        <p className="mt-0.5 text-sm text-muted">{e.description}</p>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-xs text-subtle">
          <Badge tone={SOURCE_TONE[e.source_kind] ?? "neutral"}>{e.source_label}</Badge>
          {e.weight > 0 && <Badge tone={SEVERITY_TONE[e.severity] ?? "neutral"}>{e.severity}</Badge>}
          <span>Reliability: {e.reliability}</span>
          <span aria-hidden>·</span>
          <span>{formatDateTime(e.observed_at)}</span>
        </div>
      </div>
    </li>
  );
}

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[9rem_minmax(0,1fr)] gap-3 py-2 text-sm">
      <dt className="text-subtle">{label}</dt>
      <dd className="min-w-0 break-words text-fg">{children}</dd>
    </div>
  );
}

function LinkDetails({ link }: { link: LinkDetail }) {
  const web = link.website;
  return (
    <dl className="divide-y divide-border">
      {link.url && <Detail label="Checked link"><code className="break-all">{link.url}</code></Detail>}
      {link.domain && <Detail label="Domain">{link.display_host ?? link.domain} ({link.domain})</Detail>}
      {link.registration?.registered_at && (
        <Detail label="Registered">
          {formatDateTime(link.registration.registered_at)} · {link.registration.age_days} days ago
          {link.registration.registrar ? ` · ${link.registration.registrar}` : ""}
        </Detail>
      )}
      {web && (
        <>
          <Detail label="Website">
            {web.reachable ? (
              <>
                Loaded{web.status ? ` (HTTP ${web.status})` : ""}
                {web.title ? <> · “{web.title}”</> : null}
              </>
            ) : (
              <>Couldn&apos;t load: {web.error ?? "no response"}</>
            )}
          </Detail>
          {web.redirects && web.redirects.length > 1 && (
            <Detail label="Redirect chain">
              <ol className="space-y-1">
                {web.redirects.map((r, i) => (
                  <li key={i} className="flex items-start gap-1.5">
                    <span className="tabular-nums text-subtle">{i + 1}.</span>
                    <code className="break-all">{r.url}</code>
                    <span className="text-subtle">({r.status})</span>
                  </li>
                ))}
              </ol>
            </Detail>
          )}
          {web.final_url && web.final_url !== link.url && (
            <Detail label="Ends up at"><code className="break-all">{web.final_url}</code></Detail>
          )}
          {web.reachable && (
            <Detail label="Forms">
              {web.forms ?? 0} form(s), {web.password_fields ?? 0} password field(s)
              {web.sensitive_fields?.length ? ` · asks for ${web.sensitive_fields.join(", ")}` : ""}
            </Detail>
          )}
          {web.tls && (
            <Detail label="Certificate (TLS)">
              {web.tls.trusted ? "Trusted" : `Not trusted — ${web.tls.error ?? "browsers warn"}`}
              {web.tls.issuer ? ` · issued by ${web.tls.issuer}` : ""}
              {web.tls.age_days != null ? ` · ${web.tls.age_days} days old` : ""}
            </Detail>
          )}
        </>
      )}
      {link.intelligence && link.intelligence.length > 0 && (
        <Detail label="Reputation checks">
          <ul className="space-y-0.5">
            {link.intelligence.map((i) => (
              <li key={i.provider}>
                {i.provider}:{" "}
                <span className={i.status === "match" ? "font-medium text-critical-text" : "text-muted"}>
                  {i.status === "match" ? "listed as a threat" : i.status === "no_match" ? "no match" : "unavailable"}
                </span>
              </li>
            ))}
          </ul>
        </Detail>
      )}
    </dl>
  );
}

function FeedbackBar({ scan }: { scan: ScanDetail }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const key = useOrgKey("scan", scan.id);
  const [comment, setComment] = useState("");
  const [open, setOpen] = useState<null | "false_positive" | "false_negative">(null);
  const send = useMutation({
    mutationFn: (kind: string) =>
      api<{ message: string }>(`/scans/${scan.id}/feedback`, { method: "POST", body: { kind, comment: comment || null } }),
    onSuccess: (r) => {
      toast("success", r.message);
      setOpen(null);
      queryClient.invalidateQueries({ queryKey: key });
    },
    onError: (e) => toast("error", errorMessage(e)),
  });
  if (scan.feedback) {
    return <p className="text-sm text-muted">Thanks for your feedback on this result.</p>;
  }
  const risky = ["high", "critical", "suspicious"].includes(scan.verdict ?? "");
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="text-muted">Is this result right?</span>
        <Button size="sm" variant="secondary" onClick={() => send.mutate("correct")} loading={send.isPending}>
          <ThumbsUp className="size-4" /> Yes
        </Button>
        <Button
          size="sm"
          variant="secondary"
          onClick={() => setOpen(risky ? "false_positive" : "false_negative")}
        >
          <ThumbsDown className="size-4" /> {risky ? "No, it's genuine" : "No, it's a scam"}
        </Button>
      </div>
      {open && (
        <div className="space-y-2 rounded-lg border border-border bg-surface-2 p-3">
          <label htmlFor="fb" className="text-sm font-medium">
            Tell us why (optional) — an analyst will review it
          </label>
          <textarea
            id="fb"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            rows={2}
            maxLength={2000}
            className="w-full rounded-lg border border-border bg-surface p-2 text-sm"
          />
          <div className="flex gap-2">
            <Button size="sm" onClick={() => send.mutate(open)} loading={send.isPending}>
              Send
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setOpen(null)}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

export function ScanResult({ scan, backHref = "/scans" }: { scan: ScanDetail; backHref?: string }) {
  const router = useRouter();
  const toast = useToast();
  const rescan = useMutation({
    mutationFn: () => api<ScanDetail>(`/scans/${scan.id}/rescan`, { method: "POST" }),
    onSuccess: (s) => router.push(`${backHref}/${s.id}`),
    onError: (e) => toast("error", errorMessage(e)),
  });

  if (scan.status === "queued" || scan.status === "running") {
    return (
      <Card className="flex flex-col items-center gap-4 py-16 text-center">
        <Spinner className="size-8" />
        <div>
          <p className="font-heading text-lg font-semibold">Checking {SCAN_KINDS[scan.kind]?.toLowerCase()}…</p>
          <p className="mt-1 text-sm text-muted">
            We&apos;re checking reputation, the address and {scan.kind === "url" ? "the website itself" : "common scam signs"}. This usually takes a few seconds.
          </p>
        </div>
        <p className="max-w-lg truncate text-sm text-subtle">{scan.title}</p>
      </Card>
    );
  }
  if (scan.status === "failed") {
    return (
      <Card className="py-10 text-center">
        <p className="font-medium">We couldn&apos;t finish this check.</p>
        <p className="mt-1 text-sm text-muted">{scan.error}</p>
      </Card>
    );
  }

  const verdict = (scan.verdict ?? "unknown") as Verdict;
  const tone = verdictTone(verdict);
  const { risky, positive, context } = groupEvidence(scan.evidence);
  const link = scan.artifacts.link;
  const ex = scan.artifacts.extracted;
  const email = scan.artifacts.email;

  return (
    <div className="space-y-6">
      {/* 1. Risk first */}
      <Card
        className={cn(
          "border-l-4",
          tone === "critical" && "border-l-critical",
          tone === "high" && "border-l-high",
          tone === "warning" && "border-l-warning",
          tone === "success" && "border-l-success",
          tone === "neutral" && "border-l-border-strong",
        )}
      >
        <div className="flex flex-col gap-6 sm:flex-row sm:items-center">
          <ScoreRing score={scan.risk_score ?? 0} verdict={verdict} />
          <div className="min-w-0 flex-1 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={tone} dot>
                {VERDICTS[verdict]?.label}
              </Badge>
              {scan.confidence && <Badge>{CONFIDENCE[scan.confidence]}</Badge>}
              {scan.category_label && <Badge tone="primary">{scan.category_label}</Badge>}
            </div>
            <h2 className="font-heading text-2xl font-bold text-fg">{scan.headline}</h2>
            <p className="text-muted">{scan.summary}</p>
            <p className="flex items-center gap-1.5 truncate text-sm text-subtle">
              <KindIcon kind={scan.kind} className="size-4 shrink-0" />
              <span className="truncate">{scan.title}</span>
            </p>
          </div>
        </div>
        <p className="mt-4 flex items-start gap-2 rounded-lg bg-surface-2 p-3 text-xs text-muted">
          <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          The score is our assessment of the evidence available now, not a guarantee. “Unknown” means we found no warning signs, not that it is safe.
        </p>
      </Card>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="space-y-6">
          {/* 2. Evidence second */}
          <Card>
            <CardHeader
              title={risky.length ? "Why we flagged it" : "What we checked"}
              description="Each reason shows where it came from. Our own rules are never presented as a confirmed threat-intelligence match."
            />
            {risky.length === 0 && positive.length === 0 && (
              <p className="text-sm text-muted">No warning signs were found in the information available.</p>
            )}
            {risky.length > 0 && (
              <ul className="divide-y divide-border">
                {risky.map((e, i) => (
                  <EvidenceItem key={i} e={e} />
                ))}
              </ul>
            )}
            {positive.length > 0 && (
              <ul className="mt-2 divide-y divide-border">
                {positive.map((e, i) => (
                  <li key={i} className="flex gap-3 py-3">
                    <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-success" aria-hidden />
                    <div>
                      <p className="font-medium">{e.title}</p>
                      <p className="text-sm text-muted">{e.description}</p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            {context.length > 0 && (
              <details className="mt-3 rounded-lg border border-border px-3 py-2">
                <summary className="cursor-pointer text-sm font-medium text-muted">
                  Other observations ({context.length})
                </summary>
                <ul className="divide-y divide-border">
                  {context.map((e, i) => (
                    <EvidenceItem key={i} e={e} />
                  ))}
                </ul>
              </details>
            )}
          </Card>

          {link && (
            <Card>
              <CardHeader title="Link and website details" />
              <LinkDetails link={link} />
            </Card>
          )}

          {email && (
            <Card>
              <CardHeader title="Email details" description={email.headers_provided ? undefined : "Only the message body was provided. Paste the full original email to check the sender's authentication."} />
              <dl className="divide-y divide-border">
                {email.from && <Detail label="From">{email.from}</Detail>}
                {email.reply_to && <Detail label="Reply-to">{email.reply_to}</Detail>}
                {email.return_path && <Detail label="Return path">{email.return_path}</Detail>}
                {email.subject && <Detail label="Subject">{email.subject}</Detail>}
                {Object.keys(email.authentication).length > 0 && (
                  <Detail label="Authentication">
                    {Object.entries(email.authentication).map(([k, v]) => (
                      <Badge key={k} tone={v === "pass" ? "success" : v === "fail" ? "critical" : "neutral"} className="mr-1">
                        {k.toUpperCase()} {v}
                      </Badge>
                    ))}
                    <p className="mt-1 text-xs text-subtle">Passing only proves which domain sent it — not that the sender is honest.</p>
                  </Detail>
                )}
                {email.attachments.length > 0 && (
                  <Detail label="Attachments">
                    {email.attachments.map((a) => (
                      <div key={a.filename}>
                        {a.filename} <span className="text-subtle">({a.content_type}, {a.size.toLocaleString()} bytes)</span>
                      </div>
                    ))}
                    <p className="mt-1 text-xs text-subtle">Attachments are never opened.</p>
                  </Detail>
                )}
              </dl>
            </Card>
          )}

          {ex && (ex.links.length > 0 || ex.phones.length > 0 || ex.dial_codes.length > 0 || ex.removed_secrets.length > 0) && (
            <Card>
              <CardHeader title="What we found inside" />
              <dl className="divide-y divide-border">
                {ex.links.length > 0 && (
                  <Detail label="Links">
                    {ex.links.map((l, i) => (
                      <div key={i}>
                        <code className="break-all">{l.url ?? l.error}</code>
                      </div>
                    ))}
                  </Detail>
                )}
                {ex.phones.length > 0 && <Detail label="Phone numbers">{ex.phones.join(", ")}</Detail>}
                {ex.dial_codes.length > 0 && <Detail label="Dial codes">{ex.dial_codes.join(", ")}</Detail>}
                {ex.amounts.length > 0 && <Detail label="Amounts">{ex.amounts.join(", ")}</Detail>}
                {ex.brands_mentioned.length > 0 && <Detail label="Mentions">{ex.brands_mentioned.join(", ")}</Detail>}
                {ex.removed_secrets.length > 0 && (
                  <Detail label="Removed for your safety">
                    We removed a {ex.removed_secrets.map((s) => SECRET_LABELS[s] ?? s).join(", ")} before saving anything.
                  </Detail>
                )}
              </dl>
            </Card>
          )}
        </div>

        {/* 3. Next action third */}
        <div className="space-y-6">
          <Card>
            <CardHeader title="What to do next" />
            <ol className="space-y-3">
              {scan.recommendations.map((r, i) => (
                <li key={i} className="flex gap-3 text-sm">
                  <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary-soft text-xs font-semibold text-primary-text">
                    {i + 1}
                  </span>
                  <span className="pt-0.5">{r}</span>
                </li>
              ))}
            </ol>
            <div className="mt-5 flex flex-wrap gap-2">
              <ButtonLink href={`/report?scan=${scan.id}`} variant={["high", "critical", "suspicious"].includes(verdict) ? "primary" : "secondary"}>
                <Flag className="size-4" /> Report this scam
              </ButtonLink>
              {(scan.kind === "url" || (scan.kind === "qr" && link)) && (
                <Button variant="secondary" onClick={() => rescan.mutate()} loading={rescan.isPending}>
                  <RefreshCw className="size-4" /> Check again
                </Button>
              )}
            </div>
          </Card>
          <Card>
            <FeedbackBar scan={scan} />
          </Card>
          <p className="text-xs text-subtle">
            Checked {formatDateTime(scan.completed_at)}
            {scan.submitted_by ? ` · submitted by ${scan.submitted_by}` : ""}.{" "}
            {scan.content_available ? "The submitted content is kept encrypted for a limited time." : ""}
          </p>
        </div>
      </div>
    </div>
  );
}

export function ScanResultSkeleton() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-48" />
      <Skeleton className="h-72" />
    </div>
  );
}

// --- Lists -------------------------------------------------------------------------------------

export function ScanRow({ scan, href }: { scan: Scan; href: string }) {
  return (
    <Link href={href} className="flex items-center gap-3 px-4 py-3 hover:bg-surface-2">
      <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted">
        <KindIcon kind={scan.kind} className="size-4" />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium text-fg">{scan.title}</span>
        <span className="block truncate text-xs text-subtle">
          {SCAN_KINDS[scan.kind]} · {timeAgo(scan.created_at)}
          {scan.submitted_by ? ` · ${scan.submitted_by}` : ""}
        </span>
      </span>
      <VerdictBadge verdict={scan.status === "completed" ? scan.verdict : null} score={scan.risk_score} />
      <ArrowRight className="hidden size-4 text-subtle sm:block" aria-hidden />
    </Link>
  );
}

export function ExternalNote() {
  return (
    <p className="flex items-center gap-1 text-xs text-subtle">
      <ExternalLink className="size-3" aria-hidden /> We never open links in your browser while checking them.
    </p>
  );
}
