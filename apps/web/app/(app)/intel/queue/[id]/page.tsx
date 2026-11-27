"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CircleCheck,
  Copy,
  Eye,
  HelpCircle,
  History,
  Link2,
  Play,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import Link from "next/link";
import { use, useState, type FormEvent } from "react";
import { Dialog } from "@/components/dialog";
import {
  BackLink,
  CONFIDENCE_OPTIONS,
  ConfidenceBadge,
  Facts,
  INTEL_KEY,
  IndicatorStatusBadge,
  IntelGate,
  REVIEW_DECISIONS,
  ReportStatusBadge,
  indicatorTypeLabel,
  useCampaigns,
} from "@/components/intel-ui";
import { useToast } from "@/components/providers";
import { useSession } from "@/components/session";
import {
  Badge,
  Button,
  Callout,
  Card,
  CardHeader,
  EmptyState,
  Field,
  Input,
  PageHeader,
  Select,
  Skeleton,
  Textarea,
} from "@/components/ui";
import { api, errorMessage } from "@/lib/api";
import { formatDate, formatDateTime, timeAgo } from "@/lib/format";
import { CHANNELS } from "@/lib/labels";
import type { Confidence, Indicator, QueueReport } from "@/lib/types";

type ReportDetail = {
  report: QueueReport & {
    message: string | null;
    occurred_on: string | null;
    public_note: string | null;
    full_phone: string | null;
    contact_email: string | null;
    duplicate_of: string | null;
  };
  indicators: Indicator[];
  similar: QueueReport[];
  reviews: { decision: string; notes: string; created_at: string }[];
};

type Decision = "verify" | "reject" | "duplicate" | "request_info";

const channelLabel = (c: string) => CHANNELS.find((x) => x.value === c)?.label ?? c;

const DIALOG_COPY: Record<Decision, { title: string; description: string; submit: string }> = {
  verify: {
    title: "Verify and publish",
    description:
      "Marks the report as verified and publishes its indicators as verified threat intelligence. Every scan on the platform will flag them straight away.",
    submit: "Verify and publish",
  },
  reject: {
    title: "Reject report",
    description: "The report couldn't be confirmed. Its indicators are left as they are.",
    submit: "Reject report",
  },
  duplicate: {
    title: "Mark as duplicate",
    description: "Link this report to an earlier report about the same scam.",
    submit: "Mark as duplicate",
  },
  request_info: {
    title: "Request more information",
    description: "Keeps the report under review. Use the public note to tell the reporter what you need.",
    submit: "Send request",
  },
};

function ReviewDialog({
  decision,
  detail,
  onClose,
}: {
  decision: Decision | null;
  detail: ReportDetail;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { data: campaigns } = useCampaigns(decision === "verify");
  const [notes, setNotes] = useState("");
  const [publicNote, setPublicNote] = useState("");
  const [confidence, setConfidence] = useState<Confidence>("medium");
  const [campaignId, setCampaignId] = useState("");
  const [expires, setExpires] = useState("180");
  const [duplicateOf, setDuplicateOf] = useState("");
  const [touched, setTouched] = useState(false);

  const id = detail.report.id;
  const notesTooShort = decision === "verify" && notes.trim().length < 10;
  const needsDuplicate = decision === "duplicate" && !duplicateOf;
  const expiresNum = Number(expires);
  const badExpiry = decision === "verify" && (!Number.isInteger(expiresNum) || expiresNum < 1 || expiresNum > 730);

  const submit = useMutation({
    mutationFn: () =>
      api<{ id: string; status: string }>(`/intelligence/reports/${id}/review`, {
        method: "POST",
        org: false,
        body: {
          decision,
          notes: notes.trim(),
          public_note: publicNote.trim() ? publicNote.trim() : undefined,
          confidence,
          campaign_id: campaignId || undefined,
          duplicate_of: duplicateOf || undefined,
          expires_in_days: decision === "verify" ? expiresNum : undefined,
        },
      }),
    onSuccess: () => {
      toast("success", decision ? `${REVIEW_DECISIONS[decision]}.` : "Saved.");
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY] });
      close();
    },
  });

  function close() {
    setNotes("");
    setPublicNote("");
    setConfidence("medium");
    setCampaignId("");
    setExpires("180");
    setDuplicateOf("");
    setTouched(false);
    submit.reset();
    onClose();
  }

  if (!decision) return null;
  const copy = DIALOG_COPY[decision];

  return (
    <Dialog
      open
      onClose={close}
      title={copy.title}
      description={copy.description}
      wide={decision === "verify"}
      footer={
        <>
          <Button variant="secondary" onClick={close}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="review-form"
            variant={decision === "reject" ? "danger" : "primary"}
            loading={submit.isPending}
          >
            {copy.submit}
          </Button>
        </>
      }
    >
      <form
        id="review-form"
        className="space-y-4"
        noValidate
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          setTouched(true);
          if (notesTooShort || needsDuplicate || badExpiry) return;
          submit.mutate();
        }}
      >
        {submit.isError && <Callout tone="critical">{errorMessage(submit.error)}</Callout>}
        {decision === "verify" && (
          <Callout tone="critical" icon={<ShieldAlert className="size-4" />} title="This publishes to every scan">
            {detail.indicators.length > 0 ? (
              <>
                {detail.indicators.length} indicator{detail.indicators.length === 1 ? "" : "s"} will be marked
                verified:{" "}
                <span className="font-mono text-xs">
                  {detail.indicators.map((i) => i.display_value).join(", ")}
                </span>
              </>
            ) : (
              "This report has no linked indicators, so nothing will be published. Only the report status changes."
            )}
          </Callout>
        )}

        {decision === "duplicate" && (
          <fieldset className="space-y-2">
            <legend className="mb-1.5 text-sm font-medium text-fg">Duplicate of</legend>
            {detail.similar.length === 0 ? (
              <p className="text-sm text-muted">
                No similar reports were found (same phone number or link), so this can&apos;t be marked as a duplicate.
              </p>
            ) : (
              detail.similar.map((s) => (
                <label
                  key={s.id}
                  className="flex cursor-pointer items-start gap-3 rounded-[var(--radius-control)] border border-border p-3 text-sm hover:bg-surface-2/50 has-[:checked]:border-primary has-[:checked]:bg-primary-soft/40"
                >
                  <input
                    type="radio"
                    name="duplicate_of"
                    value={s.id}
                    checked={duplicateOf === s.id}
                    onChange={() => setDuplicateOf(s.id)}
                    className="mt-1"
                  />
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-fg">{s.category_label}</span>
                      <ReportStatusBadge status={s.status} />
                      <span className="text-xs text-subtle">{formatDate(s.created_at)}</span>
                    </span>
                    <span className="mt-1 line-clamp-2 block text-muted">{s.description}</span>
                  </span>
                </label>
              ))
            )}
            {touched && needsDuplicate && detail.similar.length > 0 && (
              <p className="text-[13px] text-critical-text" role="alert">
                Choose the report this duplicates.
              </p>
            )}
          </fieldset>
        )}

        {decision === "verify" && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <Field label="Confidence" htmlFor="rv-confidence">
              <Select id="rv-confidence" value={confidence} onChange={(e) => setConfidence(e.target.value as Confidence)}>
                {CONFIDENCE_OPTIONS.map((c) => (
                  <option key={c.value} value={c.value}>
                    {c.label}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Campaign" htmlFor="rv-campaign" optional>
              <Select id="rv-campaign" value={campaignId} onChange={(e) => setCampaignId(e.target.value)}>
                <option value="">No campaign</option>
                {(campaigns ?? []).map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field
              label="Expires in (days)"
              htmlFor="rv-expires"
              error={touched && badExpiry ? "Between 1 and 730 days." : undefined}
            >
              <Input
                id="rv-expires"
                type="number"
                min={1}
                max={730}
                value={expires}
                onChange={(e) => setExpires(e.target.value)}
                invalid={touched && badExpiry}
              />
            </Field>
          </div>
        )}

        <Field
          label={decision === "verify" ? "Evidence notes" : "Internal notes"}
          htmlFor="rv-notes"
          optional={decision !== "verify"}
          error={touched && notesTooShort ? "Explain the evidence behind the verification (at least 10 characters)." : undefined}
          hint={
            decision === "verify"
              ? "Recorded in each indicator's history and used as its evidence summary if it has none. Staff only."
              : "Staff only. Never shown to the reporter."
          }
        >
          <Textarea
            id="rv-notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            invalid={touched && notesTooShort}
            rows={4}
            maxLength={5000}
          />
        </Field>

        <Field
          label="Public note to the reporter"
          htmlFor="rv-public"
          optional={decision !== "request_info"}
          hint="The reporter sees this in their report and notifications. Don't include other people's details."
        >
          <Textarea
            id="rv-public"
            value={publicNote}
            onChange={(e) => setPublicNote(e.target.value)}
            rows={2}
            maxLength={1000}
            placeholder={
              decision === "request_info"
                ? "For example: Please send a screenshot of the message, including the sender."
                : decision === "verify"
                  ? "For example: Thank you. We confirmed this scam and now warn everyone who checks this number."
                  : undefined
            }
          />
        </Field>
      </form>
    </Dialog>
  );
}

function RevealPhone({ reportId, masked }: { reportId: string; masked: string }) {
  const toast = useToast();
  const [confirming, setConfirming] = useState(false);
  const reveal = useMutation({
    mutationFn: () =>
      api<ReportDetail>(`/intelligence/reports/${reportId}`, { org: false, query: { reveal: true } }),
    onSuccess: () => setConfirming(false),
    onError: (e) => toast("error", errorMessage(e)),
  });
  const full = reveal.data?.report.full_phone;

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <span className="font-mono">{full ?? masked}</span>
      {full ? (
        <Badge tone="warning">Revealed — logged in the audit trail</Badge>
      ) : (
        <Button variant="ghost" size="sm" onClick={() => setConfirming(true)}>
          <Eye className="size-3.5" />
          Reveal full number
        </Button>
      )}
      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title="Reveal the full phone number?"
        description="Revealing it is recorded in the audit trail with your name and the time."
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirming(false)}>
              Cancel
            </Button>
            <Button loading={reveal.isPending} onClick={() => reveal.mutate()}>
              Reveal number
            </Button>
          </>
        }
      >
        <p className="text-sm text-muted">
          Only reveal the number when you need it to investigate, for example to check it against a carrier or
          a partner&apos;s records. Don&apos;t copy it into notes, campaigns or public text.
        </p>
      </Dialog>
    </span>
  );
}

function ReportDetailView({ id }: { id: string }) {
  const { intel } = useSession();
  const queryClient = useQueryClient();
  const toast = useToast();
  const canPublish = intel("intel:publish");
  const [decision, setDecision] = useState<Decision | null>(null);

  const { data, isPending, error } = useQuery({
    queryKey: [INTEL_KEY, "report", id],
    queryFn: () => api<ReportDetail>(`/intelligence/reports/${id}`, { org: false }),
  });

  const startReview = useMutation({
    mutationFn: () =>
      api(`/intelligence/reports/${id}/review`, {
        method: "POST",
        org: false,
        body: { decision: "start_review", notes: "" },
      }),
    onSuccess: () => {
      toast("success", "Marked as under review.");
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY] });
    },
    onError: (e) => toast("error", errorMessage(e)),
  });

  const back = <BackLink href="/intel/queue">Report queue</BackLink>;

  if (isPending) {
    return (
      <>
        {back}
        <Skeleton className="mb-4 h-10 w-80" />
        <Skeleton className="h-96" />
      </>
    );
  }
  if (error || !data) {
    return (
      <>
        {back}
        <Callout tone="critical">{errorMessage(error)}</Callout>
      </>
    );
  }

  const r = data.report;
  const closed = ["verified", "rejected", "duplicate"].includes(r.status);

  return (
    <>
      <PageHeader
        back={back}
        title={
          <span className="flex flex-wrap items-center gap-3">
            {r.category_label}
            <ReportStatusBadge status={r.status} />
          </span>
        }
        description={`Received ${formatDateTime(r.created_at)} via ${channelLabel(r.channel)}`}
        actions={
          <>
            {r.status === "unverified" && (
              <Button variant="secondary" size="sm" loading={startReview.isPending} onClick={() => startReview.mutate()}>
                <Play className="size-3.5" />
                Start review
              </Button>
            )}
            <Button variant="secondary" size="sm" onClick={() => setDecision("request_info")}>
              <HelpCircle className="size-3.5" />
              Request info
            </Button>
            <Button variant="secondary" size="sm" onClick={() => setDecision("duplicate")}>
              <Copy className="size-3.5" />
              Mark duplicate
            </Button>
            <Button variant="secondary" size="sm" onClick={() => setDecision("reject")}>
              <XCircle className="size-3.5" />
              Reject
            </Button>
            {canPublish && (
              <Button size="sm" onClick={() => setDecision("verify")}>
                <CircleCheck className="size-3.5" />
                Verify
              </Button>
            )}
          </>
        }
      />

      {closed && (
        <div className="mb-4">
          <Callout tone="info">
            This report has already been decided ({r.status}). You can still change the decision; the reporter is
            notified when the status changes.
            {r.duplicate_of && (
              <>
                {" "}
                <Link href={`/intel/queue/${r.duplicate_of}`} className="font-medium underline">
                  View the original report
                </Link>
                .
              </>
            )}
          </Callout>
        </div>
      )}
      {!canPublish && (
        <div className="mb-4">
          <Callout tone="neutral">
            Reviewers can triage, reject and mark duplicates. An analyst must verify reports, because verifying
            publishes indicators to every scan.
          </Callout>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader title="What the reporter told us" />
            <p className="text-sm whitespace-pre-wrap text-fg">{r.description}</p>
            {r.message && (
              <div className="mt-4">
                <p className="mb-1.5 text-xs font-medium tracking-wide text-subtle uppercase">
                  Message received (personal details redacted)
                </p>
                <pre className="max-h-80 overflow-auto rounded-[var(--radius-control)] border border-border bg-surface-2 p-3 font-mono text-xs whitespace-pre-wrap text-fg">
                  {r.message}
                </pre>
              </div>
            )}
          </Card>

          <Card padded={false}>
            <div className="p-5 pb-0">
              <CardHeader
                title="Linked indicators"
                description="Extracted from the report. Verifying the report publishes these."
              />
            </div>
            {data.indicators.length === 0 ? (
              <EmptyState title="No indicators were extracted from this report" />
            ) : (
              <ul className="divide-y divide-border border-t border-border">
                {data.indicators.map((i) => (
                  <li key={i.id}>
                    <Link
                      href={`/intel/indicators/${i.id}`}
                      className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm hover:bg-surface-2/50"
                    >
                      <Link2 className="size-4 text-subtle" />
                      <span className="text-xs text-muted">{indicatorTypeLabel(i.type)}</span>
                      <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg">{i.display_value}</span>
                      <IndicatorStatusBadge status={i.status} />
                      <ConfidenceBadge confidence={i.confidence} />
                      <span className="text-xs text-subtle">
                        {i.report_count} report{i.report_count === 1 ? "" : "s"}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card padded={false}>
            <div className="p-5 pb-0">
              <CardHeader
                title="Similar reports"
                description="Other reports with the same phone number or link — possible duplicates."
              />
            </div>
            {data.similar.length === 0 ? (
              <EmptyState title="No similar reports" />
            ) : (
              <ul className="divide-y divide-border border-t border-border">
                {data.similar.map((s) => (
                  <li key={s.id}>
                    <Link href={`/intel/queue/${s.id}`} className="block px-5 py-3 text-sm hover:bg-surface-2/50">
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-fg">{s.category_label}</span>
                        <ReportStatusBadge status={s.status} />
                        <span className="text-xs text-subtle">{timeAgo(s.created_at)}</span>
                      </span>
                      <span className="mt-1 line-clamp-2 block text-[13px] text-muted">{s.description}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Details" />
            <Facts
              className="sm:grid-cols-1"
              items={[
                ["Link", r.url ? <span className="font-mono text-xs break-all">{r.url}</span> : "—"],
                ["Phone number", r.phone ? <RevealPhone reportId={r.id} masked={r.phone} /> : "—"],
                ["Sender", r.sender ?? "—"],
                ["Happened on", formatDate(r.occurred_on)],
                ["Money lost", r.money_lost ? <Badge tone="critical">Yes</Badge> : "No"],
                ["Reported by", r.organisation_report ? "A business workspace" : "A member of the public"],
                ["Reporter contact", r.contact_email ?? "—"],
                ["Public note", r.public_note ?? "—"],
              ]}
            />
          </Card>

          <Card>
            <CardHeader title="Review history" />
            {data.reviews.length === 0 ? (
              <p className="text-sm text-muted">No decisions yet.</p>
            ) : (
              <ol className="relative space-y-4 border-l border-border pl-4">
                {data.reviews.map((v, idx) => (
                  <li key={idx} className="relative">
                    <span className="absolute top-1.5 -left-[21px] size-2.5 rounded-full border-2 border-surface bg-primary" />
                    <p className="text-sm font-medium text-fg">{REVIEW_DECISIONS[v.decision] ?? v.decision}</p>
                    <p className="text-xs text-subtle">{formatDateTime(v.created_at)}</p>
                    {v.notes && <p className="mt-1 text-[13px] whitespace-pre-wrap text-muted">{v.notes}</p>}
                  </li>
                ))}
              </ol>
            )}
            <p className="mt-4 flex items-center gap-1.5 text-xs text-subtle">
              <History className="size-3.5" />
              Every decision is recorded in the audit trail.
            </p>
          </Card>
        </div>
      </div>

      <ReviewDialog decision={decision} detail={data} onClose={() => setDecision(null)} />
    </>
  );
}

export default function ReportDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <IntelGate perm="intel:review">
      <ReportDetailView id={id} />
    </IntelGate>
  );
}
