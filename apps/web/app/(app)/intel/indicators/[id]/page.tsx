"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDownCircle, Ban, CircleCheck, Pencil, RotateCcw, ShieldAlert, XCircle } from "lucide-react";
import Link from "next/link";
import { use, useState, type FormEvent } from "react";
import { Dialog } from "@/components/dialog";
import {
  BackLink,
  CONFIDENCE_OPTIONS,
  ConfidenceBadge,
  DispositionBadge,
  Facts,
  INTEL_KEY,
  IndicatorStatusBadge,
  IntelGate,
  ReportStatusBadge,
  indicatorTypeLabel,
  splitList,
  useCampaigns,
} from "@/components/intel-ui";
import { useToast } from "@/components/providers";
import { useSession } from "@/components/session";
import {
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
import { CONFIDENCE, INDICATOR_STATUS, categoryLabel, SCAM_CATEGORIES } from "@/lib/labels";
import type { Confidence, Indicator } from "@/lib/types";

type IndicatorDetail = {
  indicator: Indicator;
  history: {
    from_status: string | null;
    to_status: string;
    from_confidence: string | null;
    to_confidence: string | null;
    reason: string | null;
    actor: string | null;
    created_at: string;
  }[];
  observations: number;
  scan_matches: number;
  reports: { id: string; category: string; status: string; created_at: string }[];
};

type ReviewDecision = "verify" | "downgrade" | "revoke" | "reject" | "reactivate";

const DECISIONS: Record<
  ReviewDecision,
  { label: string; title: string; description: string; publishes: boolean; danger?: boolean }
> = {
  verify: {
    label: "Verify",
    title: "Verify indicator",
    description: "Publishes the indicator as verified threat intelligence.",
    publishes: true,
  },
  reactivate: {
    label: "Reactivate",
    title: "Reactivate indicator",
    description: "Restores the indicator to verified with a new expiry date.",
    publishes: true,
  },
  downgrade: {
    label: "Downgrade",
    title: "Downgrade to unverified",
    description: "Stops treating the indicator as verified. Scans may still show it as a community signal.",
    publishes: false,
  },
  revoke: {
    label: "Revoke",
    title: "Revoke indicator",
    description: "Withdraws a previously verified indicator, for example after a takedown or a false positive.",
    publishes: false,
    danger: true,
  },
  reject: {
    label: "Reject",
    title: "Reject indicator",
    description: "Marks the indicator as not malicious. Scans stop using it.",
    publishes: false,
    danger: true,
  },
};

function availableDecisions(status: string): ReviewDecision[] {
  switch (status) {
    case "unverified":
      return ["verify", "reject"];
    case "verified":
      return ["downgrade", "revoke", "reject"];
    case "revoked":
    case "expired":
      return ["reactivate", "reject"];
    case "rejected":
      return ["verify"];
    default:
      return ["verify"];
  }
}

const DECISION_ICONS: Record<ReviewDecision, typeof CircleCheck> = {
  verify: CircleCheck,
  reactivate: RotateCcw,
  downgrade: ArrowDownCircle,
  revoke: Ban,
  reject: XCircle,
};

function ReviewDialog({
  decision,
  indicator,
  onClose,
}: {
  decision: ReviewDecision | null;
  indicator: Indicator;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [reason, setReason] = useState("");
  const [confidence, setConfidence] = useState<Confidence>(indicator.confidence);
  const [disposition, setDisposition] = useState(indicator.disposition);
  const [expires, setExpires] = useState("180");
  const [touched, setTouched] = useState(false);

  const meta = decision ? DECISIONS[decision] : null;
  const reasonShort = reason.trim().length < 5;
  const n = Number(expires);
  const badExpiry = Boolean(meta?.publishes) && (!Number.isInteger(n) || n < 1 || n > 730);

  const review = useMutation({
    mutationFn: () =>
      api<Indicator>(`/intelligence/indicators/${indicator.id}/review`, {
        method: "POST",
        org: false,
        body: {
          decision,
          reason: reason.trim(),
          confidence,
          disposition,
          expires_in_days: meta?.publishes ? n : undefined,
        },
      }),
    onSuccess: (ind) => {
      toast("success", `Indicator is now ${INDICATOR_STATUS[ind.status]?.label.toLowerCase() ?? ind.status}.`);
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY] });
      close();
    },
  });

  function close() {
    setReason("");
    setExpires("180");
    setTouched(false);
    review.reset();
    onClose();
  }

  if (!decision || !meta) return null;

  return (
    <Dialog
      open
      onClose={close}
      title={meta.title}
      description={meta.description}
      footer={
        <>
          <Button variant="secondary" onClick={close}>
            Cancel
          </Button>
          <Button type="submit" form="ind-review" variant={meta.danger ? "danger" : "primary"} loading={review.isPending}>
            {meta.label}
          </Button>
        </>
      }
    >
      <form
        id="ind-review"
        className="space-y-4"
        noValidate
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          setTouched(true);
          if (reasonShort || badExpiry) return;
          review.mutate();
        }}
      >
        {review.isError && <Callout tone="critical">{errorMessage(review.error)}</Callout>}
        {meta.publishes && (
          <Callout tone="critical" icon={<ShieldAlert className="size-4" />} title="Publishes to every scan">
            <span className="font-mono text-xs break-all">{indicator.display_value}</span> will be flagged in every
            scan on the platform.
          </Callout>
        )}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Field label="Confidence" htmlFor="ir-confidence">
            <Select id="ir-confidence" value={confidence} onChange={(e) => setConfidence(e.target.value as Confidence)}>
              {CONFIDENCE_OPTIONS.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Disposition" htmlFor="ir-disposition">
            <Select id="ir-disposition" value={disposition} onChange={(e) => setDisposition(e.target.value)}>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
            </Select>
          </Field>
          {meta.publishes && (
            <Field label="Expires in (days)" htmlFor="ir-expires" error={touched && badExpiry ? "Between 1 and 730 days." : undefined}>
              <Input
                id="ir-expires"
                type="number"
                min={1}
                max={730}
                value={expires}
                onChange={(e) => setExpires(e.target.value)}
                invalid={touched && badExpiry}
              />
            </Field>
          )}
        </div>
        <Field
          label="Reason"
          htmlFor="ir-reason"
          error={touched && reasonShort ? "Give a reason (at least 5 characters)." : undefined}
          hint="Recorded in the status history and audit trail."
        >
          <Textarea
            id="ir-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            invalid={touched && reasonShort}
            rows={3}
            maxLength={2000}
          />
        </Field>
      </form>
    </Dialog>
  );
}

function EditDialog({
  open,
  indicator,
  onClose,
}: {
  open: boolean;
  indicator: Indicator;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { data: campaigns } = useCampaigns(open);
  const [category, setCategory] = useState(indicator.category ?? "");
  const [campaignId, setCampaignId] = useState(indicator.campaign_id ?? "");
  const [notes, setNotes] = useState(indicator.notes ?? "");
  const [evidence, setEvidence] = useState(indicator.evidence_summary ?? "");
  const [references, setReferences] = useState(indicator.references.join("\n"));
  const [refError, setRefError] = useState<string>();

  const save = useMutation({
    mutationFn: () =>
      api<Indicator>(`/intelligence/indicators/${indicator.id}`, {
        method: "PATCH",
        org: false,
        body: {
          category: category || null,
          campaign_id: campaignId || null,
          notes: notes.trim() || null,
          evidence_summary: evidence.trim() || null,
          references: splitList(references),
        },
      }),
    onSuccess: () => {
      toast("success", "Indicator updated.");
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY] });
      onClose();
    },
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="Edit indicator"
      description="Status changes go through the review actions, so they're recorded in the history."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="ind-edit" loading={save.isPending}>
            Save changes
          </Button>
        </>
      }
    >
      <form
        id="ind-edit"
        className="space-y-4"
        noValidate
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          if (splitList(references).length > 20) {
            setRefError("Add at most 20 references.");
            return;
          }
          setRefError(undefined);
          save.mutate();
        }}
      >
        {save.isError && <Callout tone="critical">{errorMessage(save.error)}</Callout>}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Category" htmlFor="ie-category">
            <Select id="ie-category" value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">Not set</option>
              {SCAM_CATEGORIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
              {category && !SCAM_CATEGORIES.some((c) => c.value === category) && (
                <option value={category}>{indicator.category_label ?? category}</option>
              )}
            </Select>
          </Field>
          <Field label="Campaign" htmlFor="ie-campaign">
            <Select id="ie-campaign" value={campaignId} onChange={(e) => setCampaignId(e.target.value)}>
              <option value="">No campaign</option>
              {(campaigns ?? []).map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <Field label="Evidence summary" htmlFor="ie-evidence">
          <Textarea id="ie-evidence" value={evidence} onChange={(e) => setEvidence(e.target.value)} rows={3} maxLength={5000} />
        </Field>
        <Field label="References" htmlFor="ie-refs" hint="One per line." error={refError}>
          <Textarea
            id="ie-refs"
            value={references}
            onChange={(e) => setReferences(e.target.value)}
            rows={3}
            className="font-mono text-xs"
          />
        </Field>
        <Field label="Analyst notes" htmlFor="ie-notes" hint="Staff only.">
          <Textarea id="ie-notes" value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} maxLength={5000} />
        </Field>
      </form>
    </Dialog>
  );
}

function IndicatorDetailView({ id }: { id: string }) {
  const { intel } = useSession();
  const canPublish = intel("intel:publish");
  const canEdit = intel("intel:review");
  const [decision, setDecision] = useState<ReviewDecision | null>(null);
  const [editing, setEditing] = useState(false);

  const { data, isPending, error } = useQuery({
    queryKey: [INTEL_KEY, "indicator", id],
    queryFn: () => api<IndicatorDetail>(`/intelligence/indicators/${id}`, { org: false }),
  });
  const { data: campaigns } = useCampaigns();

  const back = <BackLink href="/intel/indicators">Indicators</BackLink>;
  if (isPending) {
    return (
      <>
        {back}
        <Skeleton className="mb-4 h-10 w-96" />
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

  const i = data.indicator;
  const campaign = campaigns?.find((c) => c.id === i.campaign_id);

  return (
    <>
      <PageHeader
        back={back}
        title={<span className="font-mono text-xl break-all">{i.display_value}</span>}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <span>{indicatorTypeLabel(i.type)}</span>
            <IndicatorStatusBadge status={i.status} />
            <ConfidenceBadge confidence={i.confidence} />
            <DispositionBadge disposition={i.disposition} />
          </span>
        }
        actions={
          <>
            {canEdit && (
              <Button variant="secondary" size="sm" onClick={() => setEditing(true)}>
                <Pencil className="size-3.5" />
                Edit
              </Button>
            )}
            {canPublish &&
              availableDecisions(i.status).map((d) => {
                const Icon = DECISION_ICONS[d];
                return (
                  <Button
                    key={d}
                    size="sm"
                    variant={DECISIONS[d].publishes ? "primary" : "secondary"}
                    onClick={() => setDecision(d)}
                  >
                    <Icon className="size-3.5" />
                    {DECISIONS[d].label}
                  </Button>
                );
              })}
          </>
        }
      />

      {i.status === "verified" && (
        <div className="mb-4">
          <Callout tone="critical" icon={<ShieldAlert className="size-4" />}>
            This indicator is verified and is flagged in every scan on the platform
            {i.expires_at ? ` until ${formatDate(i.expires_at)}` : ""}.
          </Callout>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader title="Details" />
            <Facts
              items={[
                ["Status", INDICATOR_STATUS[i.status]?.label ?? i.status],
                ["Confidence", CONFIDENCE[i.confidence] ?? i.confidence],
                ["Category", i.category_label ?? "—"],
                [
                  "Campaign",
                  campaign ? (
                    <Link href="/intel/campaigns" className="text-primary-text hover:underline">
                      {campaign.name}
                    </Link>
                  ) : (
                    "—"
                  ),
                ],
                ["Source", i.source ?? "—"],
                ["First seen", formatDateTime(i.first_seen_at)],
                ["Last seen", `${formatDateTime(i.last_seen_at)} (${timeAgo(i.last_seen_at)})`],
                ["Last verified", formatDateTime(i.last_verified_at)],
                ["Expires", formatDate(i.expires_at)],
                ["Community reports", i.report_count],
                ["Scan matches", data.scan_matches],
                ["All observations", data.observations],
              ]}
            />
          </Card>
          <Card>
            <CardHeader title="Evidence" />
            <p className="text-sm whitespace-pre-wrap text-fg">{i.evidence_summary || <span className="text-muted">No evidence summary yet.</span>}</p>
            {i.references.length > 0 && (
              <>
                <p className="mt-4 mb-1.5 text-xs font-medium tracking-wide text-subtle uppercase">References</p>
                <ul className="space-y-1">
                  {i.references.map((ref, idx) => (
                    <li key={idx} className="font-mono text-xs break-all text-fg">
                      {/^https?:\/\//.test(ref) ? (
                        <a href={ref} target="_blank" rel="noopener noreferrer nofollow" className="text-primary-text hover:underline">
                          {ref}
                        </a>
                      ) : (
                        ref
                      )}
                    </li>
                  ))}
                </ul>
              </>
            )}
            {i.notes && (
              <>
                <p className="mt-4 mb-1.5 text-xs font-medium tracking-wide text-subtle uppercase">Analyst notes</p>
                <p className="text-sm whitespace-pre-wrap text-muted">{i.notes}</p>
              </>
            )}
          </Card>
          <Card padded={false}>
            <div className="p-5 pb-0">
              <CardHeader title="Related reports" description="Community reports that mention this indicator (latest 20)." />
            </div>
            {data.reports.length === 0 ? (
              <EmptyState title="No community reports" />
            ) : (
              <ul className="divide-y divide-border border-t border-border">
                {data.reports.map((r) => (
                  <li key={r.id}>
                    <Link href={`/intel/queue/${r.id}`} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm hover:bg-surface-2/50">
                      <span className="flex-1 text-fg">{categoryLabel(r.category)}</span>
                      <ReportStatusBadge status={r.status} />
                      <span className="text-xs text-subtle">{formatDate(r.created_at)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        <Card>
          <CardHeader title="Status history" />
          {data.history.length === 0 ? (
            <p className="text-sm text-muted">No status changes yet.</p>
          ) : (
            <ol className="relative space-y-5 border-l border-border pl-4">
              {data.history.map((h, idx) => (
                <li key={idx} className="relative">
                  <span className="absolute top-1.5 -left-[21px] size-2.5 rounded-full border-2 border-surface bg-primary" />
                  <p className="flex flex-wrap items-center gap-1.5 text-sm">
                    {h.from_status && (
                      <>
                        <IndicatorStatusBadge status={h.from_status} />
                        <span className="text-subtle">→</span>
                      </>
                    )}
                    <IndicatorStatusBadge status={h.to_status} />
                  </p>
                  {h.to_confidence && h.to_confidence !== h.from_confidence && (
                    <p className="mt-1 text-xs text-muted">
                      Confidence: {h.from_confidence ? `${h.from_confidence} → ` : ""}
                      {h.to_confidence}
                    </p>
                  )}
                  <p className="mt-1 text-xs text-subtle">
                    {formatDateTime(h.created_at)} · {h.actor ?? "System"}
                  </p>
                  {h.reason && <p className="mt-1 text-[13px] whitespace-pre-wrap text-muted">{h.reason}</p>}
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>

      <ReviewDialog
        key={`${decision}-${i.status}-${i.confidence}`}
        decision={decision}
        indicator={i}
        onClose={() => setDecision(null)}
      />
      {editing && <EditDialog open indicator={i} onClose={() => setEditing(false)} />}
    </>
  );
}

export default function IndicatorDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <IntelGate>
      <IndicatorDetailView id={id} />
    </IntelGate>
  );
}
