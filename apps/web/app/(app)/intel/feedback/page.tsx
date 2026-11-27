"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, Lock, ThumbsDown } from "lucide-react";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { Dialog } from "@/components/dialog";
import { INTEL_KEY, IntelGate } from "@/components/intel-ui";
import { useToast } from "@/components/providers";
import { useSession } from "@/components/session";
import {
  Badge,
  Button,
  Callout,
  Card,
  EmptyState,
  Field,
  PageHeader,
  Select,
  Skeleton,
  Textarea,
} from "@/components/ui";
import { api, errorMessage } from "@/lib/api";
import { formatDateTime, timeAgo } from "@/lib/format";
import { SCAN_KINDS, VERDICTS, verdictTone, type Tone } from "@/lib/labels";

type Feedback = {
  id: string;
  kind: "false_positive" | "false_negative";
  comment: string | null;
  status: string;
  created_at: string;
  scan: {
    id: string;
    kind: string;
    title: string;
    verdict: string | null;
    risk_score: number | null;
    indicator_ids: string[];
  };
};

const KINDS: Record<string, { label: string; hint: string; tone: Tone }> = {
  false_positive: {
    label: "False positive",
    hint: "Flagged as risky, but the person says it's legitimate",
    tone: "warning",
  },
  false_negative: {
    label: "False negative",
    hint: "Rated low risk, but the person says it's a scam",
    tone: "critical",
  },
};

const STATUSES = [
  { value: "open", label: "Open" },
  { value: "accepted", label: "Accepted" },
  { value: "dismissed", label: "Dismissed" },
];

function ResolveDialog({ item, onClose }: { item: Feedback | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [status, setStatus] = useState<"accepted" | "dismissed">("accepted");
  const [resolution, setResolution] = useState("");
  const [touched, setTouched] = useState(false);
  const short = resolution.trim().length < 5;

  const resolve = useMutation({
    mutationFn: () =>
      api(`/intelligence/feedback/${item?.id}/resolve`, {
        method: "POST",
        org: false,
        body: { status, resolution: resolution.trim() },
      }),
    onSuccess: () => {
      toast("success", status === "accepted" ? "Feedback accepted." : "Feedback dismissed.");
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY] });
      close();
    },
  });

  function close() {
    setStatus("accepted");
    setResolution("");
    setTouched(false);
    resolve.reset();
    onClose();
  }

  if (!item) return null;
  return (
    <Dialog
      open
      onClose={close}
      title="Resolve disputed result"
      description={`${KINDS[item.kind]?.label ?? item.kind} on "${item.scan.title}"`}
      footer={
        <>
          <Button variant="secondary" onClick={close}>
            Cancel
          </Button>
          <Button type="submit" form="resolve-form" loading={resolve.isPending}>
            Resolve
          </Button>
        </>
      }
    >
      <form
        id="resolve-form"
        className="space-y-4"
        noValidate
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          setTouched(true);
          if (!short) resolve.mutate();
        }}
      >
        {resolve.isError && <Callout tone="critical">{errorMessage(resolve.error)}</Callout>}
        <Field
          label="Outcome"
          htmlFor="fb-status"
          hint={
            status === "accepted"
              ? "The person was right. Correct any indicator or brand data behind the result before you accept."
              : "The original result stands."
          }
        >
          <Select id="fb-status" value={status} onChange={(e) => setStatus(e.target.value as "accepted" | "dismissed")}>
            <option value="accepted">Accepted — the result was wrong</option>
            <option value="dismissed">Dismissed — the result was right</option>
          </Select>
        </Field>
        <Field
          label="Resolution"
          htmlFor="fb-resolution"
          error={touched && short ? "Describe what you found (at least 5 characters)." : undefined}
          hint="What you checked and what you changed. Recorded in the audit trail."
        >
          <Textarea
            id="fb-resolution"
            value={resolution}
            onChange={(e) => setResolution(e.target.value)}
            invalid={touched && short}
            rows={4}
            maxLength={2000}
          />
        </Field>
      </form>
    </Dialog>
  );
}

function FeedbackView() {
  const { intel } = useSession();
  const canResolve = intel("intel:review");
  const [status, setStatus] = useState("open");
  const [resolving, setResolving] = useState<Feedback | null>(null);

  const { data, isPending, error } = useQuery({
    queryKey: [INTEL_KEY, "feedback", status],
    queryFn: () => api<Feedback[]>("/intelligence/feedback", { org: false, query: { status } }),
  });

  return (
    <>
      <PageHeader
        title="Disputed results"
        description="People who think a scan result was wrong. Check the evidence, correct the intelligence if needed, then resolve."
        actions={
          <Select aria-label="Filter by status" value={status} onChange={(e) => setStatus(e.target.value)} className="w-40">
            {STATUSES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </Select>
        }
      />
      <div className="mb-4">
        <Callout tone="neutral" icon={<Lock className="size-4" />}>
          Scans are private to the person or business that ran them, so staff can&apos;t open the scan itself. Only
          the details below are shared with the console.
        </Callout>
      </div>

      {error ? (
        <Callout tone="critical">{errorMessage(error)}</Callout>
      ) : isPending ? (
        <Skeleton className="h-64" />
      ) : !data?.length ? (
        <Card>
          <EmptyState
            icon={<ThumbsDown className="size-5" />}
            title={status === "open" ? "No open disputes" : `No ${status} disputes`}
          />
        </Card>
      ) : (
        <>
          <ul className="space-y-3">
            {data.map((f) => {
              const kind = KINDS[f.kind];
              const verdict = f.scan.verdict ? VERDICTS[f.scan.verdict] : null;
              return (
                <li key={f.id}>
                  <Card className="p-4">
                    <div className="flex flex-col gap-3 md:flex-row md:items-start">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge tone={kind?.tone ?? "neutral"}>{kind?.label ?? f.kind}</Badge>
                          <span className="text-xs text-subtle" title={formatDateTime(f.created_at)}>
                            {timeAgo(f.created_at)}
                          </span>
                          {f.status !== "open" && <Badge tone="neutral">{f.status}</Badge>}
                        </div>
                        <p className="mt-2 truncate text-sm font-medium text-fg" title={f.scan.title}>
                          {f.scan.title}
                        </p>
                        <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted">
                          <span>{SCAN_KINDS[f.scan.kind] ?? f.scan.kind}</span>
                          <span aria-hidden>·</span>
                          <Badge tone={verdictTone(f.scan.verdict)}>{verdict?.short ?? "No verdict"}</Badge>
                          {f.scan.risk_score !== null && (
                            <span className="tabular-nums">Risk score {f.scan.risk_score}/100</span>
                          )}
                          {f.scan.indicator_ids.length > 0 && (
                            <>
                              <span aria-hidden>·</span>
                              <span>
                                Matched{" "}
                                {f.scan.indicator_ids.slice(0, 5).map((iid, idx) => (
                                  <span key={iid}>
                                    {idx > 0 && ", "}
                                    <Link href={`/intel/indicators/${iid}`} className="text-primary-text hover:underline">
                                      indicator {idx + 1}
                                    </Link>
                                  </span>
                                ))}
                                {f.scan.indicator_ids.length > 5 && ` and ${f.scan.indicator_ids.length - 5} more`}
                              </span>
                            </>
                          )}
                        </div>
                        <p className="mt-2 text-xs text-subtle">{kind?.hint}</p>
                        <blockquote className="mt-2 rounded-[var(--radius-control)] border-l-2 border-border-strong bg-surface-2 px-3 py-2 text-sm whitespace-pre-wrap text-fg">
                          {f.comment?.trim() || <span className="text-muted">No comment left.</span>}
                        </blockquote>
                      </div>
                      {canResolve && f.status === "open" && (
                        <Button variant="secondary" size="sm" onClick={() => setResolving(f)} className="shrink-0">
                          <CircleCheck className="size-3.5" />
                          Resolve
                        </Button>
                      )}
                    </div>
                  </Card>
                </li>
              );
            })}
          </ul>
          <p className="mt-3 text-sm text-muted">
            {data.length} {data.length === 1 ? "dispute" : "disputes"}
            {data.length >= 200 && " (showing the oldest 200)"}
          </p>
        </>
      )}
      <ResolveDialog item={resolving} onClose={() => setResolving(null)} />
    </>
  );
}

export default function FeedbackPage() {
  return (
    <IntelGate>
      <FeedbackView />
    </IntelGate>
  );
}
