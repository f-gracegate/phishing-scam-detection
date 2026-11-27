"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  CircleDot,
  FolderPlus,
  Link2,
  MessageSquareText,
  RefreshCw,
  UserRound,
} from "lucide-react";
import Link from "next/link";
import { use, useState, type FormEvent } from "react";
import { CaseStatusBadge, NoAccess, SeverityBadge, useMembers } from "@/components/business-ui";
import { useToast } from "@/components/providers";
import { ScanRow } from "@/components/scan-ui";
import { useOrgKey, useSession } from "@/components/session";
import {
  Badge,
  Button,
  Callout,
  Card,
  CardHeader,
  EmptyState,
  Field,
  PageHeader,
  Select,
  Skeleton,
  Textarea,
} from "@/components/ui";
import { api, errorMessage } from "@/lib/api";
import { formatDateTime, timeAgo } from "@/lib/format";
import { CASE_OUTCOMES, CASE_STATUS, SEVERITIES } from "@/lib/labels";
import type { Case, CaseDetail } from "@/lib/types";

type CaseEvent = CaseDetail["events"][number];

const EVENT_ICON: Record<string, typeof CircleDot> = {
  created: FolderPlus,
  note: MessageSquareText,
  status: RefreshCw,
  assigned: UserRound,
  linked: Link2,
};

const outcomeLabel = (v: string | null) => CASE_OUTCOMES.find((o) => o.value === v)?.label ?? v;

function StatusCard({ c }: { c: CaseDetail }) {
  const queryClient = useQueryClient();
  const orgKey = useOrgKey();
  const toast = useToast();
  const [status, setStatus] = useState<string>(c.status);
  const [outcome, setOutcome] = useState(c.outcome ?? "");
  const [severity, setSeverity] = useState<string>(c.severity);

  const dirty = status !== c.status || severity !== c.severity || (outcome || null) !== c.outcome;
  const needsOutcome = status === "closed" && !outcome;

  const save = useMutation({
    mutationFn: () => {
      const body: Record<string, unknown> = {};
      if (status !== c.status) body.status = status;
      if (severity !== c.severity) body.severity = severity;
      if (outcome && outcome !== c.outcome) body.outcome = outcome;
      return api<Case>(`/business/cases/${c.id}`, { method: "PATCH", body });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [...orgKey, "business"] });
      toast("success", status === "closed" && c.status !== "closed" ? "Case closed." : "Case updated.");
    },
    onError: (err) => toast("error", errorMessage(err)),
  });

  return (
    <Card>
      <CardHeader title="Status" />
      <form
        className="space-y-4"
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <Field label="Status" htmlFor="case-status">
          <Select id="case-status" value={status} onChange={(e) => setStatus(e.target.value)}>
            {Object.entries(CASE_STATUS).map(([value, s]) => (
              <option key={value} value={value}>
                {s.label}
              </option>
            ))}
          </Select>
        </Field>
        {(status === "closed" || c.outcome) && (
          <Field
            label="Outcome"
            htmlFor="case-outcome"
            hint={status === "closed" ? "Required to close the case." : undefined}
          >
            <Select
              id="case-outcome"
              value={outcome}
              onChange={(e) => setOutcome(e.target.value)}
              invalid={needsOutcome}
            >
              <option value="">Choose an outcome</option>
              {CASE_OUTCOMES.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </Field>
        )}
        <Field label="Severity" htmlFor="case-severity">
          <Select id="case-severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </Select>
        </Field>
        <Button type="submit" className="w-full" loading={save.isPending} disabled={!dirty || needsOutcome}>
          {status === "closed" && c.status !== "closed" ? "Close case" : "Save changes"}
        </Button>
      </form>
    </Card>
  );
}

function AssigneeCard({ c, canManage }: { c: CaseDetail; canManage: boolean }) {
  const queryClient = useQueryClient();
  const orgKey = useOrgKey();
  const toast = useToast();
  const members = useMembers();

  const assign = useMutation({
    mutationFn: (assignee_id: string | null) =>
      api<Case>(`/business/cases/${c.id}`, { method: "PATCH", body: { assignee_id } }),
    onSuccess: (updated) => {
      queryClient.invalidateQueries({ queryKey: [...orgKey, "business"] });
      toast("success", updated.assignee ? `Assigned to ${updated.assignee}.` : "Case unassigned.");
    },
    onError: (err) => toast("error", errorMessage(err)),
  });

  return (
    <Card>
      <CardHeader title="Assignee" />
      {canManage ? (
        <Select
          aria-label="Assignee"
          value={c.assignee_id ?? ""}
          onChange={(e) => assign.mutate(e.target.value || null)}
          disabled={members.isPending || assign.isPending}
        >
          <option value="">Unassigned</option>
          {(members.data ?? [])
            .filter((m) => m.status === "active" || m.user_id === c.assignee_id)
            .map((m) => (
              <option key={m.user_id} value={m.user_id}>
                {m.full_name || m.email}
                {m.is_you ? " (you)" : ""}
              </option>
            ))}
        </Select>
      ) : (
        <p className="text-sm text-fg">{c.assignee ?? "Unassigned"}</p>
      )}
    </Card>
  );
}

function NoteForm({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient();
  const orgKey = useOrgKey();
  const toast = useToast();
  const [message, setMessage] = useState("");

  const add = useMutation({
    mutationFn: () =>
      api<CaseEvent>(`/business/cases/${caseId}/notes`, { method: "POST", body: { message: message.trim() } }),
    onSuccess: () => {
      setMessage("");
      queryClient.invalidateQueries({ queryKey: [...orgKey, "business"] });
    },
    onError: (err) => toast("error", errorMessage(err)),
  });

  return (
    <form
      className="space-y-3 border-t border-border pt-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (message.trim()) add.mutate();
      }}
    >
      <Field label="Add a note" htmlFor="case-note" hint="Notes are visible to everyone who can see this case.">
        <Textarea
          id="case-note"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          rows={3}
          maxLength={10000}
          placeholder="What did you find? What's the next step?"
        />
      </Field>
      <div className="flex justify-end">
        <Button type="submit" size="sm" loading={add.isPending} disabled={!message.trim()}>
          Add note
        </Button>
      </div>
    </form>
  );
}

function Timeline({ events }: { events: CaseEvent[] }) {
  if (!events.length) return <p className="text-sm text-muted">No activity yet.</p>;
  return (
    <ol className="relative space-y-5">
      {events.map((e, i) => {
        const Icon = EVENT_ICON[e.kind] ?? CircleDot;
        const isNote = e.kind === "note";
        return (
          <li key={e.id} className="relative flex gap-3">
            {i < events.length - 1 && (
              <span className="absolute top-8 bottom-[-20px] left-[15px] w-px bg-border" aria-hidden />
            )}
            <span
              className={
                isNote
                  ? "flex size-8 shrink-0 items-center justify-center rounded-full bg-primary-soft text-primary-text"
                  : "flex size-8 shrink-0 items-center justify-center rounded-full bg-surface-2 text-muted"
              }
            >
              <Icon className="size-4" aria-hidden />
            </span>
            <div className="min-w-0 flex-1 pt-1">
              <p className="text-xs text-subtle">
                <span className="font-medium text-muted">{e.actor ?? "System"}</span> ·{" "}
                <time dateTime={e.created_at} title={formatDateTime(e.created_at)}>
                  {timeAgo(e.created_at)}
                </time>
              </p>
              {isNote ? (
                <p className="mt-1.5 rounded-[var(--radius-control)] border border-border bg-surface-2 px-3 py-2 text-sm whitespace-pre-wrap text-fg">
                  {e.message}
                </p>
              ) : (
                <p className="mt-0.5 text-sm text-fg">{e.message}</p>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export default function CaseDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { can } = useSession();
  const allowed = can("cases:read") || can("cases:manage");
  const canManage = can("cases:manage");

  const { data: c, isPending, isError, error } = useQuery({
    queryKey: useOrgKey("business", "cases", "detail", id),
    queryFn: () => api<CaseDetail>(`/business/cases/${id}`),
    enabled: allowed,
  });

  if (!allowed) return <NoAccess what="investigation cases" />;

  const back = (
    <Link
      href="/business/cases"
      className="mb-3 inline-flex items-center gap-1.5 text-sm text-muted hover:text-fg"
    >
      <ArrowLeft className="size-4" aria-hidden /> All cases
    </Link>
  );

  if (isPending) {
    return (
      <div className="space-y-6">
        {back}
        <Skeleton className="h-16" />
        <div className="grid gap-6 lg:grid-cols-3">
          <Skeleton className="h-80 lg:col-span-2" />
          <Skeleton className="h-80" />
        </div>
      </div>
    );
  }
  if (isError || !c) {
    return (
      <div>
        {back}
        <Card>
          <EmptyState title="We couldn't load this case" description={errorMessage(error)} />
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        back={back}
        title={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="font-mono text-base font-medium text-subtle">{c.reference}</span>
            <span className="min-w-0 break-words">{c.title}</span>
          </span>
        }
        description={
          <span className="mt-1 flex flex-wrap items-center gap-2">
            <CaseStatusBadge status={c.status} />
            <SeverityBadge severity={c.severity} />
            {c.category_label && <Badge tone="neutral">{c.category_label}</Badge>}
            <span className="text-xs text-subtle">
              Opened {formatDateTime(c.created_at)}
              {c.created_by ? ` by ${c.created_by}` : ""}
            </span>
          </span>
        }
      />

      {c.status === "closed" && (
        <Callout tone="neutral" title={`Closed ${c.closed_at ? formatDateTime(c.closed_at) : ""}`}>
          Outcome: {outcomeLabel(c.outcome) ?? "Not recorded"}
        </Callout>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {c.description && (
            <Card>
              <CardHeader title="Description" />
              <p className="text-sm whitespace-pre-wrap text-fg">{c.description}</p>
            </Card>
          )}

          <Card padded={false}>
            <div className="p-5 pb-3">
              <CardHeader
                title="Linked scans"
                description="Links, messages and emails that are part of this investigation."
              />
            </div>
            {c.scans.length ? (
              <div className="divide-y divide-border border-t border-border">
                {c.scans.map((s) => (
                  <ScanRow key={s.id} scan={s} href={`/scans/${s.id}`} />
                ))}
              </div>
            ) : (
              <p className="px-5 pb-5 text-sm text-muted">
                No scans linked yet. Open a scan result to add it to a case.
              </p>
            )}
          </Card>

          <Card>
            <CardHeader title="Timeline" description="Everything that has happened on this case." />
            <Timeline events={c.events} />
            {canManage && (
              <div className="mt-5">
                <NoteForm caseId={c.id} />
              </div>
            )}
          </Card>
        </div>

        <div className="space-y-6">
          {canManage ? (
            <StatusCard key={`${c.status}-${c.severity}-${c.outcome}`} c={c} />
          ) : (
            <Card>
              <CardHeader title="Status" />
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between gap-3">
                  <dt className="text-muted">Status</dt>
                  <dd>{CASE_STATUS[c.status]?.label ?? c.status}</dd>
                </div>
                {c.outcome && (
                  <div className="flex justify-between gap-3">
                    <dt className="text-muted">Outcome</dt>
                    <dd>{outcomeLabel(c.outcome)}</dd>
                  </div>
                )}
              </dl>
            </Card>
          )}
          <AssigneeCard c={c} canManage={canManage} />
          <Card>
            <CardHeader title="Details" />
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Last updated</dt>
                <dd className="text-right">{timeAgo(c.updated_at)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Linked scans</dt>
                <dd>{c.scan_ids.length}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Linked reports</dt>
                <dd>{c.report_ids.length}</dd>
              </div>
            </dl>
          </Card>
        </div>
      </div>
    </div>
  );
}
