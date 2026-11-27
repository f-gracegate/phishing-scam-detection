"use client";

import { useQuery } from "@tanstack/react-query";
import { Lock } from "lucide-react";
import type { ReactNode } from "react";
import { Badge, Card, EmptyState, cn } from "@/components/ui";
import { useOrgKey, useSession } from "@/components/session";
import { api, ApiError } from "@/lib/api";
import { CASE_STATUS, SEVERITY_TONE, type Tone } from "@/lib/labels";
import type { Member } from "@/lib/types";

/** Members of the current workspace (for assignee pickers). */
export function useMembers() {
  const { orgId } = useSession();
  return useQuery({
    queryKey: useOrgKey("members"),
    queryFn: () => api<Member[]>(`/organisations/${orgId}/members`, { org: false }),
    enabled: !!orgId,
  });
}

/** Shown in place of a page when the person's role doesn't include the permission. */
export function NoAccess({ what }: { what: string }) {
  return (
    <Card>
      <EmptyState
        icon={<Lock className="size-5" />}
        title="You don't have access to this"
        description={`Your role doesn't include ${what}. Ask a workspace owner or admin if you need it.`}
      />
    </Card>
  );
}

/** 402 means the current plan doesn't include the feature. */
export function isPlanError(error: unknown): boolean {
  return error instanceof ApiError && error.status === 402;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const tone: Tone = SEVERITY_TONE[severity] ?? "neutral";
  return (
    <Badge tone={tone} dot>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </Badge>
  );
}

export function CaseStatusBadge({ status }: { status: string }) {
  const s = CASE_STATUS[status] ?? { label: status, tone: "neutral" as Tone };
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

export function CodeBlock({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <div className="overflow-hidden rounded-[var(--radius-control)] border border-border bg-surface-2">
      {label && (
        <p className="border-b border-border px-3 py-1.5 text-xs font-medium tracking-wide text-subtle uppercase">
          {label}
        </p>
      )}
      <pre className="overflow-x-auto p-3 font-mono text-[12.5px] leading-relaxed text-fg">
        <code>{children}</code>
      </pre>
    </div>
  );
}

/** A labelled horizontal bar, used for simple ranked lists (categories, domains, verdicts). */
export function BarRow({
  label,
  value,
  max,
  barClass = "bg-primary",
  mono,
}: {
  label: ReactNode;
  value: number;
  max: number;
  barClass?: string;
  mono?: boolean;
}) {
  const pct = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
  return (
    <li className="space-y-1.5">
      <div className="flex items-baseline justify-between gap-3 text-sm">
        <span className={cn("min-w-0 truncate text-fg", mono && "font-mono text-[13px]")}>{label}</span>
        <span className="shrink-0 tabular-nums text-muted">{value.toLocaleString("en-GB")}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-surface-2" aria-hidden>
        <div className={cn("h-full rounded-full", barClass)} style={{ width: `${pct}%` }} />
      </div>
    </li>
  );
}
