"use client";

import { useQuery } from "@tanstack/react-query";
import { FileWarning } from "lucide-react";
import Link from "next/link";
import { useOrgKey, useSession } from "@/components/session";
import { Badge, ButtonLink, Card, EmptyState, PageHeader, Skeleton } from "@/components/ui";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { REPORT_STATUS } from "@/lib/labels";
import type { ScamReport } from "@/lib/types";

export default function ReportsPage() {
  const { orgId, can } = useSession();
  const { data, isPending } = useQuery({
    queryKey: useOrgKey("reports"),
    queryFn: () => api<ScamReport[]>("/reports"),
  });
  const team = orgId && can("reports:read");
  return (
    <>
      <PageHeader
        title={team ? "Scam reports" : "My reports"}
        description={team ? "Suspected scams reported by people in this workspace." : "Scams you've reported and what happened to them."}
        actions={<ButtonLink href="/report">Report a scam</ButtonLink>}
      />
      <Card padded={false}>
        {isPending ? (
          <div className="space-y-2 p-4">
            <Skeleton className="h-12" />
            <Skeleton className="h-12" />
          </div>
        ) : data && data.length > 0 ? (
          <ul className="divide-y divide-border">
            {data.map((r) => (
              <li key={r.id}>
                <Link href={`/reports/${r.id}`} className="flex items-center gap-3 px-4 py-3 hover:bg-surface-2">
                  <FileWarning className="size-5 shrink-0 text-subtle" aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">
                      {r.category_label}
                      {r.url ? ` · ${r.url}` : r.phone ? ` · ${r.phone}` : r.sender ? ` · ${r.sender}` : ""}
                    </span>
                    <span className="block truncate text-xs text-subtle">
                      {timeAgo(r.created_at)} · {r.description}
                    </span>
                  </span>
                  <Badge tone={REPORT_STATUS[r.status]?.tone}>{REPORT_STATUS[r.status]?.label ?? r.status}</Badge>
                </Link>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState
            icon={<FileWarning className="size-6" />}
            title="No reports yet"
            description="If you receive a scam, report it — verified reports help us warn others."
            action={<ButtonLink href="/report">Report a scam</ButtonLink>}
          />
        )}
      </Card>
    </>
  );
}
