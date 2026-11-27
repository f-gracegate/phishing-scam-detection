"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Download } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useOrgKey } from "@/components/session";
import { Badge, Button, Callout, Card, CardHeader, PageHeader, Skeleton } from "@/components/ui";
import { api, downloadFile, errorMessage } from "@/lib/api";
import { formatDate, formatDateTime } from "@/lib/format";
import { CHANNELS, REPORT_STATUS } from "@/lib/labels";
import type { ScamReport } from "@/lib/types";

const STEPS = ["unverified", "under_review", "verified"];

export default function ReportDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: r, error } = useQuery({
    queryKey: useOrgKey("report", id),
    queryFn: () => api<ScamReport>(`/reports/${id}`),
  });
  const back = (
    <Link href="/reports" className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg">
      <ArrowLeft className="size-4" /> Reports
    </Link>
  );
  if (error) return (<><PageHeader back={back} title="Report" /><Callout tone="critical">{errorMessage(error)}</Callout></>);
  if (!r) return (<><PageHeader back={back} title="Report" /><Skeleton className="h-64" /></>);
  const step = r.status === "rejected" || r.status === "duplicate" ? 2 : STEPS.indexOf(r.status);
  return (
    <>
      <PageHeader back={back} title={r.category_label} description={`Reported ${formatDateTime(r.created_at)}`} />
      <div className="grid max-w-5xl gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <Card>
          <CardHeader title="What you reported" />
          <dl className="divide-y divide-border text-sm">
            <div className="grid grid-cols-[9rem_1fr] gap-3 py-2"><dt className="text-subtle">Channel</dt><dd>{CHANNELS.find((c) => c.value === r.channel)?.label ?? r.channel}</dd></div>
            {r.url && <div className="grid grid-cols-[9rem_1fr] gap-3 py-2"><dt className="text-subtle">Link</dt><dd className="break-all"><code>{r.url}</code></dd></div>}
            {r.phone && <div className="grid grid-cols-[9rem_1fr] gap-3 py-2"><dt className="text-subtle">Phone</dt><dd>{r.phone}</dd></div>}
            {r.sender && <div className="grid grid-cols-[9rem_1fr] gap-3 py-2"><dt className="text-subtle">Sender</dt><dd>{r.sender}</dd></div>}
            {r.occurred_on && <div className="grid grid-cols-[9rem_1fr] gap-3 py-2"><dt className="text-subtle">Date</dt><dd>{formatDate(r.occurred_on)}</dd></div>}
            <div className="grid grid-cols-[9rem_1fr] gap-3 py-2"><dt className="text-subtle">What happened</dt><dd className="whitespace-pre-wrap">{r.description}</dd></div>
          </dl>
          {r.evidence.length > 0 && (
            <div className="mt-4 space-y-2">
              <p className="text-sm font-medium">Attachments</p>
              {r.evidence.map((e) => (
                <Button key={e.id} size="sm" variant="secondary" onClick={() => downloadFile(`/reports/${r.id}/evidence/${e.id}`, e.filename)}>
                  <Download className="size-4" /> {e.filename}
                </Button>
              ))}
            </div>
          )}
        </Card>
        <div className="space-y-4">
          <Card>
            <CardHeader title="Status" />
            <Badge tone={REPORT_STATUS[r.status]?.tone}>{r.status_label}</Badge>
            <ol className="mt-4 space-y-3">
              {["Received", "Being reviewed", r.status === "rejected" ? "Not confirmed" : r.status === "duplicate" ? "Already reported" : "Verified"].map((label, i) => (
                <li key={label} className="flex items-center gap-3 text-sm">
                  <span className={`size-2.5 rounded-full ${i <= step ? "bg-primary" : "bg-border-strong"}`} aria-hidden />
                  <span className={i <= step ? "font-medium" : "text-subtle"}>{label}</span>
                </li>
              ))}
            </ol>
            {r.public_note && <p className="mt-4 rounded-lg bg-surface-2 p-3 text-sm">{r.public_note}</p>}
          </Card>
          <p className="text-xs text-subtle">Unverified reports are never published. Your contact details stay private.</p>
        </div>
      </div>
    </>
  );
}
