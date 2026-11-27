"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Building2, ChevronRight, Inbox } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { INTEL_KEY, IntelGate, ReportStatusBadge } from "@/components/intel-ui";
import { Pager } from "@/components/pager";
import {
  Badge,
  Callout,
  Card,
  EmptyState,
  PageHeader,
  Select,
  Skeleton,
  Table,
  Td,
  Th,
} from "@/components/ui";
import { api, errorMessage } from "@/lib/api";
import { formatDateTime, timeAgo } from "@/lib/format";
import { CHANNELS, SCAM_CATEGORIES } from "@/lib/labels";
import type { Page, QueueReport } from "@/lib/types";

const PAGE_SIZE = 25;
const STATUSES = [
  { value: "open", label: "Open (unverified or under review)" },
  { value: "verified", label: "Verified" },
  { value: "rejected", label: "Rejected" },
  { value: "duplicate", label: "Duplicate" },
  { value: "all", label: "All reports" },
];

const channelLabel = (c: string) => CHANNELS.find((x) => x.value === c)?.label ?? c;

function QueueView() {
  const router = useRouter();
  const [status, setStatus] = useState("open");
  const [category, setCategory] = useState("");
  const [page, setPage] = useState(1);

  const { data, isPending, error } = useQuery({
    queryKey: [INTEL_KEY, "reports", { status, category, page }],
    queryFn: () =>
      api<Page<QueueReport>>("/intelligence/reports", {
        org: false,
        query: { status, category, page, page_size: PAGE_SIZE },
      }),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader
        title="Report queue"
        description="Community scam reports, oldest first. Open a report to see the full details, check for duplicates and decide."
      />
      <Card padded={false}>
        <div className="flex flex-col gap-3 border-b border-border p-4 sm:flex-row">
          <Select
            aria-label="Filter by status"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(1);
            }}
            className="sm:w-72"
          >
            {STATUSES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </Select>
          <Select
            aria-label="Filter by category"
            value={category}
            onChange={(e) => {
              setCategory(e.target.value);
              setPage(1);
            }}
            className="sm:w-64"
          >
            <option value="">All categories</option>
            {SCAM_CATEGORIES.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </Select>
        </div>
        {error ? (
          <div className="p-4">
            <Callout tone="critical">{errorMessage(error)}</Callout>
          </div>
        ) : isPending ? (
          <div className="p-4">
            <Skeleton className="h-64" />
          </div>
        ) : !data?.items.length ? (
          <EmptyState
            icon={<Inbox className="size-5" />}
            title={status === "open" ? "The queue is clear" : "No matching reports"}
            description={status === "open" ? "No reports are waiting for review." : undefined}
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Received</Th>
                  <Th>Category</Th>
                  <Th>Reported</Th>
                  <Th>Description</Th>
                  <Th>Status</Th>
                  <Th className="w-8" />
                </tr>
              </thead>
              <tbody>
                {data.items.map((r) => (
                  <tr
                    key={r.id}
                    className="cursor-pointer hover:bg-surface-2/50"
                    onClick={() => router.push(`/intel/queue/${r.id}`)}
                  >
                    <Td className="whitespace-nowrap">
                      <span className="block text-fg" title={formatDateTime(r.created_at)}>
                        {timeAgo(r.created_at)}
                      </span>
                      <span className="block text-xs text-subtle">{channelLabel(r.channel)}</span>
                    </Td>
                    <Td className="whitespace-nowrap">
                      <span className="block text-fg">{r.category_label}</span>
                      <span className="mt-1 flex gap-1">
                        {r.money_lost && <Badge tone="critical">Money lost</Badge>}
                        {r.organisation_report && (
                          <Badge tone="info">
                            <Building2 className="size-3" />
                            Business
                          </Badge>
                        )}
                      </span>
                    </Td>
                    <Td className="max-w-56 text-[13px]">
                      {r.url && <span className="block truncate font-mono text-xs text-fg">{r.url}</span>}
                      {r.phone && <span className="block font-mono text-xs text-fg">{r.phone}</span>}
                      {r.sender && <span className="block truncate text-xs text-muted">From: {r.sender}</span>}
                      {!r.url && !r.phone && !r.sender && <span className="text-subtle">—</span>}
                    </Td>
                    <Td className="max-w-md">
                      <Link
                        href={`/intel/queue/${r.id}`}
                        className="line-clamp-2 text-[13px] text-muted hover:text-fg"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {r.description}
                      </Link>
                    </Td>
                    <Td>
                      <ReportStatusBadge status={r.status} />
                    </Td>
                    <Td>
                      <ChevronRight className="size-4 text-subtle" />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pager page={page} total={data.total} pageSize={PAGE_SIZE} noun={["report", "reports"]} onPage={setPage} />
          </>
        )}
      </Card>
    </>
  );
}

export default function QueuePage() {
  return (
    <IntelGate>
      <QueueView />
    </IntelGate>
  );
}
