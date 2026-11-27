"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { History } from "lucide-react";
import { useState } from "react";
import { Pager } from "@/components/pager";
import { ScanRow } from "@/components/scan-ui";
import { useOrgKey, useSession } from "@/components/session";
import { ButtonLink, Card, EmptyState, Input, PageHeader, Select, Skeleton } from "@/components/ui";
import { api } from "@/lib/api";
import type { Page, Scan } from "@/lib/types";

const PAGE_SIZE = 20;

export default function ScansPage() {
  const { orgId, can, membership } = useSession();
  const [page, setPage] = useState(1);
  const [kind, setKind] = useState("");
  const [verdict, setVerdict] = useState("");
  const [q, setQ] = useState("");
  const [mine, setMine] = useState(false);
  const key = useOrgKey("scans", { page, kind, verdict, q, mine });
  const { data, isPending } = useQuery({
    queryKey: key,
    queryFn: () => api<Page<Scan>>("/scans", { query: { page, page_size: PAGE_SIZE, kind, verdict, q, mine } }),
    placeholderData: keepPreviousData,
  });
  const seesAll = orgId && can("scans:read_all");
  return (
    <>
      <PageHeader
        title={orgId ? "Workspace scans" : "Scan history"}
        description={
          orgId
            ? seesAll
              ? `Everything checked in ${membership?.organisation_name}.`
              : "The checks you submitted in this workspace."
            : "Your private history. Only you can see it, and you can delete it any time in Settings → Data and privacy."
        }
        actions={<ButtonLink href="/check/link">New check</ButtonLink>}
      />
      <Card padded={false}>
        <div className="flex flex-wrap gap-2 border-b border-border p-3">
          <Input
            placeholder="Search"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setPage(1);
            }}
            className="w-full sm:w-56"
            aria-label="Search scans"
          />
          <Select value={kind} onChange={(e) => (setKind(e.target.value), setPage(1))} aria-label="Type" className="w-auto">
            <option value="">All types</option>
            <option value="url">Links</option>
            <option value="message">Messages</option>
            <option value="email">Emails</option>
            <option value="qr">QR codes</option>
          </Select>
          <Select value={verdict} onChange={(e) => (setVerdict(e.target.value), setPage(1))} aria-label="Result" className="w-auto">
            <option value="">All results</option>
            <option value="high_risk">High or critical risk</option>
            <option value="suspicious">Suspicious</option>
            <option value="caution">Caution</option>
            <option value="unknown">Unknown</option>
            <option value="low">Low risk</option>
          </Select>
          {seesAll && (
            <label className="flex items-center gap-2 px-2 text-sm text-muted">
              <input type="checkbox" checked={mine} onChange={(e) => (setMine(e.target.checked), setPage(1))} /> Only mine
            </label>
          )}
        </div>
        {isPending ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-12" />
            ))}
          </div>
        ) : data && data.items.length > 0 ? (
          <>
            <div className="divide-y divide-border">
              {data.items.map((s) => (
                <ScanRow key={s.id} scan={s} href={`/scans/${s.id}`} />
              ))}
            </div>
            <div className="border-t border-border p-3">
              <Pager page={page} total={data.total} pageSize={PAGE_SIZE} noun={["scan", "scans"]} onPage={setPage} />
            </div>
          </>
        ) : (
          <EmptyState
            icon={<History className="size-6" />}
            title="Nothing checked yet"
            description="Links, messages, emails and QR codes you check appear here."
            action={<ButtonLink href="/check/link">Check a link</ButtonLink>}
          />
        )}
      </Card>
    </>
  );
}
