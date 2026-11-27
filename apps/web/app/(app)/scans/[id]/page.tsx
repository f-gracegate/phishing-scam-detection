"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ScanResult, ScanResultSkeleton, useScan } from "@/components/scan-ui";
import { Callout, PageHeader } from "@/components/ui";
import { errorMessage } from "@/lib/api";
import { SCAN_KINDS } from "@/lib/labels";

export default function ScanPage() {
  const { id } = useParams<{ id: string }>();
  const { data, error } = useScan(id);
  return (
    <>
      <PageHeader
        back={
          <Link href="/scans" className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg">
            <ArrowLeft className="size-4" /> Scan history
          </Link>
        }
        title={data ? `${SCAN_KINDS[data.kind]} check` : "Result"}
      />
      {error ? <Callout tone="critical">{errorMessage(error)}</Callout> : data ? <ScanResult scan={data} /> : <ScanResultSkeleton />}
    </>
  );
}
