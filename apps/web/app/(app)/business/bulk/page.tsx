"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowRight, Layers, Link2, MessageSquareText, RotateCcw } from "lucide-react";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { NoAccess } from "@/components/business-ui";
import { KindIcon, VerdictBadge } from "@/components/scan-ui";
import { useOrgKey, useSession } from "@/components/session";
import {
  Badge,
  Button,
  Callout,
  Card,
  CardHeader,
  PageHeader,
  Table,
  Td,
  Textarea,
  Th,
  cn,
} from "@/components/ui";
import { api, errorMessage } from "@/lib/api";
import type { Scan } from "@/lib/types";

const MAX_ITEMS = 100;

type BulkKind = "url" | "message";
type BulkOut = { batch_id: string; scan_ids: string[] };
type BatchOut = {
  batch_id: string;
  total: number;
  completed: number;
  failed: number;
  high_risk: number;
  items: Scan[];
};

const isDone = (b: BatchOut | undefined) => !!b && b.completed + b.failed >= b.total;

export default function BulkScanPage() {
  const { can } = useSession();
  const allowed = can("scans:bulk");
  const [kind, setKind] = useState<BulkKind>("url");
  const [text, setText] = useState("");
  const [checkWebsite, setCheckWebsite] = useState(false);
  const [batchId, setBatchId] = useState<string | null>(null);
  const [skipped, setSkipped] = useState(0);

  const lines = text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  const tooMany = lines.length > MAX_ITEMS;

  const submit = useMutation({
    mutationFn: () =>
      api<BulkOut>("/scans/bulk", {
        method: "POST",
        body: {
          items: lines.map((content) => ({ kind, content })),
          check_website: kind === "url" && checkWebsite,
        },
      }),
    onSuccess: (res) => {
      setSkipped(lines.length - res.scan_ids.length);
      setBatchId(res.batch_id);
    },
  });

  const batch = useQuery({
    queryKey: useOrgKey("scans", "batch", batchId),
    queryFn: () => api<BatchOut>(`/scans/batches/${batchId}`),
    enabled: !!batchId,
    refetchInterval: (q) => (isDone(q.state.data) ? false : 1500),
  });

  if (!allowed) return <NoAccess what="bulk scanning" />;

  function reset() {
    setBatchId(null);
    setSkipped(0);
    submit.reset();
  }

  const b = batch.data;
  const done = isDone(b);
  const finished = b ? b.completed + b.failed : 0;
  const pct = b && b.total ? Math.round((finished / b.total) * 100) : 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Bulk scan"
        description="Check up to 100 links or messages at once — useful for reviewing a batch of reported texts or links from a mailbox."
      />

      {!batchId ? (
        <Card>
          <form
            className="space-y-5"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              if (lines.length && !tooMany) submit.mutate();
            }}
          >
            <fieldset>
              <legend className="mb-2 text-sm font-medium text-fg">What are you checking?</legend>
              <div className="inline-flex rounded-[var(--radius-control)] border border-border-strong bg-surface-2 p-1">
                {(
                  [
                    { value: "url", label: "Links", icon: Link2 },
                    { value: "message", label: "Messages", icon: MessageSquareText },
                  ] as const
                ).map((o) => (
                  <label
                    key={o.value}
                    className={cn(
                      "flex cursor-pointer items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                      "has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-primary",
                      kind === o.value ? "bg-surface text-fg shadow-sm" : "text-muted hover:text-fg",
                    )}
                  >
                    <input
                      type="radio"
                      name="bulk-kind"
                      value={o.value}
                      checked={kind === o.value}
                      onChange={() => setKind(o.value)}
                      className="sr-only"
                    />
                    <o.icon className="size-4" aria-hidden />
                    {o.label}
                  </label>
                ))}
              </div>
            </fieldset>

            <div className="space-y-1.5">
              <label htmlFor="bulk-items" className="block text-sm font-medium text-fg">
                {kind === "url" ? "Links" : "Messages"}, one per line
              </label>
              <Textarea
                id="bulk-items"
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={12}
                invalid={tooMany}
                className="font-mono text-[13px]"
                placeholder={
                  kind === "url"
                    ? "https://mtn-momo-verify.example\nbit.ly/abc123\nhttps://gra.gov.gh"
                    : "Your MoMo account has been suspended. Call 0550000000 to reactivate.\nCongratulations! You have won GHS 5,000 in our promo…"
                }
                spellCheck={false}
              />
              <div className="flex flex-wrap items-center justify-between gap-2 text-[13px]">
                <span className={tooMany ? "text-critical-text" : "text-subtle"} role={tooMany ? "alert" : undefined}>
                  {tooMany
                    ? `That's ${lines.length} lines — the limit is ${MAX_ITEMS}. Split them into smaller batches.`
                    : kind === "message"
                      ? "Each line is checked as a separate message. Remove any passwords or PINs first."
                      : "Links aren't opened in your browser."}
                </span>
                <span className={cn("tabular-nums", tooMany ? "text-critical-text" : "text-muted")}>
                  {lines.length} / {MAX_ITEMS}
                </span>
              </div>
            </div>

            {kind === "url" && (
              <label className="flex items-start gap-3 text-sm">
                <input
                  type="checkbox"
                  checked={checkWebsite}
                  onChange={(e) => setCheckWebsite(e.target.checked)}
                  className="mt-0.5 size-4 rounded border-border-strong accent-[var(--primary)]"
                />
                <span>
                  <span className="font-medium text-fg">Visit the websites (slower)</span>
                  <span className="block text-subtle">
                    We safely load each page from our servers to look for login forms, redirects and certificate
                    problems.
                  </span>
                </span>
              </label>
            )}

            {submit.isError && <Callout tone="critical">{errorMessage(submit.error)}</Callout>}

            <div className="flex items-center justify-end gap-3 border-t border-border pt-4">
              <Button type="submit" loading={submit.isPending} disabled={!lines.length || tooMany}>
                <Layers className="size-4" aria-hidden />
                {lines.length ? `Check ${lines.length} ${lines.length === 1 ? "item" : "items"}` : "Check items"}
              </Button>
            </div>
          </form>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader
              title={done ? "Batch complete" : "Checking your items…"}
              description={
                b
                  ? `${finished} of ${b.total} finished${b.high_risk ? ` · ${b.high_risk} high risk` : ""}${b.failed ? ` · ${b.failed} couldn't be checked` : ""}`
                  : "Starting…"
              }
              action={
                <Button variant="secondary" size="sm" onClick={reset} disabled={!done && !batch.isError}>
                  <RotateCcw className="size-4" aria-hidden /> New batch
                </Button>
              }
            />
            <div
              className="h-2 overflow-hidden rounded-full bg-surface-2"
              role="progressbar"
              aria-label="Batch progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={pct}
            >
              <div
                className={cn("h-full rounded-full transition-all duration-500", done ? "bg-success" : "bg-primary")}
                style={{ width: `${pct}%` }}
              />
            </div>
            {skipped > 0 && (
              <p className="mt-3 text-[13px] text-subtle">
                {skipped} {skipped === 1 ? "line was" : "lines were"} skipped because they couldn&apos;t be read as{" "}
                {kind === "url" ? "a link" : "a message"}.
              </p>
            )}
            {batch.isError && (
              <div className="mt-3">
                <Callout tone="critical">{errorMessage(batch.error)}</Callout>
              </div>
            )}
          </Card>

          {b && (
            <Card padded={false}>
              <Table>
                <thead>
                  <tr>
                    <Th>Item</Th>
                    <Th>Result</Th>
                    <Th className="hidden md:table-cell">Summary</Th>
                    <Th>
                      <span className="sr-only">Open</span>
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {b.items.map((s) => (
                    <tr key={s.id}>
                      <Td>
                        <div className="flex min-w-0 items-center gap-2">
                          <KindIcon kind={s.kind} className="size-4 shrink-0 text-subtle" />
                          <span className="max-w-[16rem] truncate font-mono text-[13px] text-fg sm:max-w-sm" title={s.title}>
                            {s.title}
                          </span>
                        </div>
                      </Td>
                      <Td>
                        {s.status === "completed" ? (
                          <VerdictBadge verdict={s.verdict} score={s.risk_score} />
                        ) : s.status === "failed" ? (
                          <Badge tone="neutral">Couldn&apos;t check</Badge>
                        ) : (
                          <Badge tone="info" dot>
                            Checking…
                          </Badge>
                        )}
                      </Td>
                      <Td className="hidden max-w-md truncate text-sm text-muted md:table-cell">
                        {s.status === "failed" ? s.error : (s.headline ?? "")}
                      </Td>
                      <Td className="text-right">
                        {s.status === "completed" && (
                          <Link
                            href={`/scans/${s.id}`}
                            className="inline-flex items-center gap-1 text-sm font-medium whitespace-nowrap text-primary-text hover:underline"
                          >
                            Details <ArrowRight className="size-3.5" aria-hidden />
                          </Link>
                        )}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
