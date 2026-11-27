"use client";

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronRight, Database, Plus, Search, ShieldAlert, X } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { Dialog } from "@/components/dialog";
import {
  CONFIDENCE_OPTIONS,
  ConfidenceBadge,
  INDICATOR_TYPES,
  INTEL_KEY,
  IndicatorStatusBadge,
  IntelGate,
  indicatorTypeLabel,
  splitList,
  useCampaigns,
} from "@/components/intel-ui";
import { Pager } from "@/components/pager";
import { useToast } from "@/components/providers";
import { useSession } from "@/components/session";
import {
  Button,
  Callout,
  Card,
  EmptyState,
  Field,
  Input,
  PageHeader,
  Select,
  Skeleton,
  Table,
  Td,
  Textarea,
  Th,
} from "@/components/ui";
import { api, ApiError, errorMessage } from "@/lib/api";
import { formatDate, timeAgo } from "@/lib/format";
import { INDICATOR_STATUS, SCAM_CATEGORIES } from "@/lib/labels";
import type { Confidence, Indicator, Page } from "@/lib/types";

const PAGE_SIZE = 25;

function AddIndicatorDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { intel } = useSession();
  const canPublish = intel("intel:publish");
  const router = useRouter();
  const queryClient = useQueryClient();
  const toast = useToast();
  const { data: campaigns } = useCampaigns(open);

  const [type, setType] = useState("domain");
  const [value, setValue] = useState("");
  const [category, setCategory] = useState("");
  const [evidence, setEvidence] = useState("");
  const [references, setReferences] = useState("");
  const [confidence, setConfidence] = useState<Confidence>("medium");
  const [disposition, setDisposition] = useState("malicious");
  const [status, setStatus] = useState<"unverified" | "verified">("unverified");
  const [campaignId, setCampaignId] = useState("");
  const [expires, setExpires] = useState("180");
  const [errors, setErrors] = useState<Record<string, string>>({});

  const create = useMutation({
    mutationFn: () =>
      api<Indicator>("/intelligence/indicators", {
        method: "POST",
        org: false,
        body: {
          type,
          value: value.trim(),
          category: category || null,
          evidence_summary: evidence.trim(),
          references: splitList(references),
          confidence,
          disposition,
          status,
          campaign_id: campaignId || null,
          expires_in_days: Number(expires),
        },
      }),
    onSuccess: (ind) => {
      toast("success", status === "verified" ? "Indicator published as verified." : "Indicator added for review.");
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY] });
      close();
      router.push(`/intel/indicators/${ind.id}`);
    },
    onError: (err) => {
      if (err instanceof ApiError) setErrors(err.fieldErrors());
    },
  });

  function close() {
    setType("domain");
    setValue("");
    setCategory("");
    setEvidence("");
    setReferences("");
    setConfidence("medium");
    setDisposition("malicious");
    setStatus("unverified");
    setCampaignId("");
    setExpires("180");
    setErrors({});
    create.reset();
    onClose();
  }

  function validate() {
    const e: Record<string, string> = {};
    if (!value.trim()) e.value = "Enter the value.";
    if (evidence.trim().length < 10) e.evidence_summary = "Summarise the evidence (at least 10 characters).";
    if (splitList(references).length > 20) e.references = "Add at most 20 references.";
    const n = Number(expires);
    if (!Number.isInteger(n) || n < 1 || n > 730) e.expires_in_days = "Between 1 and 730 days.";
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  const placeholder = INDICATOR_TYPES.find((t) => t.value === type)?.placeholder;

  return (
    <Dialog
      open={open}
      onClose={close}
      wide
      title="Add indicator"
      description="Record a phishing or scam indicator found outside the community queue."
      footer={
        <>
          <Button variant="secondary" onClick={close}>
            Cancel
          </Button>
          <Button type="submit" form="add-indicator" loading={create.isPending}>
            {status === "verified" ? "Add and publish" : "Add indicator"}
          </Button>
        </>
      }
    >
      <form
        id="add-indicator"
        className="space-y-4"
        noValidate
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          if (validate()) create.mutate();
        }}
      >
        {create.isError && !Object.keys(errors).length && (
          <Callout tone="critical">{errorMessage(create.error)}</Callout>
        )}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-[12rem_1fr]">
          <Field label="Type" htmlFor="ai-type">
            <Select id="ai-type" value={type} onChange={(e) => setType(e.target.value)}>
              {INDICATOR_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Value" htmlFor="ai-value" error={errors.value} hint="Normalised automatically (for example, phone numbers to +233).">
            <Input
              id="ai-value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={placeholder}
              invalid={!!errors.value}
              className="font-mono"
              maxLength={2048}
            />
          </Field>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Field label="Category" htmlFor="ai-category" optional>
            <Select id="ai-category" value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">Not set</option>
              {SCAM_CATEGORIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Disposition" htmlFor="ai-disposition">
            <Select id="ai-disposition" value={disposition} onChange={(e) => setDisposition(e.target.value)}>
              <option value="malicious">Malicious</option>
              <option value="suspicious">Suspicious</option>
            </Select>
          </Field>
          <Field label="Campaign" htmlFor="ai-campaign" optional>
            <Select id="ai-campaign" value={campaignId} onChange={(e) => setCampaignId(e.target.value)}>
              <option value="">No campaign</option>
              {(campaigns ?? []).map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <Field label="Evidence summary" htmlFor="ai-evidence" error={errors.evidence_summary} hint="What you saw and why it's malicious. Staff only.">
          <Textarea
            id="ai-evidence"
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
            invalid={!!errors.evidence_summary}
            rows={3}
            maxLength={5000}
          />
        </Field>
        <Field label="References" htmlFor="ai-refs" optional error={errors.references} hint="One per line: links to screenshots, partner reports, takedown tickets.">
          <Textarea
            id="ai-refs"
            value={references}
            onChange={(e) => setReferences(e.target.value)}
            rows={3}
            className="font-mono text-xs"
          />
        </Field>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Field label="Status" htmlFor="ai-status" hint={canPublish ? undefined : "Only analysts can publish verified indicators."}>
            <Select id="ai-status" value={status} onChange={(e) => setStatus(e.target.value as "unverified" | "verified")}>
              <option value="unverified">Unverified</option>
              <option value="verified" disabled={!canPublish}>
                Verified (publish)
              </option>
            </Select>
          </Field>
          <Field label="Confidence" htmlFor="ai-confidence">
            <Select id="ai-confidence" value={confidence} onChange={(e) => setConfidence(e.target.value as Confidence)}>
              {CONFIDENCE_OPTIONS.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Expires in (days)" htmlFor="ai-expires" error={errors.expires_in_days}>
            <Input
              id="ai-expires"
              type="number"
              min={1}
              max={730}
              value={expires}
              onChange={(e) => setExpires(e.target.value)}
              invalid={!!errors.expires_in_days}
            />
          </Field>
        </div>
        {status === "verified" && (
          <Callout tone="critical" icon={<ShieldAlert className="size-4" />} title="Publishes to every scan">
            A verified indicator is flagged in every scan on the platform straight away. Only publish when the
            evidence is solid.
          </Callout>
        )}
      </form>
    </Dialog>
  );
}

function IndicatorsView() {
  const router = useRouter();
  const params = useSearchParams();
  const { intel } = useSession();
  const [q, setQ] = useState(params.get("q") ?? "");
  const [search, setSearch] = useState(params.get("q") ?? "");
  const [type, setType] = useState(params.get("type") ?? "");
  const [status, setStatus] = useState(params.get("status") ?? "");
  const [category, setCategory] = useState(params.get("category") ?? "");
  const [campaignId, setCampaignId] = useState(params.get("campaign_id") ?? "");
  const [page, setPage] = useState(1);
  const [adding, setAdding] = useState(false);

  // Debounce the free-text search.
  useEffect(() => {
    const t = setTimeout(() => {
      setSearch(q.trim());
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [q]);

  const { data, isPending, error } = useQuery({
    queryKey: [INTEL_KEY, "indicators", { search, type, status, category, campaignId, page }],
    queryFn: () =>
      api<Page<Indicator>>("/intelligence/indicators", {
        org: false,
        query: { q: search, type, status, category, campaign_id: campaignId, page, page_size: PAGE_SIZE },
      }),
    placeholderData: keepPreviousData,
  });

  const filtered = Boolean(search || type || status || category || campaignId);
  const { data: campaigns } = useCampaigns(Boolean(campaignId));
  const campaignName = campaigns?.find((c) => c.id === campaignId)?.name;

  return (
    <>
      <PageHeader
        title="Indicators"
        description="Links, domains, phone numbers and other values linked to scams. Verified indicators are flagged in every scan."
        actions={
          intel("intel:review") && (
            <Button onClick={() => setAdding(true)}>
              <Plus className="size-4" />
              Add indicator
            </Button>
          )
        }
      />
      <Card padded={false}>
        <div className="grid grid-cols-1 gap-3 border-b border-border p-4 md:grid-cols-[1fr_11rem_11rem_13rem]">
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-subtle" />
            <Input
              aria-label="Search indicators"
              placeholder="Search by link, domain, phone or email"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              className="pl-9"
            />
          </div>
          <Select
            aria-label="Filter by type"
            value={type}
            onChange={(e) => {
              setType(e.target.value);
              setPage(1);
            }}
          >
            <option value="">All types</option>
            {INDICATOR_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </Select>
          <Select
            aria-label="Filter by status"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(1);
            }}
          >
            <option value="">All statuses</option>
            {Object.entries(INDICATOR_STATUS).map(([v, s]) => (
              <option key={v} value={v}>
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
          >
            <option value="">All categories</option>
            {SCAM_CATEGORIES.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </Select>
        </div>
        {campaignId && (
          <div className="flex items-center gap-2 border-b border-border px-4 py-2.5 text-sm">
            <span className="text-muted">Campaign:</span>
            <span className="font-medium text-fg">{campaignName ?? "Selected campaign"}</span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setCampaignId("");
                setPage(1);
              }}
            >
              <X className="size-3.5" />
              Clear
            </Button>
          </div>
        )}
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
            icon={<Database className="size-5" />}
            title={filtered ? "No matching indicators" : "No indicators yet"}
            description={filtered ? "Try a different search or clear the filters." : undefined}
          />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Indicator</Th>
                  <Th>Status</Th>
                  <Th>Category</Th>
                  <Th className="text-right">Reports</Th>
                  <Th>Source</Th>
                  <Th>Last seen</Th>
                  <Th>Expires</Th>
                  <Th className="w-8" />
                </tr>
              </thead>
              <tbody>
                {data.items.map((i) => (
                  <tr
                    key={i.id}
                    className="cursor-pointer hover:bg-surface-2/50"
                    onClick={() => router.push(`/intel/indicators/${i.id}`)}
                  >
                    <Td className="max-w-sm">
                      <Link
                        href={`/intel/indicators/${i.id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="block truncate font-mono text-xs text-fg hover:underline"
                        title={i.display_value}
                      >
                        {i.display_value}
                      </Link>
                      <span className="text-xs text-subtle">{indicatorTypeLabel(i.type)}</span>
                    </Td>
                    <Td>
                      <div className="flex flex-col items-start gap-1">
                        <IndicatorStatusBadge status={i.status} />
                        <ConfidenceBadge confidence={i.confidence} />
                      </div>
                    </Td>
                    <Td className="text-[13px] text-muted">{i.category_label ?? "—"}</Td>
                    <Td className="text-right tabular-nums">{i.report_count}</Td>
                    <Td className="text-[13px] text-muted">{i.source ?? "—"}</Td>
                    <Td className="text-[13px] whitespace-nowrap text-muted">{timeAgo(i.last_seen_at)}</Td>
                    <Td className="text-[13px] whitespace-nowrap text-muted">{formatDate(i.expires_at)}</Td>
                    <Td>
                      <ChevronRight className="size-4 text-subtle" />
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pager page={page} total={data.total} pageSize={PAGE_SIZE} noun={["indicator", "indicators"]} onPage={setPage} />
          </>
        )}
      </Card>
      <AddIndicatorDialog open={adding} onClose={() => setAdding(false)} />
    </>
  );
}

export default function IndicatorsPage() {
  return (
    <IntelGate>
      <IndicatorsView />
    </IntelGate>
  );
}
