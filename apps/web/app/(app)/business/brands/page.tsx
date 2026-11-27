"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, Globe, ShieldCheck, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { NoAccess } from "@/components/business-ui";
import { Dialog } from "@/components/dialog";
import { useToast } from "@/components/providers";
import { useOrgKey, useSession } from "@/components/session";
import {
  Badge,
  Button,
  Callout,
  Card,
  CardHeader,
  EmptyState,
  Field,
  Input,
  PageHeader,
  Select,
  Skeleton,
} from "@/components/ui";
import { api, ApiError, errorMessage } from "@/lib/api";
import type { Brand } from "@/lib/types";

const BRAND_CATEGORIES = [
  { value: "bank", label: "Bank or financial services" },
  { value: "momo", label: "Mobile money" },
  { value: "telecom", label: "Telecoms" },
  { value: "ecommerce", label: "Shop or ecommerce" },
  { value: "delivery", label: "Delivery or logistics" },
  { value: "education", label: "School or university" },
  { value: "healthcare", label: "Healthcare" },
  { value: "government", label: "Government or public body" },
  { value: "other", label: "Other" },
];
const categoryName = (v: string) => BRAND_CATEGORIES.find((c) => c.value === v)?.label ?? v;

const MAX_BRANDS = 20;

const splitList = (v: string) =>
  v
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);

function AddBrandForm({ disabled }: { disabled: boolean }) {
  const queryClient = useQueryClient();
  const orgKey = useOrgKey();
  const toast = useToast();
  const [name, setName] = useState("");
  const [category, setCategory] = useState("other");
  const [domains, setDomains] = useState("");
  const [keywords, setKeywords] = useState("");
  const [senderIds, setSenderIds] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});

  const add = useMutation({
    mutationFn: () =>
      api<Brand>("/business/brands", {
        method: "POST",
        body: {
          name: name.trim(),
          category,
          official_domains: splitList(domains),
          keywords: splitList(keywords),
          sender_ids: splitList(senderIds),
        },
      }),
    onSuccess: (b) => {
      queryClient.invalidateQueries({ queryKey: [...orgKey, "business", "brands"] });
      toast("success", `${b.name} is now protected.`);
      setName("");
      setCategory("other");
      setDomains("");
      setKeywords("");
      setSenderIds("");
      setErrors({});
    },
    onError: (err) => {
      if (err instanceof ApiError) setErrors(err.fieldErrors());
    },
  });

  const hasFieldError = Object.keys(errors).length > 0;
  const canSubmit = name.trim().length >= 2 && splitList(domains).length > 0 && !disabled;

  return (
    <Card>
      <CardHeader title="Protect a brand" description="Add your organisation's name and the domains you really use." />
      <form
        className="space-y-4"
        noValidate
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          setErrors({});
          add.mutate();
        }}
      >
        {add.isError && !hasFieldError && <Callout tone="critical">{errorMessage(add.error)}</Callout>}
        {disabled && (
          <Callout tone="warning">You&apos;ve reached the limit of {MAX_BRANDS} protected brands.</Callout>
        )}
        <Field label="Brand name" htmlFor="brand-name" error={errors.name}>
          <Input
            id="brand-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Kumasi Savings & Loans"
            invalid={!!errors.name}
            maxLength={120}
          />
        </Field>
        <Field label="Category" htmlFor="brand-category" error={errors.category}>
          <Select id="brand-category" value={category} onChange={(e) => setCategory(e.target.value)}>
            {BRAND_CATEGORIES.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field
          label="Official domains"
          htmlFor="brand-domains"
          error={errors.official_domains}
          hint="Separate with commas, e.g. kumasisavings.com.gh, kss.com"
        >
          <Input
            id="brand-domains"
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
            invalid={!!errors.official_domains}
            spellCheck={false}
            autoCapitalize="none"
          />
        </Field>
        <Field
          label="Keywords"
          htmlFor="brand-keywords"
          error={errors.keywords}
          optional
          hint="Words scammers might use in look-alike domains or messages. At least 3 letters each."
        >
          <Input
            id="brand-keywords"
            value={keywords}
            onChange={(e) => setKeywords(e.target.value)}
            placeholder="e.g. kumasisavings, kss"
            spellCheck={false}
            autoCapitalize="none"
          />
        </Field>
        <Field
          label="SMS sender IDs"
          htmlFor="brand-senders"
          error={errors.sender_ids}
          optional
          hint="The names your real text messages come from."
        >
          <Input
            id="brand-senders"
            value={senderIds}
            onChange={(e) => setSenderIds(e.target.value)}
            placeholder="e.g. KSSavings"
            spellCheck={false}
          />
        </Field>
        <Button type="submit" className="w-full" loading={add.isPending} disabled={!canSubmit}>
          <ShieldCheck className="size-4" aria-hidden /> Protect brand
        </Button>
      </form>
    </Card>
  );
}

function BrandItem({ b, canManage }: { b: Brand; canManage: boolean }) {
  const queryClient = useQueryClient();
  const orgKey = useOrgKey();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);

  const remove = useMutation({
    mutationFn: () => api(`/business/brands/${b.id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [...orgKey, "business", "brands"] });
      toast("success", `${b.name} removed.`);
      setConfirm(false);
    },
    onError: (err) => toast("error", errorMessage(err)),
  });

  return (
    <li className="space-y-3 p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="flex flex-wrap items-center gap-2 font-medium text-fg">
            {b.name}
            {b.verified && (
              <Badge tone="success">
                <BadgeCheck className="size-3" aria-hidden /> Verified
              </Badge>
            )}
            {!b.active && <Badge tone="neutral">Inactive</Badge>}
          </p>
          <p className="text-xs text-subtle">{categoryName(b.category)}</p>
        </div>
        {canManage && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setConfirm(true)}
            aria-label={`Remove ${b.name}`}
            className="text-critical-text"
          >
            <Trash2 className="size-4" aria-hidden />
          </Button>
        )}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {b.official_domains.map((d) => (
          <span
            key={d}
            className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-2 py-0.5 font-mono text-xs text-fg"
          >
            <Globe className="size-3 text-subtle" aria-hidden /> {d}
          </span>
        ))}
      </div>
      {(b.keywords.length > 0 || b.sender_ids.length > 0) && (
        <dl className="grid gap-1 text-xs sm:grid-cols-[auto_1fr] sm:gap-x-3">
          {b.keywords.length > 0 && (
            <>
              <dt className="text-subtle">Keywords</dt>
              <dd className="text-muted">{b.keywords.join(", ")}</dd>
            </>
          )}
          {b.sender_ids.length > 0 && (
            <>
              <dt className="text-subtle">Sender IDs</dt>
              <dd className="text-muted">{b.sender_ids.join(", ")}</dd>
            </>
          )}
        </dl>
      )}
      <Dialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title={`Stop protecting ${b.name}?`}
        description="New scans in this workspace will no longer check for look-alikes of this brand. Past results won't change."
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
              Remove brand
            </Button>
          </>
        }
      >
        <p className="text-sm text-muted">{b.official_domains.join(", ")}</p>
      </Dialog>
    </li>
  );
}

export default function BrandsPage() {
  const { can } = useSession();
  const allowed = can("analytics:read") || can("brands:manage");
  const canManage = can("brands:manage");

  const { data, isPending, isError, error } = useQuery({
    queryKey: useOrgKey("business", "brands"),
    queryFn: () => api<Brand[]>("/business/brands"),
    enabled: allowed,
  });

  if (!allowed) return <NoAccess what="protected brands" />;

  const list = (
    <Card padded={false} className={canManage ? "lg:col-span-3" : undefined}>
      <div className="p-5 pb-0">
        <CardHeader
          title="Protected brands"
          description={data ? `${data.length} of ${MAX_BRANDS}` : undefined}
        />
      </div>
      {isPending ? (
        <div className="space-y-2 p-5">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      ) : isError ? (
        <div className="p-5">
          <Callout tone="critical">{errorMessage(error)}</Callout>
        </div>
      ) : !data.length ? (
        <EmptyState
          icon={<ShieldCheck className="size-5" />}
          title="No protected brands yet"
          description={
            canManage
              ? "Add your organisation's name and official domains to catch look-alikes."
              : "An admin can add your organisation's name and official domains here."
          }
        />
      ) : (
        <ul className="divide-y divide-border border-t border-border">
          {data.map((b) => (
            <BrandItem key={b.id} b={b} canManage={canManage} />
          ))}
        </ul>
      )}
    </Card>
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Protected brands"
        description="Tell us which names and domains belong to your organisation. Scans in this workspace will then flag look-alike domains (like yourbank-verify.com) and messages that use your name but link somewhere else."
      />
      <Callout tone="info" icon={<ShieldCheck className="size-4" />}>
        Well-known Ghanaian banks, mobile money services and government bodies are already protected for everyone.
        Add your own brand here so impersonation of your organisation is caught too.
      </Callout>
      {canManage ? (
        <div className="grid items-start gap-6 lg:grid-cols-5">
          {list}
          <div className="lg:col-span-2">
            <AddBrandForm disabled={(data?.length ?? 0) >= MAX_BRANDS} />
          </div>
        </div>
      ) : (
        list
      )}
    </div>
  );
}
