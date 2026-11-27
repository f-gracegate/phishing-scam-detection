"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, CircleAlert, KeyRound, Pencil, Plus, ShieldCheck, Tag, UserCog } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Dialog } from "@/components/dialog";
import { CONFIDENCE_OPTIONS, INTEL_KEY, IntelGate, splitList } from "@/components/intel-ui";
import { useToast } from "@/components/providers";
import { useSession } from "@/components/session";
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
  Table,
  Td,
  Textarea,
  Th,
} from "@/components/ui";
import { api, ApiError, errorMessage } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { CONFIDENCE } from "@/lib/labels";
import type { Brand, Confidence, IntelSource } from "@/lib/types";

type StaffMember = { id: string; email: string; name: string; role: string };

const SOURCE_KINDS: Record<string, string> = {
  internal: "Internal",
  community: "Community",
  commercial: "Commercial",
  feed: "Open feed",
  external_provider: "External provider",
};

const BRAND_CATEGORIES = [
  { value: "momo", label: "Mobile money" },
  { value: "bank", label: "Bank" },
  { value: "government", label: "Government" },
  { value: "telecom", label: "Telecoms" },
  { value: "delivery", label: "Delivery" },
  { value: "ecommerce", label: "Online shopping" },
  { value: "education", label: "Education" },
  { value: "crypto", label: "Cryptocurrency" },
  { value: "other", label: "Other" },
];
const brandCategoryLabel = (c: string) => BRAND_CATEGORIES.find((x) => x.value === c)?.label ?? c;

const STAFF_ROLES: Record<string, { label: string; hint: string }> = {
  administrator: { label: "Administrator", hint: "Everything, including sources, brands and staff" },
  analyst: { label: "Analyst", hint: "Verifies and publishes indicators, manages campaigns" },
  reviewer: { label: "Reviewer", hint: "Triages reports and disputed results" },
};

// --- Sources -------------------------------------------------------------------------------

function SourceDialog({ source, onClose }: { source: IntelSource; onClose: () => void }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [licence, setLicence] = useState(source.licence);
  const [permittedUse, setPermittedUse] = useState(source.permitted_use);
  const [sharing, setSharing] = useState(source.sharing_restrictions);
  const [confidence, setConfidence] = useState<Confidence>(source.default_confidence);
  const [recheck, setRecheck] = useState(String(source.recheck_days));
  const [recheckError, setRecheckError] = useState<string>();

  const save = useMutation({
    mutationFn: () =>
      api(`/intelligence/sources/${source.code}`, {
        method: "PATCH",
        org: false,
        body: {
          licence: licence.trim(),
          permitted_use: permittedUse.trim(),
          sharing_restrictions: sharing.trim(),
          default_confidence: confidence,
          recheck_days: Number(recheck),
        },
      }),
    onSuccess: () => {
      toast("success", `${source.name} updated.`);
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY, "sources"] });
      onClose();
    },
  });

  return (
    <Dialog
      open
      onClose={onClose}
      wide
      title={`Edit ${source.name}`}
      description="Record the licence terms before enabling a commercial source or feed."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="source-form" loading={save.isPending}>
            Save changes
          </Button>
        </>
      }
    >
      <form
        id="source-form"
        className="space-y-4"
        noValidate
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          const n = Number(recheck);
          if (!Number.isInteger(n) || n < 1 || n > 365) {
            setRecheckError("Between 1 and 365 days.");
            return;
          }
          setRecheckError(undefined);
          save.mutate();
        }}
      >
        {save.isError && <Callout tone="critical">{errorMessage(save.error)}</Callout>}
        <Field label="Licence" htmlFor="src-licence" hint="Licence name, contract reference or terms URL.">
          <Input id="src-licence" value={licence} onChange={(e) => setLicence(e.target.value)} maxLength={300} />
        </Field>
        <Field label="Permitted use" htmlFor="src-use">
          <Textarea id="src-use" value={permittedUse} onChange={(e) => setPermittedUse(e.target.value)} rows={2} maxLength={500} />
        </Field>
        <Field label="Sharing restrictions" htmlFor="src-sharing">
          <Textarea id="src-sharing" value={sharing} onChange={(e) => setSharing(e.target.value)} rows={2} maxLength={500} />
        </Field>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Default confidence" htmlFor="src-confidence">
            <Select id="src-confidence" value={confidence} onChange={(e) => setConfidence(e.target.value as Confidence)}>
              {CONFIDENCE_OPTIONS.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Recheck every (days)" htmlFor="src-recheck" error={recheckError}>
            <Input
              id="src-recheck"
              type="number"
              min={1}
              max={365}
              value={recheck}
              onChange={(e) => setRecheck(e.target.value)}
              invalid={!!recheckError}
            />
          </Field>
        </div>
      </form>
    </Dialog>
  );
}

function SourcesSection({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState<IntelSource | null>(null);
  const [toggleError, setToggleError] = useState<{ code: string; message: string } | null>(null);

  const { data, isPending, error } = useQuery({
    queryKey: [INTEL_KEY, "sources"],
    queryFn: () => api<IntelSource[]>("/intelligence/sources", { org: false }),
  });

  const toggle = useMutation({
    mutationFn: (s: IntelSource) =>
      api<{ code: string; enabled: boolean }>(`/intelligence/sources/${s.code}`, {
        method: "PATCH",
        org: false,
        body: { enabled: !s.enabled },
      }),
    onMutate: () => setToggleError(null),
    onSuccess: (res) => {
      toast("success", res.enabled ? "Source enabled." : "Source disabled.");
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY, "sources"] });
    },
    onError: (err, s) => {
      setToggleError({
        code: s.code,
        message:
          err instanceof ApiError && err.code === "licence_required"
            ? `${err.message} Edit ${s.name} to add it.`
            : errorMessage(err),
      });
    },
  });

  return (
    <Card padded={false}>
      <div className="p-5 pb-0">
        <CardHeader
          title="Intelligence sources"
          description="Where indicators come from. Only use a source within its licence and permitted use."
        />
      </div>
      {toggleError && (
        <div className="px-5 pb-4">
          <Callout tone="critical" icon={<CircleAlert className="size-4" />}>
            {toggleError.message}
          </Callout>
        </div>
      )}
      {error ? (
        <div className="p-5 pt-0">
          <Callout tone="critical">{errorMessage(error)}</Callout>
        </div>
      ) : isPending ? (
        <div className="p-5 pt-0">
          <Skeleton className="h-40" />
        </div>
      ) : !data?.length ? (
        <EmptyState title="No sources configured" />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Source</Th>
              <Th>Licence and permitted use</Th>
              <Th>Credentials</Th>
              <Th className="text-right">Indicators</Th>
              <Th>Last sync</Th>
              <Th>Enabled</Th>
              {isAdmin && <Th className="w-12" />}
            </tr>
          </thead>
          <tbody>
            {data.map((s) => (
              <tr key={s.code} className={toggleError?.code === s.code ? "bg-critical-soft/30" : undefined}>
                <Td>
                  <span className="block font-medium text-fg">{s.name}</span>
                  <span className="text-xs text-subtle">
                    {SOURCE_KINDS[s.kind] ?? s.kind} · {CONFIDENCE[s.default_confidence] ?? s.default_confidence} ·
                    recheck {s.recheck_days}d
                  </span>
                </Td>
                <Td className="max-w-sm text-[13px]">
                  <span className={s.licence ? "block text-fg" : "block text-subtle"}>
                    {s.licence || "No licence recorded"}
                  </span>
                  {s.permitted_use && <span className="line-clamp-2 block text-xs text-muted">{s.permitted_use}</span>}
                  {s.sharing_restrictions && (
                    <span className="line-clamp-1 block text-xs text-subtle">Sharing: {s.sharing_restrictions}</span>
                  )}
                </Td>
                <Td>
                  {s.credentials_configured === null ? (
                    <span className="text-[13px] text-subtle">Not needed</span>
                  ) : s.credentials_configured ? (
                    <Badge tone="success">
                      <KeyRound className="size-3" />
                      Configured
                    </Badge>
                  ) : (
                    <Badge tone="warning">Missing</Badge>
                  )}
                </Td>
                <Td className="text-right tabular-nums">{s.indicators}</Td>
                <Td className="text-[13px] whitespace-nowrap text-muted">
                  {s.last_synced_at ? timeAgo(s.last_synced_at) : "—"}
                </Td>
                <Td>
                  {isAdmin ? (
                    <label className="inline-flex cursor-pointer items-center gap-2">
                      <input
                        type="checkbox"
                        role="switch"
                        aria-label={`${s.enabled ? "Disable" : "Enable"} ${s.name}`}
                        checked={s.enabled}
                        disabled={toggle.isPending}
                        onChange={() => toggle.mutate(s)}
                        className="size-4 accent-[var(--color-primary)]"
                      />
                      <span className="text-[13px] text-muted">{s.enabled ? "On" : "Off"}</span>
                    </label>
                  ) : (
                    <Badge tone={s.enabled ? "success" : "neutral"}>{s.enabled ? "On" : "Off"}</Badge>
                  )}
                </Td>
                {isAdmin && (
                  <Td>
                    <Button variant="ghost" size="sm" onClick={() => setEditing(s)} aria-label={`Edit ${s.name}`}>
                      <Pencil className="size-3.5" />
                    </Button>
                  </Td>
                )}
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {editing && <SourceDialog key={editing.code} source={editing} onClose={() => setEditing(null)} />}
    </Card>
  );
}

// --- Brands --------------------------------------------------------------------------------

function BrandDialog({ brand, onClose }: { brand: Brand | "new"; onClose: () => void }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const existing = brand === "new" ? null : brand;
  const [name, setName] = useState(existing?.name ?? "");
  const [category, setCategory] = useState(existing?.category ?? "bank");
  const [domains, setDomains] = useState((existing?.official_domains ?? []).join("\n"));
  const [keywords, setKeywords] = useState((existing?.keywords ?? []).join(", "));
  const [senderIds, setSenderIds] = useState((existing?.sender_ids ?? []).join(", "));
  const [contact, setContact] = useState(existing?.official_contact ?? "");
  const [verified, setVerified] = useState(existing?.verified ?? false);
  const [active, setActive] = useState(existing?.active ?? true);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const save = useMutation({
    mutationFn: () =>
      api<Brand>(existing ? `/intelligence/brands/${existing.id}` : "/intelligence/brands", {
        method: existing ? "PUT" : "POST",
        org: false,
        body: {
          name: name.trim(),
          category,
          official_domains: splitList(domains, true),
          keywords: splitList(keywords, true),
          sender_ids: splitList(senderIds, true),
          official_contact: contact.trim() || null,
          verified,
          active,
        },
      }),
    onSuccess: () => {
      toast("success", existing ? "Brand updated." : "Brand added.");
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY, "brands"] });
      onClose();
    },
    onError: (err) => {
      if (err instanceof ApiError) setErrors(err.fieldErrors());
    },
  });

  function validate() {
    const e: Record<string, string> = {};
    if (name.trim().length < 2) e.name = "Enter the brand name.";
    const d = splitList(domains, true);
    if (d.length === 0) e.official_domains = "Add at least one official domain.";
    if (d.length > 30) e.official_domains = "Add at most 30 domains.";
    if (splitList(keywords, true).length > 30) e.keywords = "Add at most 30 keywords.";
    if (splitList(senderIds, true).length > 30) e.sender_ids = "Add at most 30 sender IDs.";
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  return (
    <Dialog
      open
      onClose={onClose}
      wide
      title={existing ? `Edit ${existing.name}` : "Add brand"}
      description="Scans compare links and senders against these details to spot impersonation."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="brand-form" loading={save.isPending}>
            {existing ? "Save changes" : "Add brand"}
          </Button>
        </>
      }
    >
      <form
        id="brand-form"
        className="space-y-4"
        noValidate
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          if (validate()) save.mutate();
        }}
      >
        {save.isError && !Object.keys(errors).length && (
          <Callout tone="critical">{errorMessage(save.error)}</Callout>
        )}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-[1fr_12rem]">
          <Field label="Name" htmlFor="br-name" error={errors.name}>
            <Input id="br-name" value={name} onChange={(e) => setName(e.target.value)} invalid={!!errors.name} maxLength={120} />
          </Field>
          <Field label="Category" htmlFor="br-category">
            <Select id="br-category" value={category} onChange={(e) => setCategory(e.target.value)}>
              {BRAND_CATEGORIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
              {!BRAND_CATEGORIES.some((c) => c.value === category) && <option value={category}>{category}</option>}
            </Select>
          </Field>
        </div>
        <Field
          label="Official domains"
          htmlFor="br-domains"
          error={errors.official_domains}
          hint="One per line, without www. Subdomains are covered automatically."
        >
          <Textarea
            id="br-domains"
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
            invalid={!!errors.official_domains}
            rows={3}
            className="font-mono text-xs"
            placeholder="gcbbank.com.gh"
          />
        </Field>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Keywords" htmlFor="br-keywords" optional error={errors.keywords} hint="Comma-separated, at least 3 letters each.">
            <Input id="br-keywords" value={keywords} onChange={(e) => setKeywords(e.target.value)} invalid={!!errors.keywords} />
          </Field>
          <Field label="SMS sender IDs" htmlFor="br-senders" optional error={errors.sender_ids} hint="Comma-separated.">
            <Input id="br-senders" value={senderIds} onChange={(e) => setSenderIds(e.target.value)} invalid={!!errors.sender_ids} />
          </Field>
        </div>
        <Field label="Official contact" htmlFor="br-contact" optional hint="A public customer-service number or page, never a personal number.">
          <Input id="br-contact" value={contact} onChange={(e) => setContact(e.target.value)} maxLength={300} />
        </Field>
        <div className="flex flex-col gap-3 sm:flex-row sm:gap-8">
          <label className="flex cursor-pointer items-start gap-2.5 text-sm">
            <input
              type="checkbox"
              checked={verified}
              onChange={(e) => setVerified(e.target.checked)}
              className="mt-0.5 size-4 accent-[var(--color-primary)]"
            />
            <span>
              <span className="block font-medium text-fg">Verified</span>
              <span className="block text-[13px] text-muted">I checked these domains against the brand&apos;s own channels.</span>
            </span>
          </label>
          <label className="flex cursor-pointer items-start gap-2.5 text-sm">
            <input
              type="checkbox"
              checked={active}
              onChange={(e) => setActive(e.target.checked)}
              className="mt-0.5 size-4 accent-[var(--color-primary)]"
            />
            <span>
              <span className="block font-medium text-fg">Active</span>
              <span className="block text-[13px] text-muted">Used by scans.</span>
            </span>
          </label>
        </div>
      </form>
    </Dialog>
  );
}

function BrandsSection({ isAdmin }: { isAdmin: boolean }) {
  const [editing, setEditing] = useState<Brand | "new" | null>(null);
  const { data, isPending, error } = useQuery({
    queryKey: [INTEL_KEY, "brands"],
    queryFn: () => api<Brand[]>("/intelligence/brands", { org: false }),
  });
  const unverified = data?.filter((b) => !b.verified).length ?? 0;

  return (
    <Card padded={false}>
      <div className="p-5 pb-0">
        <CardHeader
          title="Brand catalogue"
          description="Organisations commonly impersonated in Ghanaian scams."
          action={
            isAdmin && (
              <Button size="sm" onClick={() => setEditing("new")}>
                <Plus className="size-3.5" />
                Add brand
              </Button>
            )
          }
        />
        <div className="mb-4">
          <Callout tone="warning" icon={<Tag className="size-4" />}>
            Catalogue entries start unverified. Check each brand&apos;s official domains and sender IDs against its
            own website or customer service before marking it verified
            {unverified > 0 ? ` — ${unverified} still to check` : ""}.
          </Callout>
        </div>
      </div>
      {error ? (
        <div className="p-5 pt-0">
          <Callout tone="critical">{errorMessage(error)}</Callout>
        </div>
      ) : isPending ? (
        <div className="p-5 pt-0">
          <Skeleton className="h-40" />
        </div>
      ) : !data?.length ? (
        <EmptyState title="The catalogue is empty" />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Brand</Th>
              <Th>Official domains</Th>
              <Th>Keywords</Th>
              <Th>Sender IDs</Th>
              <Th>Status</Th>
              {isAdmin && <Th className="w-12" />}
            </tr>
          </thead>
          <tbody>
            {data.map((b) => (
              <tr key={b.id} className={b.active ? undefined : "opacity-60"}>
                <Td>
                  <span className="block font-medium text-fg">{b.name}</span>
                  <span className="text-xs text-subtle">{brandCategoryLabel(b.category)}</span>
                </Td>
                <Td className="max-w-56 font-mono text-xs text-fg">
                  {b.official_domains.map((d) => (
                    <span key={d} className="block truncate">
                      {d}
                    </span>
                  ))}
                </Td>
                <Td className="max-w-48 text-xs text-muted">{b.keywords.join(", ") || "—"}</Td>
                <Td className="max-w-40 text-xs text-muted">{b.sender_ids.join(", ") || "—"}</Td>
                <Td>
                  <div className="flex flex-col items-start gap-1">
                    {b.verified ? (
                      <Badge tone="success">
                        <BadgeCheck className="size-3" />
                        Verified
                      </Badge>
                    ) : (
                      <Badge tone="warning">Unverified</Badge>
                    )}
                    {!b.active && <Badge tone="neutral">Inactive</Badge>}
                  </div>
                </Td>
                {isAdmin && (
                  <Td>
                    <Button variant="ghost" size="sm" onClick={() => setEditing(b)} aria-label={`Edit ${b.name}`}>
                      <Pencil className="size-3.5" />
                    </Button>
                  </Td>
                )}
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {editing && (
        <BrandDialog key={editing === "new" ? "new" : editing.id} brand={editing} onClose={() => setEditing(null)} />
      )}
    </Card>
  );
}

// --- Staff ---------------------------------------------------------------------------------

function StaffSection() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { me } = useSession();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"analyst" | "reviewer" | "">("reviewer");
  const [emailError, setEmailError] = useState<string>();

  const { data, isPending, error } = useQuery({
    queryKey: [INTEL_KEY, "staff"],
    queryFn: () => api<StaffMember[]>("/intelligence/staff", { org: false }),
  });

  const assign = useMutation({
    mutationFn: (vars: { email: string; role: string }) =>
      api<{ email: string; role: string }>("/intelligence/staff", {
        method: "POST",
        org: false,
        body: vars,
      }),
    onSuccess: (res) => {
      toast("success", res.role ? `${res.email} is now ${STAFF_ROLES[res.role]?.label.toLowerCase() ?? res.role}.` : `${res.email} no longer has an intelligence role.`);
      setEmail("");
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY, "staff"] });
      if (res.email.toLowerCase() === me.user.email.toLowerCase()) {
        queryClient.invalidateQueries({ queryKey: ["me"] });
      }
    },
    onError: (err) => toast("error", errorMessage(err)),
  });

  return (
    <Card padded={false}>
      <div className="p-5 pb-0">
        <CardHeader
          title="Intelligence staff"
          description="Who can use this console. Platform administrators always have full access."
        />
        <form
          className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-[1fr_14rem_auto] sm:items-end"
          noValidate
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (!/^\S+@\S+\.\S+$/.test(email.trim())) {
              setEmailError("Enter the email address of an existing account.");
              return;
            }
            setEmailError(undefined);
            assign.mutate({ email: email.trim(), role });
          }}
        >
          <Field label="Email address" htmlFor="staff-email" error={emailError}>
            <Input
              id="staff-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              invalid={!!emailError}
              placeholder="name@example.com"
            />
          </Field>
          <Field label="Role" htmlFor="staff-role">
            <Select id="staff-role" value={role} onChange={(e) => setRole(e.target.value as typeof role)}>
              <option value="reviewer">Reviewer</option>
              <option value="analyst">Analyst</option>
              <option value="">No role (remove access)</option>
            </Select>
          </Field>
          <Button type="submit" loading={assign.isPending}>
            <UserCog className="size-4" />
            Set role
          </Button>
        </form>
        <p className="mb-4 text-[13px] text-muted">
          {role ? STAFF_ROLES[role].hint : "Removes console access. Administrator access is managed separately."}. The
          person must already have a GraceGate account.
        </p>
      </div>
      {error ? (
        <div className="p-5 pt-0">
          <Callout tone="critical">{errorMessage(error)}</Callout>
        </div>
      ) : isPending ? (
        <div className="p-5 pt-0">
          <Skeleton className="h-32" />
        </div>
      ) : !data?.length ? (
        <EmptyState title="No staff yet" />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Name</Th>
              <Th>Email</Th>
              <Th>Role</Th>
              <Th className="w-40" />
            </tr>
          </thead>
          <tbody>
            {data.map((s) => (
              <tr key={s.id}>
                <Td className="font-medium text-fg">{s.name || "—"}</Td>
                <Td className="text-muted">{s.email}</Td>
                <Td>
                  <Badge tone={s.role === "administrator" ? "primary" : s.role === "analyst" ? "info" : "neutral"}>
                    {STAFF_ROLES[s.role]?.label ?? s.role}
                  </Badge>
                </Td>
                <Td className="text-right">
                  {s.role !== "administrator" && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setEmail(s.email);
                        setRole(s.role === "analyst" ? "reviewer" : "analyst");
                      }}
                    >
                      Change role
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

function SourcesView() {
  const { intel } = useSession();
  const isAdmin = intel("intel:admin");
  return (
    <>
      <PageHeader
        title="Sources & brands"
        description="Intelligence sources and their licences, the brand catalogue used to spot impersonation, and console staff."
        actions={
          !isAdmin && (
            <Badge tone="neutral">
              <ShieldCheck className="size-3" />
              Read only — platform administrators can make changes
            </Badge>
          )
        }
      />
      <div className="space-y-6">
        <SourcesSection isAdmin={isAdmin} />
        <BrandsSection isAdmin={isAdmin} />
        {isAdmin && <StaffSection />}
      </div>
    </>
  );
}

export default function SourcesPage() {
  return (
    <IntelGate>
      <SourcesView />
    </IntelGate>
  );
}
