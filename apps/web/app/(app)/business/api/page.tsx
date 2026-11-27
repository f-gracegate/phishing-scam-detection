"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useMemo, useState, useSyncExternalStore, type FormEvent } from "react";
import { CodeBlock, NoAccess, isPlanError } from "@/components/business-ui";
import { CopyField } from "@/components/copy-field";
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
  Table,
  Td,
  Th,
} from "@/components/ui";
import { api, ApiError, errorMessage } from "@/lib/api";
import { formatDate, timeAgo } from "@/lib/format";
import type { ApiKey } from "@/lib/types";

type Usage = {
  plan: string;
  monthly_scans: number | null;
  scans_this_month: number;
  api: { day: string; endpoint: string; quantity: number }[];
  api_total: number;
};

const EXPIRY = [
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
  { value: "730", label: "2 years" },
  { value: "", label: "Never" },
];

const n = (v: number) => v.toLocaleString("en-GB");

const noopSubscribe = () => () => {};
function useOrigin() {
  return useSyncExternalStore(
    noopSubscribe,
    () => window.location.origin,
    () => "https://<host>",
  );
}

function keyState(k: ApiKey): { label: string; tone: "success" | "neutral" | "warning" } {
  if (k.status === "revoked" || k.revoked_at) return { label: "Revoked", tone: "neutral" };
  if (k.expires_at && new Date(k.expires_at).getTime() < Date.now()) return { label: "Expired", tone: "warning" };
  return { label: "Active", tone: "success" };
}

function CreateKeyDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const orgKey = useOrgKey();
  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState("365");
  const [created, setCreated] = useState<ApiKey | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const create = useMutation({
    mutationFn: () =>
      api<ApiKey>("/business/api-keys", {
        method: "POST",
        body: { name: name.trim(), expires_in_days: expiry ? Number(expiry) : null },
      }),
    onSuccess: (key) => {
      setCreated(key);
      queryClient.invalidateQueries({ queryKey: [...orgKey, "business", "api-keys"] });
    },
    onError: (err) => {
      if (err instanceof ApiError) setErrors(err.fieldErrors());
    },
  });

  function close() {
    setName("");
    setExpiry("365");
    setCreated(null);
    setErrors({});
    create.reset();
    onClose();
  }

  return (
    <Dialog
      open={open}
      onClose={close}
      title={created ? "Your new API key" : "Create an API key"}
      description={
        created
          ? `“${created.name}” is ready. Copy the key now and store it somewhere safe, such as a secrets manager.`
          : "Keys let your own systems submit links and messages for checking."
      }
      footer={
        created ? (
          <Button onClick={close}>I&apos;ve saved it</Button>
        ) : (
          <>
            <Button variant="secondary" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" form="create-key-form" loading={create.isPending} disabled={name.trim().length < 2}>
              Create key
            </Button>
          </>
        )
      }
    >
      {created?.secret ? (
        <div className="space-y-4">
          <CopyField label="API key" value={created.secret} />
          <Callout tone="warning" icon={<TriangleAlert className="size-4" />} title="You won't see this key again">
            We only store a fingerprint of it. If you lose it, revoke it and create a new one. Never put it in
            front-end code or share it in chat.
          </Callout>
        </div>
      ) : (
        <form
          id="create-key-form"
          className="space-y-4"
          noValidate
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            setErrors({});
            create.mutate();
          }}
        >
          {create.isError && !errors.name && (
            <Callout tone={isPlanError(create.error) ? "warning" : "critical"}>
              {errorMessage(create.error)}
              {isPlanError(create.error) && (
                <>
                  {" "}
                  <Link href="/settings/subscription" className="font-medium underline">
                    See plans
                  </Link>
                </>
              )}
            </Callout>
          )}
          <Field label="Name" htmlFor="key-name" error={errors.name} hint="So you can tell your keys apart, e.g. “Helpdesk integration”.">
            <Input
              id="key-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              invalid={!!errors.name}
              maxLength={100}
              autoFocus
            />
          </Field>
          <Field label="Expires after" htmlFor="key-expiry" error={errors.expires_in_days}>
            <Select id="key-expiry" value={expiry} onChange={(e) => setExpiry(e.target.value)}>
              {EXPIRY.map((x) => (
                <option key={x.label} value={x.value}>
                  {x.label}
                </option>
              ))}
            </Select>
          </Field>
        </form>
      )}
    </Dialog>
  );
}

function KeyRow({ k }: { k: ApiKey }) {
  const queryClient = useQueryClient();
  const orgKey = useOrgKey();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  const state = keyState(k);

  const revoke = useMutation({
    mutationFn: () => api<ApiKey>(`/business/api-keys/${k.id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [...orgKey, "business", "api-keys"] });
      toast("success", `“${k.name}” revoked.`);
      setConfirm(false);
    },
    onError: (err) => toast("error", errorMessage(err)),
  });

  return (
    <tr className={state.label === "Active" ? undefined : "opacity-60"}>
      <Td>
        <p className="font-medium text-fg">{k.name}</p>
        <p className="font-mono text-xs text-subtle">{k.prefix}…</p>
      </Td>
      <Td>
        <Badge tone={state.tone}>{state.label}</Badge>
      </Td>
      <Td className="text-sm whitespace-nowrap text-muted">{k.last_used_at ? timeAgo(k.last_used_at) : "Never"}</Td>
      <Td className="text-sm whitespace-nowrap text-muted">{k.expires_at ? formatDate(k.expires_at) : "Never"}</Td>
      <Td className="text-right">
        {state.label !== "Revoked" && (
          <Button variant="ghost" size="sm" onClick={() => setConfirm(true)} className="text-critical-text">
            Revoke
          </Button>
        )}
        <Dialog
          open={confirm}
          onClose={() => setConfirm(false)}
          title="Revoke this API key?"
          description={`Anything using “${k.name}” will stop working straight away. This can't be undone.`}
          footer={
            <>
              <Button variant="secondary" onClick={() => setConfirm(false)}>
                Cancel
              </Button>
              <Button variant="danger" loading={revoke.isPending} onClick={() => revoke.mutate()}>
                Revoke key
              </Button>
            </>
          }
        >
          <p className="font-mono text-sm text-muted">{k.prefix}…</p>
        </Dialog>
      </Td>
    </tr>
  );
}

function UsageCard() {
  const { data, isPending, isError, error } = useQuery({
    queryKey: useOrgKey("business", "usage"),
    queryFn: () => api<Usage>("/business/usage"),
  });

  const perDay = useMemo(() => {
    const map = new Map<string, { total: number; endpoints: Record<string, number> }>();
    for (const row of data?.api ?? []) {
      const entry = map.get(row.day) ?? { total: 0, endpoints: {} };
      entry.total += row.quantity;
      entry.endpoints[row.endpoint] = (entry.endpoints[row.endpoint] ?? 0) + row.quantity;
      map.set(row.day, entry);
    }
    return [...map.entries()].sort((a, b) => b[0].localeCompare(a[0]));
  }, [data]);

  if (isPending) return <Skeleton className="h-64" />;
  if (isError) {
    return (
      <Card>
        <CardHeader title="Usage" />
        <Callout tone="critical">{errorMessage(error)}</Callout>
      </Card>
    );
  }

  const limit = data.monthly_scans;
  const pct = limit ? Math.min(100, Math.round((data.scans_this_month / limit) * 100)) : 0;

  return (
    <Card padded={false}>
      <div className="space-y-5 p-5">
        <CardHeader title="Usage" description="Scans count towards your plan whether they come from the app or the API." />
        <div className="grid gap-4 sm:grid-cols-3">
          <div>
            <p className="text-[13px] text-muted">Plan</p>
            <p className="mt-1 font-heading text-lg font-semibold text-fg">{data.plan}</p>
          </div>
          <div className="sm:col-span-2">
            <div className="flex items-baseline justify-between gap-3">
              <p className="text-[13px] text-muted">Scans this month</p>
              <p className="text-sm tabular-nums text-fg">
                <span className="font-semibold">{n(data.scans_this_month)}</span>
                <span className="text-muted"> / {limit === null ? "Unlimited" : n(limit)}</span>
              </p>
            </div>
            {limit !== null && (
              <div
                className="mt-2 h-2 overflow-hidden rounded-full bg-surface-2"
                role="progressbar"
                aria-label="Monthly scans used"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={pct}
              >
                <div
                  className={pct >= 90 ? "h-full rounded-full bg-critical" : pct >= 75 ? "h-full rounded-full bg-warning" : "h-full rounded-full bg-primary"}
                  style={{ width: `${pct}%` }}
                />
              </div>
            )}
          </div>
        </div>
        <p className="text-sm text-muted">
          <span className="font-medium text-fg">{n(data.api_total)}</span> API calls in the last 30 days.
        </p>
      </div>
      {perDay.length > 0 ? (
        <Table>
          <thead>
            <tr>
              <Th>Day</Th>
              <Th>Endpoints</Th>
              <Th className="text-right">Calls</Th>
            </tr>
          </thead>
          <tbody>
            {perDay.map(([day, entry]) => (
              <tr key={day}>
                <Td className="text-sm whitespace-nowrap text-fg">{formatDate(day)}</Td>
                <Td className="text-xs text-muted">
                  {Object.entries(entry.endpoints)
                    .sort((a, b) => b[1] - a[1])
                    .map(([ep, q]) => (
                      <span key={ep} className="mr-3 inline-block font-mono">
                        {ep} <span className="text-subtle">×{n(q)}</span>
                      </span>
                    ))}
                </Td>
                <Td className="text-right text-sm font-medium tabular-nums">{n(entry.total)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <p className="border-t border-border px-5 py-4 text-sm text-muted">No API calls in the last 30 days.</p>
      )}
    </Card>
  );
}

export default function ApiPage() {
  const { can } = useSession();
  const allowed = can("api:manage");
  const origin = useOrigin();
  const [creating, setCreating] = useState(false);

  const keys = useQuery({
    queryKey: useOrgKey("business", "api-keys"),
    queryFn: () => api<ApiKey[]>("/business/api-keys"),
    enabled: allowed,
  });

  if (!allowed) return <NoAccess what="API key management" />;

  const curl = `curl -X POST ${origin}/api/v1/scans/url \\
  -H "Authorization: Bearer psk_..." \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://example.com"}'`;

  return (
    <div className="space-y-6">
      <PageHeader
        title="API"
        description="Connect your own systems — helpdesks, email gateways, chat bots — to check links and messages automatically."
        actions={
          <Button onClick={() => setCreating(true)}>
            <Plus className="size-4" aria-hidden /> Create key
          </Button>
        }
      />

      <Card padded={false}>
        <div className="p-5 pb-0">
          <CardHeader title="API keys" description="Each key acts on behalf of this workspace. Revoke any key you no longer use." />
        </div>
        {keys.isPending ? (
          <div className="space-y-2 p-5">
            <Skeleton className="h-10" />
            <Skeleton className="h-10" />
          </div>
        ) : keys.isError ? (
          <div className="p-5">
            <Callout tone={isPlanError(keys.error) ? "warning" : "critical"}>{errorMessage(keys.error)}</Callout>
          </div>
        ) : !keys.data.length ? (
          <EmptyState
            icon={<KeyRound className="size-5" />}
            title="No API keys yet"
            description="Create a key to start checking links and messages from your own systems."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Key</Th>
                <Th>Status</Th>
                <Th>Last used</Th>
                <Th>Expires</Th>
                <Th>
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {keys.data.map((k) => (
                <KeyRow key={k.id} k={k} />
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <UsageCard />
        </div>
        <Card className="lg:col-span-2">
          <CardHeader title="Quick start" description="Check a link with a single request." />
          <div className="space-y-4">
            <CodeBlock label="curl">{curl}</CodeBlock>
            <div className="space-y-2 text-sm text-muted">
              <p>
                The response includes the scan <code className="font-mono text-[13px] text-fg">id</code> and its
                status. Scans run in the background, so poll{" "}
                <code className="font-mono text-[13px] text-fg">GET /api/v1/scans/{"{id}"}</code> for the verdict.
              </p>
              <p>
                Add <code className="font-mono text-[13px] text-fg">?wait=true</code> to the URL to wait for the
                result in the same request instead.
              </p>
              <p>
                Messages work the same way via{" "}
                <code className="font-mono text-[13px] text-fg">/api/v1/scans/message</code>, and batches via{" "}
                <code className="font-mono text-[13px] text-fg">/api/v1/scans/bulk</code>.
              </p>
            </div>
          </div>
        </Card>
      </div>

      <CreateKeyDialog open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}
