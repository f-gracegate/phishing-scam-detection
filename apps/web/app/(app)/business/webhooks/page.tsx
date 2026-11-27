"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Send, Trash2, TriangleAlert, Webhook as WebhookIcon } from "lucide-react";
import Link from "next/link";
import { useState, type FormEvent } from "react";
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
  Skeleton,
} from "@/components/ui";
import { api, ApiError, errorMessage } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { WEBHOOK_EVENTS } from "@/lib/labels";
import type { Webhook } from "@/lib/types";

const eventLabel = (e: string) => WEBHOOK_EVENTS.find((x) => x.value === e)?.label ?? e;

function PlanCallout({ error }: { error: unknown }) {
  return (
    <Callout tone="warning" title="Not included in your plan">
      {errorMessage(error)}{" "}
      <Link href="/settings/subscription" className="font-medium underline">
        See plans
      </Link>
    </Callout>
  );
}

function AddWebhookDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const orgKey = useOrgKey();
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [events, setEvents] = useState<string[]>(["scan.high_risk"]);
  const [created, setCreated] = useState<Webhook | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const create = useMutation({
    mutationFn: () =>
      api<Webhook>("/business/webhooks", {
        method: "POST",
        body: { url: url.trim(), description: description.trim(), events },
      }),
    onSuccess: (w) => {
      setCreated(w);
      queryClient.invalidateQueries({ queryKey: [...orgKey, "business", "webhooks"] });
    },
    onError: (err) => {
      if (err instanceof ApiError) setErrors(err.fieldErrors());
    },
  });

  function close() {
    setUrl("");
    setDescription("");
    setEvents(["scan.high_risk"]);
    setCreated(null);
    setErrors({});
    create.reset();
    onClose();
  }

  function toggle(value: string, on: boolean) {
    setEvents((prev) => (on ? [...prev, value] : prev.filter((e) => e !== value)));
  }

  const urlError = errors.url;

  return (
    <Dialog
      open={open}
      onClose={close}
      title={created ? "Webhook added" : "Add a webhook"}
      description={
        created
          ? "Use this signing secret to check that deliveries really come from us. Copy it now — you won't see it again."
          : "We'll send a signed POST request to your endpoint when these events happen."
      }
      footer={
        created ? (
          <Button onClick={close}>I&apos;ve saved it</Button>
        ) : (
          <>
            <Button variant="secondary" onClick={close}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="add-webhook-form"
              loading={create.isPending}
              disabled={!url.trim() || events.length === 0}
            >
              Add webhook
            </Button>
          </>
        )
      }
    >
      {created?.secret ? (
        <div className="space-y-4">
          <CopyField label="Signing secret" value={created.secret} />
          <Callout tone="warning" icon={<TriangleAlert className="size-4" />}>
            Store it with your other secrets. If it leaks, delete this webhook and add it again to get a new secret.
          </Callout>
        </div>
      ) : (
        <form
          id="add-webhook-form"
          className="space-y-4"
          noValidate
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            setErrors({});
            create.mutate();
          }}
        >
          {create.isError &&
            !urlError &&
            (isPlanError(create.error) ? (
              <PlanCallout error={create.error} />
            ) : (
              <Callout tone="critical">{errorMessage(create.error)}</Callout>
            ))}
          <Field
            label="Endpoint URL"
            htmlFor="webhook-url"
            error={urlError}
            hint="Must be a public HTTPS address."
          >
            <Input
              id="webhook-url"
              type="url"
              inputMode="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/hooks/phishing"
              invalid={!!urlError}
              autoFocus
            />
          </Field>
          <Field label="Description" htmlFor="webhook-description" optional>
            <Input
              id="webhook-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={200}
              placeholder="e.g. SOC Slack alerts"
            />
          </Field>
          <fieldset>
            <legend className="mb-2 text-sm font-medium text-fg">Events</legend>
            <div className="space-y-2">
              {WEBHOOK_EVENTS.map((ev) => (
                <label key={ev.value} className="flex items-start gap-3 text-sm">
                  <input
                    type="checkbox"
                    checked={events.includes(ev.value)}
                    onChange={(e) => toggle(ev.value, e.target.checked)}
                    className="mt-0.5 size-4 rounded border-border-strong accent-[var(--primary)]"
                  />
                  <span>
                    <span className="text-fg">{ev.label}</span>
                    <span className="ml-2 font-mono text-xs text-subtle">{ev.value}</span>
                  </span>
                </label>
              ))}
            </div>
            {events.length === 0 && <p className="mt-2 text-[13px] text-critical-text">Choose at least one event.</p>}
            {errors.events && <p className="mt-2 text-[13px] text-critical-text">{errors.events}</p>}
          </fieldset>
        </form>
      )}
    </Dialog>
  );
}

function DeliveryBadge({ w }: { w: Webhook }) {
  const d = w.last_delivery;
  if (!d) return <Badge tone="neutral">No deliveries yet</Badge>;
  const ok = d.status === "delivered";
  const pending = d.status === "pending";
  return (
    <span className="flex flex-wrap items-center gap-2">
      <Badge tone={ok ? "success" : pending ? "info" : "critical"} dot>
        {ok ? "Delivered" : pending ? "Pending retry" : "Failed"}
        {d.response_status ? ` · ${d.response_status}` : ""}
      </Badge>
      <span className="text-xs text-subtle">{timeAgo(d.at)}</span>
    </span>
  );
}

function WebhookCard({ w }: { w: Webhook }) {
  const queryClient = useQueryClient();
  const orgKey = useOrgKey();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  const invalidate = () => queryClient.invalidateQueries({ queryKey: [...orgKey, "business", "webhooks"] });

  const test = useMutation({
    mutationFn: () =>
      api<{ delivered: boolean; response_status: number | null; error: string | null }>(
        `/business/webhooks/${w.id}/test`,
        { method: "POST" },
      ),
    onSuccess: (r) => {
      invalidate();
      if (r.delivered) toast("success", `Test delivered${r.response_status ? ` (HTTP ${r.response_status})` : ""}.`);
      else
        toast(
          "error",
          `Test failed${r.response_status ? ` (HTTP ${r.response_status})` : ""}${r.error ? `: ${r.error}` : "."}`,
        );
    },
    onError: (err) => toast("error", errorMessage(err)),
  });
  const remove = useMutation({
    mutationFn: () => api(`/business/webhooks/${w.id}`, { method: "DELETE" }),
    onSuccess: () => {
      invalidate();
      toast("success", "Webhook deleted.");
      setConfirm(false);
    },
    onError: (err) => toast("error", errorMessage(err)),
  });

  const lastError = w.last_delivery?.error;

  return (
    <li className="space-y-3 p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-mono text-sm text-fg" title={w.url}>
            {w.url}
          </p>
          {w.description && <p className="mt-0.5 text-sm text-muted">{w.description}</p>}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => test.mutate()} loading={test.isPending}>
            {!test.isPending && <Send className="size-3.5" aria-hidden />} Send test
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setConfirm(true)}
            aria-label={`Delete webhook ${w.url}`}
            className="text-critical-text"
          >
            <Trash2 className="size-4" aria-hidden />
          </Button>
        </div>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {w.events.map((e) => (
          <Badge key={e} tone="primary">
            {eventLabel(e)}
          </Badge>
        ))}
        {!w.active && <Badge tone="warning">Paused</Badge>}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
        <span className="text-muted">Last delivery:</span>
        <DeliveryBadge w={w} />
        {w.consecutive_failures > 0 && (
          <span className="text-xs text-critical-text">
            {w.consecutive_failures} failed {w.consecutive_failures === 1 ? "delivery" : "deliveries"} in a row
          </span>
        )}
      </div>
      {lastError && w.last_delivery?.status !== "delivered" && (
        <p className="truncate font-mono text-xs text-subtle" title={lastError}>
          {lastError}
        </p>
      )}
      <Dialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title="Delete this webhook?"
        description="We'll stop sending events to this endpoint straight away."
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
              Delete webhook
            </Button>
          </>
        }
      >
        <p className="font-mono text-sm break-all text-muted">{w.url}</p>
      </Dialog>
    </li>
  );
}

const VERIFY_SNIPPET = `// Node.js example
import crypto from "node:crypto";

function verify(rawBody, header, secret) {
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=")));
  const expected = crypto
    .createHmac("sha256", secret)
    .update(\`\${parts.t}.\${rawBody}\`)
    .digest("hex");
  const fresh = Math.abs(Date.now() / 1000 - Number(parts.t)) < 300;
  return fresh && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1));
}`;

export default function WebhooksPage() {
  const { can } = useSession();
  const allowed = can("webhooks:manage");
  const [adding, setAdding] = useState(false);

  const { data, isPending, isError, error } = useQuery({
    queryKey: useOrgKey("business", "webhooks"),
    queryFn: () => api<Webhook[]>("/business/webhooks"),
    enabled: allowed,
  });

  if (!allowed) return <NoAccess what="webhook management" />;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Webhooks"
        description="Get notified in your own tools — Slack, Teams, your SIEM or ticketing system — when something important happens."
        actions={
          <Button onClick={() => setAdding(true)}>
            <Plus className="size-4" aria-hidden /> Add webhook
          </Button>
        }
      />

      <div className="grid gap-6 lg:grid-cols-5">
        <Card padded={false} className="lg:col-span-3">
          <div className="p-5 pb-0">
            <CardHeader title="Endpoints" />
          </div>
          {isPending ? (
            <div className="space-y-2 p-5">
              <Skeleton className="h-24" />
              <Skeleton className="h-24" />
            </div>
          ) : isError ? (
            <div className="p-5">
              {isPlanError(error) ? <PlanCallout error={error} /> : <Callout tone="critical">{errorMessage(error)}</Callout>}
            </div>
          ) : !data.length ? (
            <EmptyState
              icon={<WebhookIcon className="size-5" />}
              title="No webhooks yet"
              description="Add an endpoint to receive high-risk results, new cases and more as they happen."
            />
          ) : (
            <ul className="divide-y divide-border border-t border-border">
              {data.map((w) => (
                <WebhookCard key={w.id} w={w} />
              ))}
            </ul>
          )}
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Verifying deliveries" description="Always check the signature before trusting a request." />
          <div className="space-y-4 text-sm text-muted">
            <p>Every delivery includes this header:</p>
            <CodeBlock>X-PSD-Signature: t=&lt;unix time&gt;,v1=&lt;signature&gt;</CodeBlock>
            <ol className="list-decimal space-y-1.5 pl-5">
              <li>
                Join the timestamp and the raw request body with a full stop:{" "}
                <code className="font-mono text-[13px] text-fg">t.body</code>
              </li>
              <li>Compute an HMAC-SHA256 of that string using your signing secret, as hex.</li>
              <li>
                Compare it with <code className="font-mono text-[13px] text-fg">v1</code> using a constant-time
                comparison.
              </li>
              <li>Reject requests whose timestamp is more than five minutes old, to block replays.</li>
            </ol>
            <CodeBlock label="Example">{VERIFY_SNIPPET}</CodeBlock>
            <p>Reply with any 2xx status within a few seconds. Failed deliveries are retried.</p>
          </div>
        </Card>
      </div>

      <AddWebhookDialog open={adding} onClose={() => setAdding(false)} />
    </div>
  );
}
