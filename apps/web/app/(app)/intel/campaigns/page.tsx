"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Globe, Megaphone, Pencil, Plus, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { Dialog } from "@/components/dialog";
import { CAMPAIGN_STATUS, INTEL_KEY, IntelGate, useCampaigns } from "@/components/intel-ui";
import { useToast } from "@/components/providers";
import { useSession } from "@/components/session";
import {
  Badge,
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
import { SCAM_CATEGORIES } from "@/lib/labels";
import type { Campaign } from "@/lib/types";

function CampaignDialog({ campaign, onClose }: { campaign: Campaign | "new"; onClose: () => void }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const existing = campaign === "new" ? null : campaign;
  const [name, setName] = useState(existing?.name ?? "");
  const [category, setCategory] = useState(existing?.category ?? "momo");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [status, setStatus] = useState<Campaign["status"]>(existing?.status ?? "active");
  const [published, setPublished] = useState(existing?.published ?? false);
  const [publicTitle, setPublicTitle] = useState(existing?.public_title ?? "");
  const [publicSummary, setPublicSummary] = useState(existing?.public_summary ?? "");
  const [errors, setErrors] = useState<Record<string, string>>({});

  const save = useMutation({
    mutationFn: () =>
      api<Campaign>(existing ? `/intelligence/campaigns/${existing.id}` : "/intelligence/campaigns", {
        method: existing ? "PUT" : "POST",
        org: false,
        body: {
          name: name.trim(),
          category,
          description: description.trim(),
          status,
          published,
          public_title: publicTitle.trim() || null,
          public_summary: publicSummary.trim() || null,
        },
      }),
    onSuccess: () => {
      toast("success", existing ? "Campaign updated." : "Campaign created.");
      queryClient.invalidateQueries({ queryKey: [INTEL_KEY] });
      onClose();
    },
    onError: (err) => {
      if (err instanceof ApiError) setErrors(err.fieldErrors());
    },
  });

  function validate() {
    const e: Record<string, string> = {};
    if (name.trim().length < 3) e.name = "Use at least 3 characters.";
    if (published) {
      if (!publicTitle.trim()) e.public_title = "Add a public title before publishing.";
      if (!publicSummary.trim()) e.public_summary = "Add a public summary before publishing.";
    }
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  return (
    <Dialog
      open
      onClose={onClose}
      wide
      title={existing ? "Edit campaign" : "New campaign"}
      description="Group related indicators into a campaign. Publishing shows a public warning to everyone."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="campaign-form" loading={save.isPending}>
            {existing ? "Save changes" : "Create campaign"}
          </Button>
        </>
      }
    >
      <form
        id="campaign-form"
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
        <Field label="Internal name" htmlFor="cp-name" error={errors.name}>
          <Input id="cp-name" value={name} onChange={(e) => setName(e.target.value)} invalid={!!errors.name} maxLength={200} />
        </Field>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Category" htmlFor="cp-category">
            <Select id="cp-category" value={category} onChange={(e) => setCategory(e.target.value)}>
              {SCAM_CATEGORIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
              {!SCAM_CATEGORIES.some((c) => c.value === category) && (
                <option value={category}>{existing?.category_label ?? category}</option>
              )}
            </Select>
          </Field>
          <Field label="Status" htmlFor="cp-status">
            <Select id="cp-status" value={status} onChange={(e) => setStatus(e.target.value as Campaign["status"])}>
              {Object.entries(CAMPAIGN_STATUS).map(([v, s]) => (
                <option key={v} value={v}>
                  {s.label}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <Field label="Internal description" htmlFor="cp-desc" optional hint="Staff only.">
          <Textarea id="cp-desc" value={description} onChange={(e) => setDescription(e.target.value)} rows={3} maxLength={5000} />
        </Field>

        <div className="rounded-[var(--radius-control)] border border-border p-4">
          <label className="flex cursor-pointer items-start gap-3">
            <input
              type="checkbox"
              checked={published}
              onChange={(e) => setPublished(e.target.checked)}
              className="mt-1 size-4 accent-[var(--color-primary)]"
            />
            <span>
              <span className="block text-sm font-medium text-fg">Publish as a public warning</span>
              <span className="block text-[13px] text-muted">
                Shown on the public warnings page and in the apps. Requires a public title and summary.
              </span>
            </span>
          </label>
          <div className="mt-4 space-y-4">
            <Callout tone="warning" icon={<TriangleAlert className="size-4" />}>
              Public text must never contain private message content, reporters&apos; details or personal phone
              numbers. Describe the scam pattern in general terms.
            </Callout>
            <Field label="Public title" htmlFor="cp-ptitle" optional={!published} error={errors.public_title}>
              <Input
                id="cp-ptitle"
                value={publicTitle}
                onChange={(e) => setPublicTitle(e.target.value)}
                invalid={!!errors.public_title}
                maxLength={200}
                placeholder='For example: Fake "money sent by mistake" messages'
              />
            </Field>
            <Field
              label="Public summary"
              htmlFor="cp-psummary"
              optional={!published}
              error={errors.public_summary}
              hint={`${publicSummary.length}/1000`}
            >
              <Textarea
                id="cp-psummary"
                value={publicSummary}
                onChange={(e) => setPublicSummary(e.target.value)}
                invalid={!!errors.public_summary}
                rows={4}
                maxLength={1000}
              />
            </Field>
          </div>
        </div>
      </form>
    </Dialog>
  );
}

function CampaignsView() {
  const { intel } = useSession();
  const canManage = intel("intel:publish");
  const [editing, setEditing] = useState<Campaign | "new" | null>(null);
  const { data, isPending, error } = useCampaigns();

  return (
    <>
      <PageHeader
        title="Campaigns"
        description="Coordinated scam waves. Link indicators to a campaign and publish a plain-language warning when it helps the public."
        actions={
          canManage && (
            <Button onClick={() => setEditing("new")}>
              <Plus className="size-4" />
              New campaign
            </Button>
          )
        }
      />
      <Card padded={false}>
        {error ? (
          <div className="p-4">
            <Callout tone="critical">{errorMessage(error)}</Callout>
          </div>
        ) : isPending ? (
          <div className="p-4">
            <Skeleton className="h-48" />
          </div>
        ) : !data?.length ? (
          <EmptyState icon={<Megaphone className="size-5" />} title="No campaigns yet" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Campaign</Th>
                <Th>Category</Th>
                <Th>Status</Th>
                <Th className="text-right">Indicators</Th>
                <Th>Public warning</Th>
                <Th>Updated</Th>
                {canManage && <Th className="w-12" />}
              </tr>
            </thead>
            <tbody>
              {data.map((c) => (
                <tr key={c.id}>
                  <Td className="max-w-sm">
                    <span className="block font-medium text-fg">{c.name}</span>
                    {c.description && <span className="line-clamp-1 text-xs text-muted">{c.description}</span>}
                  </Td>
                  <Td className="text-[13px] text-muted">{c.category_label}</Td>
                  <Td>
                    <Badge tone={CAMPAIGN_STATUS[c.status]?.tone ?? "neutral"}>
                      {CAMPAIGN_STATUS[c.status]?.label ?? c.status}
                    </Badge>
                  </Td>
                  <Td className="text-right tabular-nums">
                    {c.indicators > 0 ? (
                      <Link
                        href={`/intel/indicators?campaign_id=${c.id}`}
                        className="text-primary-text hover:underline"
                      >
                        {c.indicators}
                      </Link>
                    ) : (
                      0
                    )}
                  </Td>
                  <Td className="max-w-xs">
                    {c.published ? (
                      <>
                        <Badge tone="success">
                          <Globe className="size-3" />
                          Published {formatDate(c.published_at)}
                        </Badge>
                        <span className="mt-1 block truncate text-xs text-muted">{c.public_title}</span>
                      </>
                    ) : (
                      <span className="text-[13px] text-subtle">Not published</span>
                    )}
                  </Td>
                  <Td className="text-[13px] whitespace-nowrap text-muted">{timeAgo(c.updated_at)}</Td>
                  {canManage && (
                    <Td>
                      <Button variant="ghost" size="sm" onClick={() => setEditing(c)} aria-label={`Edit ${c.name}`}>
                        <Pencil className="size-3.5" />
                      </Button>
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      {editing && <CampaignDialog key={editing === "new" ? "new" : editing.id} campaign={editing} onClose={() => setEditing(null)} />}
    </>
  );
}

export default function CampaignsPage() {
  return (
    <IntelGate>
      <CampaignsView />
    </IntelGate>
  );
}
