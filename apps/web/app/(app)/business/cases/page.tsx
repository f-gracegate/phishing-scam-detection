"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderSearch, Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { CaseStatusBadge, NoAccess, SeverityBadge, useMembers } from "@/components/business-ui";
import { Dialog } from "@/components/dialog";
import { useToast } from "@/components/providers";
import { useOrgKey, useSession } from "@/components/session";
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
  cn,
} from "@/components/ui";
import { api, ApiError, errorMessage } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { SCAM_CATEGORIES, SEVERITIES } from "@/lib/labels";
import type { Case } from "@/lib/types";

const FILTERS = [
  { value: "open", label: "Open" },
  { value: "", label: "All" },
  { value: "closed", label: "Closed" },
];

function NewCaseDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const orgKey = useOrgKey();
  const router = useRouter();
  const toast = useToast();
  const members = useMembers();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [category, setCategory] = useState("");
  const [assignee, setAssignee] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});

  const create = useMutation({
    mutationFn: () =>
      api<Case>("/business/cases", {
        method: "POST",
        body: {
          title: title.trim(),
          description: description.trim(),
          severity,
          category: category || null,
          assignee_id: assignee || null,
        },
      }),
    onSuccess: (c) => {
      queryClient.invalidateQueries({ queryKey: [...orgKey, "business", "cases"] });
      toast("success", `${c.reference} opened.`);
      close();
      router.push(`/business/cases/${c.id}`);
    },
    onError: (err) => {
      if (err instanceof ApiError) setErrors(err.fieldErrors());
    },
  });

  function close() {
    setTitle("");
    setDescription("");
    setSeverity("medium");
    setCategory("");
    setAssignee("");
    setErrors({});
    create.reset();
    onClose();
  }

  const fieldError = errors.title || errors.description || errors.assignee_id;

  return (
    <Dialog
      open={open}
      onClose={close}
      title="Open a new case"
      description="Track an investigation into a phishing attempt or scam affecting your organisation."
      footer={
        <>
          <Button variant="secondary" onClick={close}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="new-case-form"
            loading={create.isPending}
            disabled={title.trim().length < 3}
          >
            Open case
          </Button>
        </>
      }
    >
      <form
        id="new-case-form"
        className="space-y-4"
        noValidate
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          setErrors({});
          create.mutate();
        }}
      >
        {create.isError && !fieldError && <Callout tone="critical">{errorMessage(create.error)}</Callout>}
        <Field label="Title" htmlFor="case-title" error={errors.title} hint="At least 3 characters.">
          <Input
            id="case-title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="e.g. Fake MTN MoMo reversal texts to finance team"
            invalid={!!errors.title}
            maxLength={200}
            autoFocus
          />
        </Field>
        <Field label="Description" htmlFor="case-description" error={errors.description} optional>
          <Textarea
            id="case-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={4}
            placeholder="What happened, who was targeted and what you know so far."
            maxLength={10000}
          />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Severity" htmlFor="case-severity">
            <Select id="case-severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Scam type" htmlFor="case-category" optional>
            <Select id="case-category" value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">Not sure yet</option>
              {SCAM_CATEGORIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <Field label="Assign to" htmlFor="case-assignee" error={errors.assignee_id} optional>
          <Select
            id="case-assignee"
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
            disabled={members.isPending}
          >
            <option value="">Unassigned</option>
            {(members.data ?? [])
              .filter((m) => m.status === "active")
              .map((m) => (
                <option key={m.user_id} value={m.user_id}>
                  {m.full_name || m.email}
                  {m.is_you ? " (you)" : ""}
                </option>
              ))}
          </Select>
        </Field>
      </form>
    </Dialog>
  );
}

export default function CasesPage() {
  const { can } = useSession();
  const [status, setStatus] = useState("open");
  const [creating, setCreating] = useState(false);
  const allowed = can("cases:read") || can("cases:manage");

  const { data, isPending, isError, error } = useQuery({
    queryKey: useOrgKey("business", "cases", status),
    queryFn: () => api<Case[]>("/business/cases", { query: { status } }),
    enabled: allowed,
  });

  if (!allowed) return <NoAccess what="investigation cases" />;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cases"
        description="Investigations into phishing and scams targeting your organisation. Link scans, record notes and close each case with an outcome."
        actions={
          can("cases:manage") && (
            <Button onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden /> New case
            </Button>
          )
        }
      />

      <Card padded={false}>
        <div className="flex items-center gap-1 border-b border-border p-2" role="tablist" aria-label="Filter cases">
          {FILTERS.map((f) => (
            <button
              key={f.label}
              type="button"
              role="tab"
              aria-selected={status === f.value}
              onClick={() => setStatus(f.value)}
              className={cn(
                "rounded-[var(--radius-control)] px-3 py-1.5 text-sm font-medium transition-colors",
                status === f.value ? "bg-primary-soft text-primary-text" : "text-muted hover:bg-surface-2 hover:text-fg",
              )}
            >
              {f.label}
            </button>
          ))}
        </div>

        {isPending ? (
          <div className="space-y-2 p-5">
            <Skeleton className="h-10" />
            <Skeleton className="h-10" />
            <Skeleton className="h-10" />
          </div>
        ) : isError ? (
          <EmptyState title="We couldn't load cases" description={errorMessage(error)} />
        ) : !data.length ? (
          <EmptyState
            icon={<FolderSearch className="size-5" />}
            title={status === "closed" ? "No closed cases" : status === "open" ? "No open cases" : "No cases yet"}
            description={
              can("cases:manage")
                ? "Open a case when you want to track an investigation from first report to outcome."
                : "Cases your team opens will appear here."
            }
            action={
              can("cases:manage") && (
                <Button variant="secondary" onClick={() => setCreating(true)}>
                  <Plus className="size-4" aria-hidden /> New case
                </Button>
              )
            }
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Case</Th>
                <Th>Status</Th>
                <Th>Severity</Th>
                <Th>Assignee</Th>
                <Th>Updated</Th>
              </tr>
            </thead>
            <tbody>
              {data.map((c) => (
                <tr key={c.id} className="hover:bg-surface-2/60">
                  <Td>
                    <Link href={`/business/cases/${c.id}`} className="group block min-w-0">
                      <span className="block font-mono text-xs text-subtle">{c.reference}</span>
                      <span className="block max-w-md truncate font-medium text-fg group-hover:text-primary-text group-hover:underline">
                        {c.title}
                      </span>
                      {c.category_label && (
                        <span className="block truncate text-xs text-muted">{c.category_label}</span>
                      )}
                    </Link>
                  </Td>
                  <Td>
                    <CaseStatusBadge status={c.status} />
                  </Td>
                  <Td>
                    <SeverityBadge severity={c.severity} />
                  </Td>
                  <Td className="text-sm text-muted">{c.assignee ?? "Unassigned"}</Td>
                  <Td className="text-sm whitespace-nowrap text-muted">{timeAgo(c.updated_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <NewCaseDialog open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}
