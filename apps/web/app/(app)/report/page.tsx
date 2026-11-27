"use client";

import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, Paperclip, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useMemo, useRef, useState, type FormEvent } from "react";
import { useSession } from "@/components/session";
import { Button, ButtonLink, Callout, Card, Field, Input, PageHeader, Select, Textarea } from "@/components/ui";
import { api, ApiError, errorMessage } from "@/lib/api";
import { CHANNELS, SCAM_CATEGORIES } from "@/lib/labels";
import type { ScamReport } from "@/lib/types";

function newKey() {
  return typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : String(Date.now());
}

function ReportForm() {
  const params = useSearchParams();
  const scanId = params.get("scan");
  const { orgId, membership } = useSession();
  const idempotency = useMemo(() => newKey(), []);
  const [form, setForm] = useState({
    category: "momo",
    channel: "sms",
    url: "",
    phone: "",
    sender: "",
    message: "",
    description: "",
    occurred_on: "",
    money_lost: false,
    contact_email: "",
    consent: false,
  });
  const [files, setFiles] = useState<File[]>([]);
  const fileRef = useRef<HTMLInputElement>(null);
  const set = (k: keyof typeof form, v: string | boolean) => setForm((f) => ({ ...f, [k]: v }));

  const submit = useMutation({
    mutationFn: async () => {
      const report = await api<ScamReport>("/reports", {
        method: "POST",
        body: {
          ...form,
          url: form.url || null,
          phone: form.phone || null,
          sender: form.sender || null,
          message: form.message || null,
          occurred_on: form.occurred_on || null,
          contact_email: form.contact_email || null,
          scan_id: scanId,
        },
        headers: { "Idempotency-Key": idempotency },
      });
      for (const file of files) {
        const data = new FormData();
        data.append("file", file);
        await api(`/reports/${report.id}/evidence`, { method: "POST", form: data });
      }
      return report;
    },
  });
  const errors = submit.error instanceof ApiError ? submit.error.fieldErrors() : {};

  if (submit.isSuccess) {
    return (
      <Card className="max-w-2xl py-10 text-center">
        <CheckCircle2 className="mx-auto size-12 text-success" aria-hidden />
        <h2 className="mt-3 font-heading text-xl font-semibold">Thank you — your report was received</h2>
        <p className="mx-auto mt-2 max-w-md text-sm text-muted">
          It&apos;s marked <strong>unverified</strong> until an analyst reviews it. Reports are never published as accusations;
          verified details help us warn other people.
        </p>
        <div className="mt-6 flex justify-center gap-2">
          <ButtonLink href={`/reports/${submit.data.id}`} variant="secondary">
            Track this report
          </ButtonLink>
          <ButtonLink href="/home">Back to home</ButtonLink>
        </div>
      </Card>
    );
  }

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    submit.mutate();
  };

  return (
    <form onSubmit={onSubmit} className="grid max-w-5xl gap-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
      <Card className="space-y-5">
        {submit.error && !Object.keys(errors).length && <Callout tone="critical">{errorMessage(submit.error)}</Callout>}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="What kind of scam?" htmlFor="category">
            <Select id="category" value={form.category} onChange={(e) => set("category", e.target.value)}>
              {SCAM_CATEGORIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="How did it reach you?" htmlFor="channel">
            <Select id="channel" value={form.channel} onChange={(e) => set("channel", e.target.value)}>
              {CHANNELS.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <p className="text-sm font-medium">What should we look into? (at least one)</p>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Suspicious link or website" htmlFor="url" error={errors.url} optional>
            <Input id="url" value={form.url} onChange={(e) => set("url", e.target.value)} placeholder="momo-refund.xyz/claim" />
          </Field>
          <Field label="Phone number" htmlFor="phone" error={errors.phone} optional hint="Kept encrypted and never shown publicly">
            <Input id="phone" value={form.phone} onChange={(e) => set("phone", e.target.value)} placeholder="024 123 4567" inputMode="tel" />
          </Field>
          <Field label="Sender name, email or social profile" htmlFor="sender" optional>
            <Input id="sender" value={form.sender} onChange={(e) => set("sender", e.target.value)} />
          </Field>
          <Field label="When did it happen?" htmlFor="date" optional>
            <Input id="date" type="date" value={form.occurred_on} onChange={(e) => set("occurred_on", e.target.value)} max={new Date().toISOString().slice(0, 10)} />
          </Field>
        </div>
        <Field label="The message (if any)" htmlFor="message" optional hint="We remove PINs, codes and card numbers before saving">
          <Textarea id="message" rows={4} value={form.message} onChange={(e) => set("message", e.target.value)} />
        </Field>
        <Field label="What happened?" htmlFor="description" error={errors.description}>
          <Textarea
            id="description"
            rows={4}
            required
            minLength={10}
            value={form.description}
            onChange={(e) => set("description", e.target.value)}
            placeholder="e.g. Someone called saying they sent money by mistake and asked me to approve a prompt."
          />
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.money_lost} onChange={(e) => set("money_lost", e.target.checked)} />
          I lost money or shared account details
        </label>
        <div>
          <input
            ref={fileRef}
            type="file"
            multiple
            accept="image/png,image/jpeg,image/webp,application/pdf,text/plain,.eml"
            className="hidden"
            onChange={(e) => setFiles(Array.from(e.target.files ?? []).slice(0, 5))}
          />
          <Button type="button" variant="secondary" size="sm" onClick={() => fileRef.current?.click()}>
            <Paperclip className="size-4" /> Attach screenshots ({files.length}/5)
          </Button>
          {files.length > 0 && <p className="mt-1 text-xs text-subtle">{files.map((f) => f.name).join(", ")}</p>}
        </div>
        <Field label="Your email, if we may contact you" htmlFor="contact" error={errors.contact_email} optional>
          <Input id="contact" type="email" value={form.contact_email} onChange={(e) => set("contact_email", e.target.value)} />
        </Field>
        <label className="flex items-start gap-2 text-sm text-muted">
          <input type="checkbox" className="mt-0.5" checked={form.consent} onChange={(e) => set("consent", e.target.checked)} required />
          <span>
            I agree that this report may be reviewed by analysts and that verified links and numbers may be used to warn others. My
            name and contact details are never published.{" "}
            <Link href="/legal/privacy" className="underline">
              Privacy notice
            </Link>
          </span>
        </label>
        <div className="flex justify-end">
          <Button type="submit" loading={submit.isPending} disabled={!form.consent}>
            Send report
          </Button>
        </div>
      </Card>
      <div className="space-y-4">
        {form.money_lost && (
          <Callout tone="critical" title="Act quickly">
            Call your bank or mobile money provider now to block the transaction or your account, change any password you shared,
            and report it to the Cyber Security Authority (call or text 292) or the police.
          </Callout>
        )}
        <Card>
          <ShieldAlert className="size-6 text-primary" aria-hidden />
          <h3 className="mt-2 font-heading font-semibold">How reports are used</h3>
          <ul className="mt-2 space-y-2 text-sm text-muted">
            <li>Every report starts as <strong>unverified</strong>.</li>
            <li>An analyst checks the evidence before anything is confirmed.</li>
            <li>A report alone never labels a person, number or business a criminal.</li>
            <li>{orgId ? `Your security team at ${membership?.organisation_name} can also see it.` : "You can follow its status in My reports."}</li>
          </ul>
        </Card>
      </div>
    </form>
  );
}

export default function ReportPage() {
  return (
    <>
      <PageHeader title="Report a scam" description="Tell us about a suspicious link, number or message. It helps us protect others." />
      <Suspense>
        <ReportForm />
      </Suspense>
    </>
  );
}
