"use client";

import { useMutation } from "@tanstack/react-query";
import { Camera, FileUp, Link2, Lock, Mail, MessageSquare, QrCode, Search } from "lucide-react";
import { useRouter } from "next/navigation";
import { useRef, useState, type FormEvent, type ReactNode } from "react";
import { useSession } from "@/components/session";
import { Button, Callout, Card, Field, Input, Select, Textarea, cn } from "@/components/ui";
import { api, ApiError, errorMessage } from "@/lib/api";
import type { ScanDetail } from "@/lib/types";

function useSubmit(path: string) {
  const router = useRouter();
  return useMutation({
    mutationFn: (body: unknown) => api<ScanDetail>(path, { method: "POST", body }),
    onSuccess: (scan) => router.push(`/scans/${scan.id}`),
  });
}

function PrivacyToggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-start gap-2 text-sm text-muted">
      <input
        type="checkbox"
        className="mt-0.5 size-4 accent-[var(--primary)]"
        checked={value}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        Also check with trusted outside threat-intelligence services.{" "}
        <span className="text-subtle">Private tokens in links are removed first.</span>
      </span>
    </label>
  );
}

function ScopeNote() {
  const { orgId, membership } = useSession();
  return (
    <p className="flex items-center gap-1.5 text-xs text-subtle">
      <Lock className="size-3" aria-hidden />
      {orgId
        ? `Saved to ${membership?.organisation_name}. Security staff in this workspace can see it.`
        : "Saved to your private history. Only you can see it."}
    </p>
  );
}

function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return <Callout tone="critical">{errorMessage(error)}</Callout>;
}

// --- Link ------------------------------------------------------------------------------------

export function LinkCheckForm({ large = false, autoFocus = false }: { large?: boolean; autoFocus?: boolean }) {
  const [url, setUrl] = useState("");
  const [external, setExternal] = useState(true);
  const submit = useSubmit("/scans/url");
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    submit.mutate({ url: url.trim(), privacy: { allow_external_intelligence_lookup: external } });
  };
  const fieldError = submit.error instanceof ApiError && submit.error.code === "invalid_url";
  return (
    <form onSubmit={onSubmit} className="space-y-3">
      <div className={cn("flex flex-col gap-2 sm:flex-row", large && "sm:gap-3")}>
        <div className="relative flex-1">
          <Link2 className="pointer-events-none absolute top-1/2 left-3.5 size-5 -translate-y-1/2 text-subtle" aria-hidden />
          <Input
            aria-label="Link to check"
            placeholder="Paste a suspicious link, e.g. mtn-momo-refund.xyz/claim"
            value={url}
            autoFocus={autoFocus}
            onChange={(e) => setUrl(e.target.value)}
            className={cn("pl-11", large && "h-14 text-base")}
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <Button type="submit" loading={submit.isPending} className={cn(large && "h-14 px-6 text-base")}>
          <Search className="size-4" /> Check link
        </Button>
      </div>
      {fieldError ? <p className="text-sm text-critical-text">{submit.error?.message}</p> : <ErrorBox error={submit.error} />}
      <PrivacyToggle value={external} onChange={setExternal} />
    </form>
  );
}

// --- Message -----------------------------------------------------------------------------------

export function MessageCheckForm() {
  const [text, setText] = useState("");
  const [sender, setSender] = useState("");
  const [channel, setChannel] = useState("sms");
  const [checkLinks, setCheckLinks] = useState(false);
  const [external, setExternal] = useState(true);
  const submit = useSubmit("/scans/message");
  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        submit.mutate({
          text,
          sender: sender || null,
          channel,
          check_links: checkLinks,
          privacy: { allow_external_intelligence_lookup: external },
        });
      }}
    >
      <ErrorBox error={submit.error} />
      <Field label="The message" htmlFor="msg" hint="Paste the whole SMS or WhatsApp message. We remove PINs, codes and card numbers before saving.">
        <Textarea
          id="msg"
          rows={7}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="e.g. MTN MoMo: GHS 450 was sent to your wallet by mistake. Please reverse…"
          maxLength={20000}
          required
        />
      </Field>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Who sent it? (optional)" htmlFor="sender" hint="The number or sender name shown on your phone">
          <Input id="sender" value={sender} onChange={(e) => setSender(e.target.value)} placeholder="0244 123 456 or MobileMoney" />
        </Field>
        <Field label="Where did you get it?" htmlFor="channel">
          <Select id="channel" value={channel} onChange={(e) => setChannel(e.target.value)}>
            <option value="sms">SMS / text message</option>
            <option value="whatsapp">WhatsApp</option>
            <option value="social">Social media</option>
            <option value="other">Somewhere else</option>
          </Select>
        </Field>
      </div>
      <label className="flex items-start gap-2 text-sm text-muted">
        <input type="checkbox" className="mt-0.5 size-4" checked={checkLinks} onChange={(e) => setCheckLinks(e.target.checked)} />
        Also visit any links in the message to inspect the websites (slower)
      </label>
      <PrivacyToggle value={external} onChange={setExternal} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <ScopeNote />
        <Button type="submit" loading={submit.isPending} disabled={!text.trim()}>
          <MessageSquare className="size-4" /> Check message
        </Button>
      </div>
    </form>
  );
}

// --- Email -------------------------------------------------------------------------------------

export function EmailCheckForm() {
  const [raw, setRaw] = useState("");
  const [external, setExternal] = useState(true);
  const fileRef = useRef<HTMLInputElement>(null);
  const router = useRouter();
  const submit = useSubmit("/scans/email");
  const upload = useMutation({
    mutationFn: (file: File) => {
      const form = new FormData();
      form.append("file", file);
      return api<ScanDetail>("/scans/email/file", { method: "POST", form, query: { allow_external: external } });
    },
    onSuccess: (scan) => router.push(`/scans/${scan.id}`),
  });
  return (
    <div className="space-y-4">
      <ErrorBox error={submit.error ?? upload.error} />
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          submit.mutate({ raw, privacy: { allow_external_intelligence_lookup: external } });
        }}
      >
        <Field
          label="Paste the email"
          htmlFor="raw"
          hint="For the most accurate result paste the full original: in Gmail open ⋮ → “Show original”; in Outlook “View source”. Pasting just the text also works."
        >
          <Textarea id="raw" rows={10} value={raw} onChange={(e) => setRaw(e.target.value)} className="font-mono text-[13px]" required />
        </Field>
        <PrivacyToggle value={external} onChange={setExternal} />
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              accept=".eml,message/rfc822,text/plain"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) upload.mutate(f);
                e.target.value = "";
              }}
            />
            <Button type="button" variant="secondary" onClick={() => fileRef.current?.click()} loading={upload.isPending}>
              <FileUp className="size-4" /> Upload .eml file
            </Button>
          </div>
          <Button type="submit" loading={submit.isPending} disabled={!raw.trim()}>
            <Mail className="size-4" /> Check email
          </Button>
        </div>
        <ScopeNote />
      </form>
      <p className="text-xs text-subtle">Attachments are never opened or run — we only look at their names and types.</p>
    </div>
  );
}

// --- QR code -----------------------------------------------------------------------------------

async function decodeImage(file: File): Promise<string | null> {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(bitmap.width * scale);
  canvas.height = Math.round(bitmap.height * scale);
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const { default: jsQR } = await import("jsqr");
  const result = jsQR(data.data, data.width, data.height, { inversionAttempts: "attemptBoth" });
  return result?.data ?? null;
}

export function QrCheckForm() {
  const [decoded, setDecoded] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const submit = useSubmit("/scans/qr");

  const onFile = async (file: File) => {
    setProblem(null);
    setDecoded(null);
    setBusy(true);
    try {
      const text = await decodeImage(file);
      if (!text) setProblem("We couldn't find a QR code in that picture. Try a sharper, closer photo.");
      else setDecoded(text);
    } catch {
      setProblem("That image couldn't be read.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <ErrorBox error={submit.error} />
      <div className="flex flex-col items-center gap-3 rounded-xl border-2 border-dashed border-border-strong bg-surface-2 px-6 py-10 text-center">
        <QrCode className="size-10 text-subtle" aria-hidden />
        <p className="max-w-sm text-sm text-muted">
          Take a photo of the QR code or choose a screenshot. The picture is read on this device — only the decoded text is checked.
        </p>
        <input
          ref={fileRef}
          type="file"
          accept="image/*"
          capture="environment"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void onFile(f);
            e.target.value = "";
          }}
        />
        <Button type="button" onClick={() => fileRef.current?.click()} loading={busy}>
          <Camera className="size-4" /> Take or choose a photo
        </Button>
      </div>
      {problem && <Callout tone="warning">{problem}</Callout>}
      {decoded && (
        <Card>
          <p className="text-sm text-subtle">This QR code contains:</p>
          <p className="mt-1 break-all font-medium text-fg">{decoded}</p>
          <p className="mt-2 text-xs text-subtle">Don&apos;t open it yet — check it first.</p>
          <div className="mt-4 flex gap-2">
            <Button onClick={() => submit.mutate({ payload: decoded })} loading={submit.isPending}>
              <Search className="size-4" /> Check what it points to
            </Button>
            <Button variant="ghost" onClick={() => setDecoded(null)}>
              Clear
            </Button>
          </div>
        </Card>
      )}
    </div>
  );
}

export function CheckCard({ title, description, children }: { title: string; description: ReactNode; children: ReactNode }) {
  return (
    <Card className="max-w-3xl">
      <h2 className="font-heading text-lg font-semibold">{title}</h2>
      <p className="mt-1 mb-5 text-sm text-muted">{description}</p>
      {children}
    </Card>
  );
}
