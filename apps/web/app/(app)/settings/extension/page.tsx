"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Trash2 } from "lucide-react";
import { useState } from "react";
import { CopyField } from "@/components/copy-field";
import { Dialog } from "@/components/dialog";
import { useToast } from "@/components/providers";
import { Button, Callout, Card, CardHeader, Field, Input, Skeleton } from "@/components/ui";
import { api, errorMessage } from "@/lib/api";
import { formatDate, timeAgo } from "@/lib/format";

type Token = { id: string; name: string; prefix: string; created_at: string; last_used_at: string | null; expires_at: string | null };

export default function ExtensionSettingsPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState("Chrome on my laptop");
  const [secret, setSecret] = useState<string | null>(null);
  const tokens = useQuery({ queryKey: ["ext-tokens"], queryFn: () => api<Token[]>("/me/extension-tokens", { org: false }) });
  const create = useMutation({
    mutationFn: () => api<Token & { token: string }>("/me/extension-tokens", { method: "POST", body: { name }, org: false }),
    onSuccess: (t) => {
      setSecret(t.token);
      queryClient.invalidateQueries({ queryKey: ["ext-tokens"] });
    },
    onError: (e) => toast("error", errorMessage(e)),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api(`/me/extension-tokens/${id}`, { method: "DELETE", org: false }),
    onSuccess: () => {
      toast("success", "Browser disconnected.");
      queryClient.invalidateQueries({ queryKey: ["ext-tokens"] });
    },
  });
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader
          title="Browser extension"
          description="The extension checks links from your browser's toolbar or right-click menu, and can warn you before you open a site our analysts have verified as dangerous."
        />
        <ul className="mb-4 space-y-1.5 text-sm text-muted">
          <li>• It only sends a link when you ask it to check one, or — if you turn on warnings — the website&apos;s domain name.</li>
          <li>• It never collects your browsing history.</li>
          <li>• Checks are saved to your private history.</li>
        </ul>
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Name this browser" htmlFor="ext-name" className="w-full max-w-xs">
            <Input id="ext-name" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Button onClick={() => create.mutate()} loading={create.isPending}>
            <Globe className="size-4" /> Connect a browser
          </Button>
        </div>
      </Card>
      <Card>
        <CardHeader title="Connected browsers" />
        {tokens.isPending ? (
          <Skeleton className="h-16" />
        ) : tokens.data?.length ? (
          <ul className="divide-y divide-border">
            {tokens.data.map((t) => (
              <li key={t.id} className="flex items-center justify-between gap-3 py-2.5 text-sm">
                <span>
                  <span className="font-medium">{t.name}</span>{" "}
                  <code className="text-xs text-subtle">{t.prefix}…</code>
                  <span className="block text-xs text-subtle">
                    Connected {formatDate(t.created_at)} · {t.last_used_at ? `last used ${timeAgo(t.last_used_at)}` : "not used yet"}
                  </span>
                </span>
                <Button size="sm" variant="ghost" onClick={() => revoke.mutate(t.id)} aria-label={`Disconnect ${t.name}`}>
                  <Trash2 className="size-4" />
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">No browsers connected.</p>
        )}
      </Card>
      <Dialog
        open={!!secret}
        onClose={() => setSecret(null)}
        title="Paste this into the extension"
        description="Open the extension, choose Settings, and paste this connection code. It's shown only once."
        footer={<Button onClick={() => setSecret(null)}>Done</Button>}
      >
        {secret && <div className="mb-3"><CopyField value={secret} label="Connection code" /></div>}
        <Callout tone="warning">
          Anyone with this code can run checks as you. Don&apos;t share it.
        </Callout>
      </Dialog>
    </div>
  );
}
