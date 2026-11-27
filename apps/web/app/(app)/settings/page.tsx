"use client";

import { useQuery } from "@tanstack/react-query";
import { Building2, Check } from "lucide-react";
import { useSession } from "@/components/session";
import { Badge, ButtonLink, Card, CardHeader, Skeleton } from "@/components/ui";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/format";

type MyPlan = {
  code: "free" | "plus";
  name: string;
  until: string | null;
  features: string[];
  plans: { code: string; name: string; monthly_price_ghs: number; features: string[] }[];
};

export default function AccountSettingsPage() {
  const { me } = useSession();
  const plan = useQuery({ queryKey: ["my-plan"], queryFn: () => api<MyPlan>("/me/plan", { org: false }) });
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Your account" />
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-subtle">Name</dt>
            <dd className="font-medium">{me.user.full_name || "—"}</dd>
          </div>
          <div>
            <dt className="text-subtle">Email</dt>
            <dd className="font-medium">{me.user.email}</dd>
          </div>
          <div>
            <dt className="text-subtle">Two-step sign-in</dt>
            <dd>{me.user.mfa_enabled ? <Badge tone="success">On</Badge> : <Badge tone="warning">Off</Badge>}</dd>
          </div>
          <div>
            <dt className="text-subtle">Member since</dt>
            <dd>{formatDate(me.user.created_at)}</dd>
          </div>
        </dl>
      </Card>

      <Card>
        <CardHeader title="Personal protection plan" description="Your personal plan covers your private checks. Business workspaces have their own subscription." />
        {!plan.data ? (
          <Skeleton className="h-32" />
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {plan.data.plans.map((p) => {
              const current = p.code === plan.data.code;
              return (
                <div key={p.code} className={`rounded-xl border p-4 ${current ? "border-primary ring-1 ring-primary" : "border-border"}`}>
                  <div className="flex items-center justify-between">
                    <h3 className="font-heading font-semibold">{p.name}</h3>
                    {current && <Badge tone="primary">Current</Badge>}
                  </div>
                  <p className="mt-1 font-heading text-2xl font-bold">
                    GH₵{p.monthly_price_ghs}
                    <span className="text-sm font-normal text-subtle"> / month</span>
                  </p>
                  <ul className="mt-3 space-y-1.5 text-sm text-muted">
                    {p.features.map((f) => (
                      <li key={f} className="flex gap-2">
                        <Check className="mt-0.5 size-4 shrink-0 text-success" aria-hidden /> {f}
                      </li>
                    ))}
                  </ul>
                  {current && plan.data.until && <p className="mt-3 text-xs text-subtle">Renews {formatDate(plan.data.until)}</p>}
                  {!current && p.code === "plus" && (
                    <p className="mt-3 text-xs text-subtle">Personal Plus checkout with Mobile Money is coming soon.</p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Card>

      <Card>
        <CardHeader
          title="Business workspaces"
          description="Protect your team: shared dashboards, investigations, bulk checks and the business API."
          action={
            <ButtonLink href="/onboarding" variant="secondary" size="sm">
              <Building2 className="size-4" /> New workspace
            </ButtonLink>
          }
        />
        {me.memberships.length ? (
          <ul className="divide-y divide-border text-sm">
            {me.memberships.map((m) => (
              <li key={m.organisation_id} className="flex justify-between py-2">
                <span className="font-medium">{m.organisation_name}</span>
                <span className="text-subtle">{m.role_label}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">You aren&apos;t part of a business workspace.</p>
        )}
      </Card>
    </div>
  );
}
