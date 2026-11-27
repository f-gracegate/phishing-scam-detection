"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { usePathname, useRouter } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { Spinner } from "@/components/ui";
import { api, ApiError, GATE_EVENT, setActiveOrgId } from "@/lib/api";
import type { Me, MembershipSummary } from "@/lib/types";

const ORG_KEY = "psd-org";
const ORG_EVENT = "psd:org-changed";

// Pages that only make sense inside a business workspace.
const ORG_REQUIRED = ["/business", "/team", "/settings/organisation", "/settings/audit",
  "/settings/subscription"];
export const PERSONAL = "personal";

type Session = {
  me: Me;
  orgId: string | null;
  membership: MembershipSummary | null;
  can: (permission: string) => boolean;
  /** Switch to a business workspace, or to the personal space with null. */
  switchOrg: (id: string | null) => void;
  /** Platform threat-intelligence permission (analysts, reviewers, administrators). */
  intel: (permission: string) => boolean;
};

const SessionContext = createContext<Session | null>(null);

export function useSession(): Session {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used inside <SessionGate>");
  return ctx;
}

/** Org-scoped query keys start with this, so switching organisation refetches everything. */
export function useOrgKey(...parts: unknown[]) {
  const { orgId } = useSession();
  return ["org", orgId, ...parts];
}

function subscribeOrg(callback: () => void) {
  window.addEventListener(ORG_EVENT, callback);
  window.addEventListener("storage", callback);
  return () => {
    window.removeEventListener(ORG_EVENT, callback);
    window.removeEventListener("storage", callback);
  };
}

function readStoredOrg(): string | null {
  try {
    return localStorage.getItem(ORG_KEY);
  } catch {
    return null;
  }
}

export function rememberOrg(id: string) {
  try {
    localStorage.setItem(ORG_KEY, id);
  } catch {
    /* ignore */
  }
  window.dispatchEvent(new Event(ORG_EVENT));
}

function FullPageSpinner() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <Spinner className="size-6" />
    </div>
  );
}

export function SessionGate({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const queryClient = useQueryClient();
  const storedOrg = useSyncExternalStore(subscribeOrg, readStoredOrg, () => null);

  const meQuery = useQuery({
    queryKey: ["me"],
    queryFn: () => api<Me>("/auth/me", { org: false }),
    staleTime: 60_000,
  });
  const me = meQuery.data;
  const memberships = me?.memberships ?? [];
  // The personal space is the default; a business workspace only when chosen.
  const orgRequired = ORG_REQUIRED.some((p) => pathname.startsWith(p));
  const membership =
    memberships.find((m) => m.organisation_id === storedOrg) ??
    (orgRequired ? (memberships[0] ?? null) : null);
  const orgId = membership?.organisation_id ?? null;
  setActiveOrgId(orgId);

  const mfaBlocked = Boolean(membership?.require_mfa && me && !me.user.mfa_enabled);

  // Where should this user be right now?
  let redirectTo: string | null = null;
  const error = meQuery.error;
  if (error instanceof ApiError && error.status === 401) {
    redirectTo = `/login?next=${encodeURIComponent(pathname)}`;
  } else if (me?.user.must_change_password) {
    redirectTo = "/change-password";
  } else if (me && !membership && orgRequired) {
    redirectTo = "/onboarding";
  } else if (me && mfaBlocked && !pathname.startsWith("/settings/security")) {
    redirectTo = "/settings/security?required=1";
  }

  useEffect(() => {
    if (redirectTo) router.replace(redirectTo);
  }, [redirectTo, router]);

  // Server says the session or organisation access changed: re-check who we are.
  useEffect(() => {
    const onGate = (event: Event) => {
      const code = (event as CustomEvent<string>).detail;
      if (code === "password_change_required") router.replace("/change-password");
      else queryClient.invalidateQueries({ queryKey: ["me"] });
    };
    window.addEventListener(GATE_EVENT, onGate);
    return () => window.removeEventListener(GATE_EVENT, onGate);
  }, [queryClient, router]);

  const switchOrg = useCallback(
    (id: string | null) => {
      rememberOrg(id ?? PERSONAL);
      router.push(id ? "/business" : "/home");
    },
    [router],
  );

  const value = useMemo<Session | null>(() => {
    if (!me) return null;
    const perms = new Set(membership?.permissions ?? []);
    const intelPerms = new Set(me.intel_permissions ?? []);
    return {
      me,
      orgId,
      membership,
      can: (p) => perms.has(p),
      switchOrg,
      intel: (p) => intelPerms.has(p),
    };
  }, [me, orgId, membership, switchOrg]);

  if (meQuery.isPending || redirectTo || !value) {
    if (error && !(error instanceof ApiError && error.status === 401)) {
      return (
        <div className="flex min-h-screen flex-col items-center justify-center gap-2 p-6 text-center">
          <p className="font-medium">We couldn&apos;t load your workspace.</p>
          <p className="text-sm text-muted">{(error as Error).message}</p>
          <button className="mt-2 text-sm text-primary" onClick={() => meQuery.refetch()}>
            Try again
          </button>
        </div>
      );
    }
    return <FullPageSpinner />;
  }

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}
