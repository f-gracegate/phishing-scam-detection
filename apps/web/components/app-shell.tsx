"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BarChart3,
  BookOpen,
  Briefcase,
  Building2,
  ChevronDown,
  Database,
  FileWarning,
  Flag,
  History,
  Home,
  Inbox,
  KeyRound,
  Link2,
  LogOut,
  Mail,
  Megaphone,
  Menu,
  MessageSquareWarning,
  Moon,
  QrCode,
  Radar,
  ScanSearch,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Tag,
  ThumbsDown,
  User,
  Users,
  Webhook,
  X,
  Layers,
  type LucideIcon,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { SubscriptionBanner } from "@/components/billing-ui";
import { DeletionBanner } from "@/components/deletion-banner";
import { NotificationBell } from "@/components/notification-bell";
import { PoweredBy, ProductMark } from "@/components/powered-by";
import { toggleTheme } from "@/components/providers";
import { useSession } from "@/components/session";
import { Avatar, cn } from "@/components/ui";
import { api } from "@/lib/api";

type NavItem = {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Organisation permission (business workspace). */
  permission?: string;
  /** Platform threat-intelligence permission. */
  intel?: string;
  exact?: boolean;
};

type NavSection = { title?: string; items: NavItem[]; scope: "personal" | "org" | "both" | "intel" };

const NAV: NavSection[] = [
  {
    title: "Protection centre",
    scope: "both",
    items: [
      { href: "/home", label: "Home", icon: Home },
      { href: "/check/link", label: "Check a link", icon: Link2 },
      { href: "/check/message", label: "Check a message", icon: MessageSquareWarning },
      { href: "/check/email", label: "Check an email", icon: Mail },
      { href: "/check/qr", label: "Scan a QR code", icon: QrCode },
      { href: "/report", label: "Report a scam", icon: Flag, exact: true },
      { href: "/scans", label: "Scan history", icon: History },
      { href: "/reports", label: "My reports", icon: FileWarning },
      { href: "/safety", label: "Safety centre", icon: BookOpen },
    ],
  },
  {
    title: "Business",
    scope: "org",
    items: [
      { href: "/business", label: "Dashboard", icon: BarChart3, permission: "analytics:read", exact: true },
      { href: "/business/cases", label: "Investigations", icon: Briefcase, permission: "cases:read" },
      { href: "/business/bulk", label: "Bulk scan", icon: Layers, permission: "scans:bulk" },
      { href: "/business/brands", label: "Protected brands", icon: Tag, permission: "analytics:read" },
      { href: "/business/api", label: "API & usage", icon: KeyRound, permission: "api:manage" },
      { href: "/business/webhooks", label: "Webhooks", icon: Webhook, permission: "webhooks:manage" },
      { href: "/team", label: "Team", icon: Users, permission: "members:read" },
    ],
  },
  {
    title: "Threat intelligence",
    scope: "intel",
    items: [
      { href: "/intel", label: "Overview", icon: Radar, intel: "intel:read", exact: true },
      { href: "/intel/queue", label: "Report queue", icon: Inbox, intel: "intel:read" },
      { href: "/intel/indicators", label: "Indicators", icon: Database, intel: "intel:read" },
      { href: "/intel/feedback", label: "Disputed results", icon: ThumbsDown, intel: "intel:read" },
      { href: "/intel/campaigns", label: "Campaigns", icon: Megaphone, intel: "intel:read" },
      { href: "/intel/sources", label: "Sources & brands", icon: ShieldCheck, intel: "intel:read" },
    ],
  },
];

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  const { can, intel, orgId, me } = useSession();
  const sections = NAV.filter(
    (s) =>
      s.scope === "both" ||
      (s.scope === "org" && orgId) ||
      (s.scope === "personal" && !orgId) ||
      (s.scope === "intel" && intel("intel:read")),
  );
  return (
    <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4" aria-label="Main">
      {sections.map((section, i) => (
        <div key={i}>
          {section.title && (
            <p className="mb-1.5 px-3 text-[11px] font-medium tracking-wider text-sidebar-muted uppercase">
              {section.title}
            </p>
          )}
          <ul className="space-y-0.5">
            {section.items
              .filter((item) => (!item.permission || can(item.permission)) && (!item.intel || intel(item.intel)))
              .map((item) => {
                const active = item.exact
                  ? pathname === item.href
                  : pathname === item.href || pathname.startsWith(`${item.href}/`);
                const Icon = item.icon;
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      onClick={onNavigate}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                        active
                          ? "bg-sidebar-active font-medium text-white"
                          : "text-sidebar-text hover:bg-sidebar-active/60 hover:text-white",
                      )}
                    >
                      <Icon className={cn("size-[18px]", active ? "text-blue-400" : "")} aria-hidden />
                      <span className="flex-1">{item.label}</span>
                    </Link>
                  </li>
                );
              })}
          </ul>
        </div>
      ))}
      <ul className="space-y-0.5">
        <li>
          <Link
            href="/settings"
            onClick={onNavigate}
            className={cn(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm",
              pathname.startsWith("/settings")
                ? "bg-sidebar-active font-medium text-white"
                : "text-sidebar-text hover:bg-sidebar-active/60 hover:text-white",
            )}
          >
            <Settings className="size-[18px]" aria-hidden />
            Settings
          </Link>
        </li>
        {me.user.is_platform_admin && process.env.NODE_ENV === "development" && (
          <li>
            <Link
              href="/dev/mailbox"
              onClick={onNavigate}
              className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-sidebar-text hover:bg-sidebar-active/60 hover:text-white"
            >
              <ScanSearch className="size-[18px]" aria-hidden />
              Dev mailbox
            </Link>
          </li>
        )}
      </ul>
    </nav>
  );
}

function ApiStatus() {
  const { data, isError } = useQuery({
    queryKey: ["health"],
    queryFn: () => fetch("/api/health").then((r) => r.json() as Promise<{ status: string }>),
    refetchInterval: 60_000,
  });
  const online = !isError && data?.status === "ok";
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] text-sidebar-muted">
      <span
        className={cn("size-1.5 rounded-full", online ? "bg-green-400" : "bg-amber-400")}
        aria-hidden
      />
      {online ? "Online" : data || isError ? "Degraded" : "Connecting"}
    </span>
  );
}

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <div className="flex h-full flex-col bg-sidebar">
      <div className="flex items-center justify-between border-b border-sidebar-border px-5 py-4">
        <ProductMark inverted />
      </div>
      <div className="px-5 pt-3">
        <ApiStatus />
      </div>
      <NavLinks onNavigate={onNavigate} />
      <div className="border-t border-sidebar-border px-5 py-4">
        <PoweredBy inverted />
      </div>
    </div>
  );
}

function OrgSwitcher() {
  const { me, orgId, switchOrg, membership } = useSession();
  if (me.memberships.length === 0) {
    return (
      <span className="flex items-center gap-2 text-sm font-semibold text-fg">
        <User className="size-4 text-subtle" aria-hidden /> Personal protection
      </span>
    );
  }
  return (
    <label className="relative flex min-w-0 items-center gap-2">
      {orgId ? (
        <Building2 className="size-4 shrink-0 text-subtle" aria-hidden />
      ) : (
        <User className="size-4 shrink-0 text-subtle" aria-hidden />
      )}
      <span className="sr-only">Workspace</span>
      <select
        value={orgId ?? ""}
        onChange={(e) => switchOrg(e.target.value || null)}
        className="max-w-[16rem] min-w-0 appearance-none truncate rounded-lg bg-transparent py-1.5 pr-7 pl-1 text-sm font-semibold text-fg hover:bg-surface-2 focus:outline-none"
      >
        <option value="">Personal (private)</option>
        {me.memberships.map((m) => (
          <option key={m.organisation_id} value={m.organisation_id}>
            {m.organisation_name}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-1.5 size-4 text-subtle" aria-hidden />
      {membership && (
        <span className="hidden truncate text-xs text-subtle lg:inline">{membership.role_label}</span>
      )}
    </label>
  );
}

function UserMenu() {
  const { me } = useSession();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const logout = useMutation({
    mutationFn: () => api("/auth/logout", { method: "POST", org: false, noRefresh: true }),
    onSettled: () => {
      // Drop every cached response so nothing from this session survives sign-out.
      queryClient.clear();
      router.replace("/login");
    },
  });

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  const name = me.user.full_name || me.user.email;
  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 rounded-lg p-1 hover:bg-surface-2"
        aria-expanded={open}
        aria-haspopup="menu"
      >
        <Avatar name={name} />
        <span className="hidden text-left text-sm leading-tight md:block">
          <span className="block font-medium text-fg">{name}</span>
          <span className="block text-xs text-subtle">{me.user.email}</span>
        </span>
        <ChevronDown className="hidden size-4 text-subtle md:block" aria-hidden />
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 z-30 mt-2 w-56 rounded-xl border border-border bg-surface p-1.5 shadow-lg"
        >
          <Link
            role="menuitem"
            href="/settings/security"
            onClick={() => setOpen(false)}
            className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-fg hover:bg-surface-2"
          >
            <ShieldAlert className="size-4 text-subtle" /> Account security
          </Link>
          <Link
            role="menuitem"
            href="/onboarding"
            onClick={() => setOpen(false)}
            className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-fg hover:bg-surface-2"
          >
            <Building2 className="size-4 text-subtle" /> New business workspace
          </Link>
          <button
            role="menuitem"
            type="button"
            onClick={() => logout.mutate()}
            className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-fg hover:bg-surface-2"
          >
            <LogOut className="size-4 text-subtle" /> Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen lg:pl-64">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 lg:block">
        <Sidebar />
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true">
          <div className="absolute inset-0 bg-slate-950/60" onClick={() => setMobileOpen(false)} />
          <div className="absolute inset-y-0 left-0 w-72 max-w-[85%] shadow-xl">
            <button
              type="button"
              onClick={() => setMobileOpen(false)}
              className="absolute top-4 right-3 z-10 rounded-md p-1 text-sidebar-text hover:bg-sidebar-active"
              aria-label="Close menu"
            >
              <X className="size-5" />
            </button>
            <Sidebar onNavigate={() => setMobileOpen(false)} />
          </div>
        </div>
      )}

      <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-border bg-surface/90 px-4 backdrop-blur sm:px-6">
        <button
          type="button"
          onClick={() => setMobileOpen(true)}
          className="rounded-md p-1.5 text-muted hover:bg-surface-2 lg:hidden"
          aria-label="Open menu"
        >
          <Menu className="size-5" />
        </button>
        <div className="min-w-0 flex-1">
          <OrgSwitcher />
        </div>
        <NotificationBell />
        <button
          type="button"
          onClick={toggleTheme}
          className="rounded-lg p-2 text-muted hover:bg-surface-2 hover:text-fg"
          aria-label="Toggle dark mode"
          title="Toggle dark mode"
        >
          <Moon className="size-[18px] dark:hidden" />
          <Sun className="hidden size-[18px] dark:block" />
        </button>
        <UserMenu />
      </header>

      <main className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6 lg:py-8">
        <DeletionBanner />
        <SubscriptionBanner />
        {children}
      </main>
    </div>
  );
}
