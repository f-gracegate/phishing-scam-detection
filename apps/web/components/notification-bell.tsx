"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useOrgKey, useSession } from "@/components/session";
import { cn } from "@/components/ui";
import { api } from "@/lib/api";
import { timeAgo } from "@/lib/format";
import type { NotificationList } from "@/lib/types";

export function NotificationBell() {
  const { orgId } = useSession();
  const queryClient = useQueryClient();
  const key = useOrgKey("notifications");
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const { data } = useQuery({
    queryKey: key,
    queryFn: () => api<NotificationList>("/notifications"),
    enabled: Boolean(orgId),
    refetchInterval: 60_000,
  });
  const markRead = useMutation({
    mutationFn: (ids?: string[]) =>
      api<NotificationList>("/notifications/read", { method: "POST", body: { ids: ids ?? null } }),
    onSuccess: (res) => queryClient.setQueryData(key, res),
  });

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  if (!orgId) return null;
  const unread = data?.unread ?? 0;

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="relative rounded-lg p-2 text-muted hover:bg-surface-2 hover:text-fg"
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
        aria-expanded={open}
      >
        <Bell className="size-[18px]" />
        {unread > 0 && (
          <span className="absolute top-1 right-1 flex min-w-4 items-center justify-center rounded-full bg-critical px-1 text-[10px] leading-4 font-semibold text-white">
            {unread > 99 ? "99+" : unread}
          </span>
        )}
      </button>
      {open && (
        <div className="absolute right-0 z-30 mt-2 w-[min(24rem,calc(100vw-2rem))] overflow-hidden rounded-xl border border-border bg-surface shadow-lg">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <p className="text-sm font-semibold">Notifications</p>
            {unread > 0 && (
              <button
                type="button"
                className="text-xs font-medium text-primary-text hover:underline"
                onClick={() => markRead.mutate(undefined)}
              >
                Mark all read
              </button>
            )}
          </div>
          <ul className="max-h-96 divide-y divide-border overflow-y-auto">
            {(data?.items ?? []).map((n) => (
              <li key={n.id}>
                <Link
                  href={n.link ?? "/home"}
                  onClick={() => {
                    setOpen(false);
                    if (!n.read) markRead.mutate([n.id]);
                  }}
                  className={cn("flex gap-3 px-4 py-3 hover:bg-surface-2", !n.read && "bg-primary-soft/40")}
                >
                  <span className={cn("mt-1.5 size-2 shrink-0 rounded-full", n.severity === "critical" || n.severity === "high" ? "bg-critical" : n.severity === "medium" ? "bg-high" : "bg-primary")} />
                  <span className="min-w-0 flex-1">
                    <span className={cn("block text-sm", !n.read && "font-medium")}>{n.title}</span>
                    <span className="line-clamp-2 block text-xs text-muted">{n.body}</span>
                    <span className="mt-0.5 block text-[11px] text-subtle">{timeAgo(n.created_at)}</span>
                  </span>
                </Link>
              </li>
            ))}
            {data && data.items.length === 0 && (
              <li className="px-4 py-8 text-center text-sm text-muted">You&apos;re all caught up.</li>
            )}
          </ul>

        </div>
      )}
    </div>
  );
}
