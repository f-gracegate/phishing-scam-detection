// Pure helpers shared by the popup, background worker and options page (and unit tests).

export type Settings = { server: string; token: string; warnings: boolean };

export const DEFAULT_SETTINGS: Settings = { server: "", token: "", warnings: false };

export type Verdict = "low" | "caution" | "suspicious" | "high" | "critical" | "unknown";

export const VERDICT_TEXT: Record<Verdict, { label: string; colour: string }> = {
  critical: { label: "Critical risk", colour: "#DC2626" },
  high: { label: "High risk", colour: "#DC2626" },
  suspicious: { label: "Suspicious", colour: "#EA580C" },
  caution: { label: "Caution", colour: "#D97706" },
  low: { label: "Low risk", colour: "#15803D" },
  unknown: { label: "Unknown — no warning signs found", colour: "#475467" },
};

/** Only normal web pages can be checked; browser pages and local files are skipped. */
export function checkableUrl(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)) return null;
    return u.href;
  } catch {
    return null;
  }
}

/** The domain sent for automatic warnings. Never the path, query or fragment. */
export function domainOf(raw: string): string | null {
  const url = checkableUrl(raw);
  return url ? new URL(url).hostname.toLowerCase() : null;
}

export function normaliseServer(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, "");
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

export function validToken(token: string): boolean {
  return /^pse_[A-Za-z0-9_-]{20,}$/.test(token.trim());
}
