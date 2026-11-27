import { DEFAULT_SETTINGS, normaliseServer, type Settings, type Verdict } from "./core.js";

export async function getSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get(DEFAULT_SETTINGS);
  return { ...DEFAULT_SETTINGS, ...(stored as Partial<Settings>) };
}

export type ScanResult = {
  id: string;
  status: string;
  verdict: Verdict | null;
  risk_score: number | null;
  headline: string | null;
  summary: string | null;
  evidence: { title: string; weight: number; source_label: string }[];
  recommendations: string[];
};

export type Reputation = {
  domain: string;
  status: "verified_malicious" | "verified_suspicious" | "reported" | "no_record";
  category_label: string | null;
  message: string;
};

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const settings = await getSettings();
  if (!settings.server || !settings.token) throw new Error("Connect the extension in its settings first.");
  const res = await fetch(`${normaliseServer(settings.server)}/api/v1${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: `Bearer ${settings.token}`,
      ...(init.headers ?? {}),
    },
  });
  if (!res.ok) {
    let message = `The service returned an error (${res.status}).`;
    try {
      const body = await res.json();
      if (body?.error?.message) message = body.error.message;
    } catch {
      /* keep default */
    }
    throw new Error(message);
  }
  return (await res.json()) as T;
}

export function checkLink(url: string): Promise<ScanResult> {
  return call<ScanResult>("/scans/url?wait=true", { method: "POST", body: JSON.stringify({ url }) });
}

export function reputation(domain: string): Promise<Reputation> {
  return call<Reputation>(`/scans/reputation?domain=${encodeURIComponent(domain)}`);
}

export async function resultPage(id: string): Promise<string> {
  const settings = await getSettings();
  return `${normaliseServer(settings.server)}/scans/${id}`;
}
