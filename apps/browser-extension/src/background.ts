import { checkLink, getSettings, reputation, resultPage } from "./api.js";
import { checkableUrl, domainOf } from "./core.js";

const MENU_ID = "psd-check-link";
// Domains checked recently, so each site is looked up at most once an hour.
const cache = new Map<string, { at: number; bad: boolean }>();
const allowedOnce = new Set<string>();

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: MENU_ID, title: "Check this link for scams", contexts: ["link"] });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== MENU_ID) return;
  const url = checkableUrl(info.linkUrl);
  if (!url) return;
  try {
    const scan = await checkLink(url);
    await chrome.tabs.create({ url: await resultPage(scan.id) });
  } catch (err) {
    await chrome.tabs.create({ url: chrome.runtime.getURL(`options.html?error=${encodeURIComponent(String(err))}`) });
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg?.type === "allow-once" && typeof msg.domain === "string") {
    allowedOnce.add(msg.domain);
    reply({ ok: true });
  }
});

// Optional warnings: only when the person turned them on and granted site access. Only the
// domain is sent, and only verified scam sites trigger a warning.
async function onNavigate(details: { frameId: number; url: string; tabId: number }) {
  if (details.frameId !== 0) return;
  const settings = await getSettings();
  if (!settings.warnings) return;
  const domain = domainOf(details.url);
  if (!domain || allowedOnce.has(domain)) return;
  const hit = cache.get(domain);
  let bad = hit && Date.now() - hit.at < 3_600_000 ? hit.bad : undefined;
  if (bad === undefined) {
    try {
      const rep = await reputation(domain);
      bad = rep.status === "verified_malicious";
      cache.set(domain, { at: Date.now(), bad });
    } catch {
      return;
    }
  }
  if (bad) {
    const target = chrome.runtime.getURL(
      `warning.html?domain=${encodeURIComponent(domain)}&url=${encodeURIComponent(details.url)}`,
    );
    await chrome.tabs.update(details.tabId, { url: target });
  }
}

function listenForNavigation() {
  if (chrome.webNavigation && !chrome.webNavigation.onBeforeNavigate.hasListener(onNavigate)) {
    chrome.webNavigation.onBeforeNavigate.addListener(onNavigate);
  }
}

listenForNavigation();
chrome.permissions.onAdded.addListener(listenForNavigation);
