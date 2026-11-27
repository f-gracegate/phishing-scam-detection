import { checkLink, getSettings, resultPage, type ScanResult } from "./api.js";
import { checkableUrl, VERDICT_TEXT } from "./core.js";

const $ = (id: string) => document.getElementById(id) as HTMLElement;

function render(scan: ScanResult) {
  const v = VERDICT_TEXT[scan.verdict ?? "unknown"];
  $("result").hidden = false;
  $("verdict").textContent = scan.verdict === "unknown" ? v.label : `${v.label} · ${scan.risk_score}/100`;
  $("verdict").style.color = v.colour;
  $("headline").textContent = scan.headline ?? "";
  const list = $("reasons");
  list.replaceChildren();
  for (const e of scan.evidence.filter((x) => x.weight > 0).slice(0, 3)) {
    const li = document.createElement("li");
    li.textContent = `${e.title} (${e.source_label})`;
    list.append(li);
  }
  const next = $("next");
  next.textContent = scan.recommendations[0] ?? "";
  void resultPage(scan.id).then((href) => (($("details") as HTMLAnchorElement).href = href));
}

async function main() {
  const settings = await getSettings();
  if (!settings.server || !settings.token) {
    $("setup").hidden = false;
    $("main").hidden = true;
    return;
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = checkableUrl(tab?.url);
  $("url").textContent = url ? new URL(url).hostname : "This page can't be checked.";
  const button = $("check") as HTMLButtonElement;
  button.disabled = !url;
  button.addEventListener("click", async () => {
    if (!url) return;
    button.disabled = true;
    button.textContent = "Checking…";
    $("error").textContent = "";
    try {
      render(await checkLink(url));
    } catch (err) {
      $("error").textContent = err instanceof Error ? err.message : String(err);
    } finally {
      button.disabled = false;
      button.textContent = "Check this page";
    }
  });
}

$("open-options").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("open-options-2")?.addEventListener("click", () => chrome.runtime.openOptionsPage());
void main();
