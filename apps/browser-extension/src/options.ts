import { getSettings } from "./api.js";
import { normaliseServer, validToken } from "./core.js";

const $ = (id: string) => document.getElementById(id) as HTMLInputElement;

async function load() {
  const s = await getSettings();
  $("server").value = s.server;
  $("token").value = s.token;
  $("warnings").checked = s.warnings;
  const err = new URLSearchParams(location.search).get("error");
  if (err) $("status").textContent = err;
}

document.getElementById("form")!.addEventListener("submit", async (e) => {
  e.preventDefault();
  const server = normaliseServer($("server").value);
  const token = $("token").value.trim();
  const status = document.getElementById("status")!;
  if (!server || !validToken(token)) {
    status.textContent = "Enter the service address and the connection code from Settings → Browser extension.";
    return;
  }
  let warnings = $("warnings").checked;
  if (warnings) {
    // Site access is requested only for warnings, and only when the person asks for it.
    warnings = await chrome.permissions.request({
      permissions: ["webNavigation"],
      origins: ["https://*/*", "http://*/*"],
    });
    $("warnings").checked = warnings;
  } else {
    await chrome.permissions.remove({ permissions: ["webNavigation"], origins: ["https://*/*", "http://*/*"] });
  }
  await chrome.storage.local.set({ server, token, warnings });
  status.textContent = warnings ? "Saved. Warnings are on." : "Saved.";
});

void load();
