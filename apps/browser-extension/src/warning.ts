const params = new URLSearchParams(location.search);
const domain = params.get("domain") ?? "";
const url = params.get("url") ?? "";
document.getElementById("domain")!.textContent = domain;
document.getElementById("back")!.addEventListener("click", () => history.length > 2 ? history.go(-2) : window.close());
document.getElementById("continue")!.addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "allow-once", domain });
  if (/^https?:\/\//.test(url)) location.href = url;
});
