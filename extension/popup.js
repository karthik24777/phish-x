const $ = (id) => document.getElementById(id);
(async () => {
  const { enabled = true } = await chrome.storage.local.get("enabled");
  $("en").checked = enabled;
  $("en").addEventListener("change", (e) => chrome.storage.local.set({ enabled: e.target.checked }));
  try {
    const r = await fetch("http://127.0.0.1:8765/health", { signal: AbortSignal.timeout(2000) });
    const h = await r.json();
    $("st").classList.add("ok");
    $("stxt").textContent = "Protection service running";
    $("n1").textContent = h.stats.checked;
    $("n2").textContent = h.stats.blocked;
    $("n3").textContent = h.stats.sandboxed;
  } catch {
    $("st").classList.add("bad");
    $("stxt").textContent = "Service not running — links are NOT being checked";
    $("hint").textContent = "Start it with start.sh (Mac/Linux) or start.bat (Windows).";
  }
})();

// Sites you chose to always trust (exact host names). Remove any time.
async function renderTrusted() {
  const box = $("tr");
  while (box.firstChild) box.removeChild(box.firstChild);
  const { trusted = {} } = await chrome.storage.local.get("trusted");
  const hosts = Object.keys(trusted);
  if (!hosts.length) return;
  const h = document.createElement("h2"); h.textContent = "Sites you trust"; box.appendChild(h);
  hosts.forEach((host) => {
    const row = document.createElement("div"); row.className = "t";
    const name = document.createElement("span"); name.textContent = host;
    const rm = document.createElement("button"); rm.textContent = "Remove";
    rm.addEventListener("click", async () => {
      const cur = (await chrome.storage.local.get("trusted")).trusted || {};
      delete cur[host]; await chrome.storage.local.set({ trusted: cur }); renderTrusted();
    });
    row.append(name, rm); box.appendChild(row);
  });
}
renderTrusted();
