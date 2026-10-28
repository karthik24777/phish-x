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
