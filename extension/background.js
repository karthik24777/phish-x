// PHISH-X Link Guard — background service worker.
// Runs by default in the background: every top-level navigation is checked against
// the local PHISH-X service BEFORE you interact with the page.
//
// Policy (see README):
//   PHISHING   -> warning page
//   SUSPICIOUS -> quietly inspect the page first; warn only if the page looks like a data trap
//   SAFE       -> nothing happens
// If the PHISH-X service is not running the extension fails OPEN (links load normally)
// and the toolbar badge shows "off" so you know protection is down.

const API = "http://127.0.0.1:8765";
const ALLOW_MS = 24 * 60 * 60 * 1000; // "proceed anyway" is remembered for 24 hours

async function api(path, url, timeoutMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(API + path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url }),
      signal: ctl.signal,
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

async function isAllowed(host) {
  const { allow = {} } = await chrome.storage.local.get("allow");
  return !!allow[host] && allow[host] > Date.now();
}

function badge(tabId, text, color) {
  chrome.action.setBadgeText({ tabId, text });
  if (color) chrome.action.setBadgeBackgroundColor({ tabId, color });
}

chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0) return; // top-level navigations only

  let u;
  try { u = new URL(d.url); } catch { return; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return;
  if ((u.hostname === "127.0.0.1" || u.hostname === "localhost") && u.port === "8765") return;

  const { enabled = true } = await chrome.storage.local.get("enabled");
  if (!enabled) return;
  if (await isAllowed(u.hostname)) return;

  let r;
  try {
    r = await api("/check", d.url, 4000);
  } catch {
    badge(d.tabId, "off", "#6b7280"); // service down: fail open, but say so
    return;
  }

  let warn = r.verdict === "PHISHING";
  if (!warn && r.verdict === "SUSPICIOUS") {
    try {
      const s = await api("/sandbox", d.url, 15000);
      warn = s.verdict === "PHISHING";
    } catch { /* inspection failed: don't interrupt on a grey-zone score alone */ }
  }

  if (warn) {
    badge(d.tabId, "!", "#C1443A");
    chrome.tabs.update(d.tabId, {
      url: chrome.runtime.getURL("warning.html") + "?u=" + encodeURIComponent(d.url),
    });
  } else {
    badge(d.tabId, "", null);
  }
});
