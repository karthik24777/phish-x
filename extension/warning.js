// PHISH-X warning page.
// SECURITY: this page displays data that came from an attacker-controlled site
// (hostnames, form targets, labels). Everything is inserted with textContent /
// createElement — never innerHTML — so a hostile page cannot inject script here.

const API = "http://127.0.0.1:8765";
const ALLOW_MS = 24 * 60 * 60 * 1000;
const $ = (id) => document.getElementById(id);

const target = new URLSearchParams(location.search).get("u") || "";

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

async function post(path) {
  const r = await fetch(API + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: target }),
  });
  if (!r.ok) throw new Error("PHISH-X service returned " + r.status);
  return r.json();
}

function stateFor(verdict) {
  if (verdict === "PHISHING") return "danger";
  if (verdict === "SUSPICIOUS") return "suspicious";
  return "safe";
}

function applyVerdict(r, opts = {}) {
  const s = stateFor(r.verdict);
  document.body.className = s === "danger" ? "" : "state-" + s;

  const headlines = {
    danger: ["This link looks dangerous", "PHISH-X thinks this page is trying to steal information. Do not enter any passwords, card details or codes on it."],
    suspicious: ["This link looks suspicious", "PHISH-X could not rule out a scam. Be careful before entering anything."],
    safe: ["This link looks safe", "No strong warning signs were found."],
  };
  $("headline").textContent = headlines[s][0];
  $("sub").textContent = r.impersonates
    ? "This address is pretending to be " + r.impersonates + ". It is not the real site."
    : headlines[s][1];

  $("meter").hidden = false;
  $("score").textContent = r.risk_score;
  $("chip").textContent = r.verdict;
  requestAnimationFrame(() => { $("barfill").style.width = r.risk_score + "%"; });

  const ul = $("evidence");
  clear(ul);
  (r.evidence || []).forEach((t) => ul.appendChild(el("li", "", t)));
  $("why").hidden = !(r.evidence && r.evidence.length);
  $("actions").hidden = false;
  if (opts.afterSandbox) $("btn-sandbox").hidden = true;
}

function renderSandbox(r) {
  const page = r.page || {};
  const body = $("sb-body");
  clear(body);

  if (!page.fetched) {
    $("sb-status").textContent = "The sandbox could not open this page: " + (page.error || "unknown error") +
      " The verdict above is based on the link text alone.";
    return;
  }

  $("sb-status").textContent = "Opened in the sandbox. Page title: " + (page.title || "(none)") +
    " — status " + page.status + ".";

  // What it asks for
  body.appendChild(el("h3", "", "Information this page asks for"));
  const info = page.information_requested || [];
  if (!info.length) {
    body.appendChild(el("p", "note", "No data-collection fields were found in the page's HTML."));
  } else {
    const t = el("table");
    const head = el("tr");
    ["Item", "Risk"].forEach((h) => head.appendChild(el("th", "", h)));
    t.appendChild(head);
    info.forEach((i) => {
      const row = el("tr");
      row.appendChild(el("td", "", i.label));
      const td = el("td");
      td.appendChild(el("span", "tag " + i.risk, i.risk.toUpperCase()));
      row.appendChild(td);
      t.appendChild(row);
    });
    body.appendChild(t);
  }

  // Objective
  const objs = page.likely_objectives || [];
  if (objs.length) {
    body.appendChild(el("h3", "", "What the attacker is likely after (based on what the page asks for)"));
    objs.forEach((o) => {
      const d = el("div", "obj");
      d.appendChild(el("b", "", o.objective));
      d.appendChild(el("span", "", o.why));
      body.appendChild(d);
    });
  }

  // Where data goes
  const forms = page.forms || [];
  if (forms.length) {
    body.appendChild(el("h3", "", "Where the data would be sent"));
    forms.forEach((f) => {
      const d = el("div", "obj");
      const line = el("div", "kv", f.method + " → " + f.action);
      d.appendChild(line);
      if (f.sends_to_other_domain) d.appendChild(el("span", "warnline", "This is a different website than the page you were on."));
      if (f.insecure_transport) d.appendChild(el("span", "warnline", " Sent without encryption."));
      body.appendChild(d);
    });
  }

  // Other findings
  const fs = page.findings || [];
  if (fs.length) {
    body.appendChild(el("h3", "", "Other findings"));
    const ul = el("ul", "plain");
    fs.forEach((f) => ul.appendChild(el("li", "", f)));
    body.appendChild(ul);
  }

  body.appendChild(el("p", "note", "Mode: " + (page.sandbox_mode || "static") + ". Interaction: " + (page.interaction || "none") + "."));
}

async function init() {
  let u;
  try { u = new URL(target); } catch { u = null; }
  if (!u || (u.protocol !== "http:" && u.protocol !== "https:")) {
    $("headline").textContent = "Nothing to check";
    $("sub").textContent = "This page was opened without a valid link.";
    return;
  }
  $("target").textContent = target;
  $("target").title = target;

  try {
    applyVerdict(await post("/check"));
  } catch (e) {
    document.body.className = "state-suspicious";
    $("headline").textContent = "PHISH-X service is not reachable";
    $("sub").textContent = "Start the PHISH-X service on this computer (see README), then reload. " + e.message;
    $("actions").hidden = false;
    $("btn-sandbox").hidden = true;
  }
}

$("btn-back").addEventListener("click", () => {
  history.back();
  setTimeout(() => window.close(), 250);
});

$("btn-sandbox").addEventListener("click", async () => {
  const btn = $("btn-sandbox");
  btn.disabled = true;
  $("sandbox").hidden = false;
  clear($("sb-body"));
  $("sb-status").textContent = "";
  const sp = el("span", "spin");
  $("sb-status").appendChild(sp);
  $("sb-status").appendChild(document.createTextNode("Opening the page in the PHISH-X sandbox. Your browser is not loading it…"));
  try {
    const r = await post("/sandbox");
    renderSandbox(r);
    applyVerdict(r, { afterSandbox: true });
    $("sb-title").textContent = "Sandbox result: " + r.verdict.toLowerCase().replace("likely ", "");
    $("sandbox").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    $("sb-status").textContent = "Sandbox check failed: " + e.message;
    btn.disabled = false;
  }
});

let armed = false;
$("btn-proceed").addEventListener("click", async () => {
  const b = $("btn-proceed");
  if (!armed) {
    armed = true;
    b.classList.add("armed");
    b.textContent = "Click again to open it anyway — you may lose passwords or money";
    setTimeout(() => { armed = false; b.classList.remove("armed"); b.textContent = "Proceed anyway (not recommended)"; }, 6000);
    return;
  }
  const host = new URL(target).hostname;
  const { allow = {} } = await chrome.storage.local.get("allow");
  allow[host] = Date.now() + ALLOW_MS;
  await chrome.storage.local.set({ allow });
  location.replace(target);
});

init();
