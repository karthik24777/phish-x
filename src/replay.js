// PHISH-X sandbox replay viewer (used by the dashboard and the link popup).
// Everything from the inspected site goes in via textContent; the only HTML-ish thing set is <img src="data:image/jpeg...">
// produced by PHISH-X's own sandbox browser.
(function () {
  const css = `
  .rp{margin-top:12px;border:1px solid var(--line,#ddd);border-radius:12px;overflow:hidden}
  .rp h3{margin:0;padding:10px 14px;font-size:15px;background:var(--mint,#e4f2ec);color:var(--ink,#111)}
  .rp-sum{display:flex;flex-wrap:wrap;gap:8px;padding:10px 14px}
  .rp-chip{background:var(--bg,#f3f6f5);border:1px solid var(--line,#ddd);border-radius:99px;padding:3px 11px;font-size:12.5px}
  .rp-chip b{color:var(--green,#2a6a52)}
  .rp-flow{display:flex;align-items:stretch;gap:6px;padding:6px 14px 12px;flex-wrap:wrap}
  .rp-box{flex:1 1 150px;border:1px solid var(--line,#ddd);border-radius:10px;padding:8px 10px;font-size:13px;background:var(--card,#fff)}
  .rp-box small{display:block;color:var(--mut,#666);font-size:11.5px;margin-bottom:2px}
  .rp-box.bad{border-color:#e63946;background:rgba(230,57,70,.08)}
  .rp-arrow{align-self:center;font-size:20px;color:var(--mut,#666)}
  .rp-stage{padding:0 14px 12px}
  .rp-img{width:100%;max-height:430px;object-fit:contain;object-position:top;border:1px solid var(--line,#ddd);border-radius:8px;background:#fff;display:block}
  .rp-cap{margin:8px 0 2px;font-weight:600;font-size:14px}.rp-det{margin:0;font-size:13px;color:var(--mut,#666)}
  .rp-ctl{display:flex;gap:6px;align-items:center;padding:0 14px 12px;flex-wrap:wrap}
  .rp-ctl button{padding:6px 12px;font-size:13px}
  .rp-dot{width:10px;height:10px;border-radius:50%;background:var(--line,#ccc);border:0;padding:0;cursor:pointer}
  .rp-dot.on{background:var(--green,#2a6a52)}
  .rp-net{padding:0 14px 14px;overflow-x:auto}.rp-net table{font-size:12.5px;width:100%;border-collapse:collapse}
  .rp-net td,.rp-net th{padding:3px 6px;border-bottom:1px solid var(--line,#ddd);text-align:left;white-space:nowrap}
  .rp-net .x{color:#c0392b;font-weight:600}.rp-net .a{color:var(--mut,#666)}`;
  function el(t, x, c) { const e = document.createElement(t); if (c) e.className = c; if (x !== undefined && x !== null) e.textContent = String(x); return e; }
  window.renderReplay = function (host, page) {
    const rp = page && page.replay;
    if (!rp) return;
    if (!document.getElementById("rp-css")) { const s = document.createElement("style"); s.id = "rp-css"; s.textContent = css; document.head.appendChild(s); }
    const box = el("div", null, "rp");
    box.appendChild(el("h3", "Sandbox replay: what PHISH-X did inside the isolated browser"));
    const f = rp.flow || {};
    const sum = el("div", null, "rp-sum");
    [["Real details used", f.real_data_used || 0], ["Fake values typed", (f.fake_values || []).length],
     ["Submissions cancelled", f.cancelled || 0], ["Internal requests blocked", f.blocked || 0]].forEach(([k, v]) => {
      const c = el("span", k + ": ", "rp-chip"); c.appendChild(el("b", v)); sum.appendChild(c); });
    box.appendChild(sum);
    // data-flow: page -> fake data -> destination
    const flow = el("div", null, "rp-flow");
    const b1 = el("div", null, "rp-box"); b1.append(el("small", "1. The page"), el("span", f.page_host || "?")); flow.appendChild(b1);
    flow.appendChild(el("span", "→", "rp-arrow"));
    const b2 = el("div", null, "rp-box"); b2.append(el("small", "2. It asked for (PHISH-X typed fake values)"), el("span", (f.fake_values || []).join(", ") || "nothing")); flow.appendChild(b2);
    flow.appendChild(el("span", "→", "rp-arrow"));
    const b3 = el("div", null, "rp-box" + (f.other_domain ? " bad" : "")); b3.append(el("small", "3. It tried to send it to"),
      el("span", (f.destinations || []).join(", ") || "nowhere", f.other_domain ? "x" : "")); flow.appendChild(b3);
    box.appendChild(flow);
    // stepper
    const steps = rp.steps || [];
    const stage = el("div", null, "rp-stage"), img = el("img", null, "rp-img"), cap = el("p", null, "rp-cap"), det = el("p", null, "rp-det");
    const ctl = el("div", null, "rp-ctl");
    const prev = el("button", "◀ Back"), play = el("button", "▶ Play"), next = el("button", "Next ▶");
    const dots = steps.map((_, i) => { const d = el("button", null, "rp-dot"); d.title = "Step " + (i + 1); d.onclick = () => go(i); return d; });
    let cur = 0, timer = null;
    function go(i) {
      cur = Math.max(0, Math.min(steps.length - 1, i)); const s = steps[cur];
      cap.textContent = "Step " + (cur + 1) + " of " + steps.length + ": " + s.title; det.textContent = s.detail + (s.t !== undefined ? "  (at " + s.t + " s)" : "");
      if (s.image && /^data:image\/jpeg;base64,/.test(s.image)) { img.src = s.image; img.style.display = "block"; } else { img.removeAttribute("src"); img.style.display = "none"; }
      dots.forEach((d, j) => d.classList.toggle("on", j === cur));
    }
    function stop() { if (timer) { clearInterval(timer); timer = null; play.textContent = "▶ Play"; } }
    prev.onclick = () => { stop(); go(cur - 1); }; next.onclick = () => { stop(); go(cur + 1); };
    play.onclick = () => { if (timer) return stop(); if (cur >= steps.length - 1) go(0); play.textContent = "❚❚ Pause";
      timer = setInterval(() => { if (cur >= steps.length - 1) return stop(); go(cur + 1); }, 2600); };
    ctl.append(prev, play, next); dots.forEach(d => ctl.appendChild(d));
    stage.append(img, cap, det); box.append(stage, ctl);
    // network log
    const net = rp.network || [];
    if (net.length) {
      const wrap = el("div", null, "rp-net"); wrap.appendChild(el("p", "Every request the page made (" + net.length + "):", "rp-det"));
      const t = el("table"), h = el("tr"); ["Method", "Host", "Path", "What the sandbox did"].forEach(x => h.appendChild(el("th", x))); t.appendChild(h);
      net.forEach(n => { const tr = el("tr"); [n.method, n.host, n.path].forEach(x => tr.appendChild(el("td", x)));
        const bad = /^(BLOCKED|CANCELLED)/.test(n.outcome); tr.appendChild(el("td", n.outcome, bad ? "x" : "a")); t.appendChild(tr); });
      wrap.appendChild(t); box.appendChild(wrap);
    }
    host.appendChild(box);
    if (steps.length) { go(0); if (steps.length > 1) setTimeout(() => play.click(), 600); }
  };
})();
