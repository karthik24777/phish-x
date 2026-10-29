"""
PHISH-X — dynamic sandbox (isolated real browser + synthetic data).

What it does
  1. Opens the suspicious URL in a fresh, throw-away headless Chromium (no cookies, no profile,
     no downloads, no service workers, no permissions).
  2. Finds the input fields (after JavaScript has run), works out what each asks for, and fills
     them with obviously synthetic values. Your real data is never involved.
  3. Submits the form, but the submission is INTERCEPTED AND CANCELLED inside the browser:
     we record where it would have gone and which fields it carried, and it is never sent.
  4. If new fields appear (multi-step kits: email, then password, then OTP) it repeats, up to 3 rounds.

Safety design
  * Every request the page makes is checked before it leaves: non-http(s) schemes and addresses that
    resolve to private / loopback / link-local / reserved ranges are refused (SSRF guard).
  * In capture mode every non-GET request and every navigation away is recorded and aborted.
  * Hard limits: 25 s total, 80 requests, no downloads, media/fonts/websockets refused.
Known limits (say these): the address check and Chromium resolve DNS separately, so a DNS-rebinding
attacker could in theory slip a request past the check. Real isolation needs the browser inside a
container/VM whose network can only reach the public internet. Some kits detect headless browsers and
show a harmless page; the report only says what was observed.
"""
import base64
import json
import re
import time
from urllib.parse import urlparse, parse_qs

import brands
import sandbox as static

SYN = {
    "email": "phishx.test.user@example.invalid", "password": "Synthetic-Pass-0000!",
    "username": "phishx_test_user", "otp": "000000", "card": "4111111111111111", "cvv": "123",
    "expiry": "12/30", "bank": "000000000000", "pin": "0000", "gov_id": "000000000000",
    "dob": "01/01/1990", "address": "1 Test Street", "phone": "9000000000", "name": "Test User", "text": "test",
}
LABEL_TO_KEY = {
    "One-time password (OTP)": "otp", "CVV / security code": "cvv", "Card number": "card", "Card expiry": "expiry",
    "Bank account / UPI / PIN": "bank", "Government ID (SSN / Aadhaar / PAN)": "gov_id", "Date of birth": "dob",
    "Home address": "address", "Password": "password", "Username / login ID": "username",
    "Email address": "email", "Phone number": "phone", "Full name": "name",
}
MAX_TOTAL_S, MAX_REQUESTS, MAX_ROUNDS = 25, 80, 3

SCAN_JS = """() => {
  const vis = e => { const r = e.getBoundingClientRect(), s = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const out = []; let i = 0;
  document.querySelectorAll('input,textarea').forEach(e => {
    const t = (e.getAttribute('type') || 'text').toLowerCase();
    if (['hidden','submit','button','image','reset','checkbox','radio','file'].includes(t)) return;
    let label = '';
    if (e.id) { const l = document.querySelector('label[for="' + CSS.escape(e.id) + '"]'); if (l) label = l.innerText; }
    const pl = e.closest('label'); if (pl && !label) label = pl.innerText;
    e.setAttribute('data-phishx', String(i));
    out.push({idx: i++, type: t, name: e.name || '', id: e.id || '', placeholder: e.placeholder || '',
              autocomplete: e.autocomplete || '', aria: e.getAttribute('aria-label') || '', label: label,
              visible: vis(e), filled: e.getAttribute('data-phishx-filled') === '1',
              action: e.form ? (e.form.getAttribute('action') || '') : null});
  });
  return out;
}"""

SUBMIT_JS = """() => {
  const el = document.querySelector('[data-phishx-filled="1"]');
  if (el && el.form) { try { el.form.requestSubmit(); return 'form'; } catch (e) { try { el.form.submit(); return 'form'; } catch (e2) {} } }
  const btn = [...document.querySelectorAll('button,input[type=submit],a[role=button]')].find(b => {
    const r = b.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && /(sign|log|continue|next|verify|submit|confirm|proceed|login|update|unlock)/i.test(b.innerText || b.value || '');
  });
  if (btn) { btn.click(); return 'button'; }
  return 'none';
}"""


def available():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except Exception:
        return False


def _body_info(req):
    try:
        body = req.post_data or ""
    except Exception:
        body = ""
    names = []
    ctype = (req.headers.get("content-type") or "").lower()
    if "json" in ctype:
        try:
            j = json.loads(body)
            names = list(j.keys()) if isinstance(j, dict) else []
        except Exception:
            pass
    elif "multipart" in ctype:
        names = re.findall(r'name="([^"]+)"', body)
    else:
        names = list(parse_qs(body, keep_blank_values=True).keys())
    return body, names


def _shot(page, label):
    """Small JPEG of the sandbox browser for the replay view, cropped to where the page actually has content."""
    try:
        box = page.evaluate("""() => { let r = 0, b = 0;
            document.querySelectorAll('body *').forEach(e => { const q = e.getBoundingClientRect();
              if (q.width > 0 && q.height > 0) { r = Math.max(r, q.right); b = Math.max(b, q.bottom); } });
            return [r, b]; }""")
        w = int(min(1100, max(560, box[0] + 60)))
        h = int(min(800, max(300, box[1] + 60)))
        data = page.screenshot(type="jpeg", quality=55, clip={"x": 0, "y": 0, "width": w, "height": h})
        return "data:image/jpeg;base64," + base64.b64encode(data).decode()
    except Exception:
        return None


HIGHLIGHT_JS = """() => document.querySelectorAll('[data-phishx-filled="1"]').forEach(e => { e.style.outline = '3px solid #e63946'; e.style.outlineOffset = '2px'; })"""


def investigate(url: str, test_allow=(), replay=False):
    """Run the dynamic investigation. Returns a dict shaped like sandbox.inspect()."""
    from playwright.sync_api import sync_playwright

    result = {"url": url, "fetched": False, "sandbox_mode": "dynamic (isolated browser, synthetic data, submissions cancelled)"}
    p0 = urlparse(url)
    if p0.scheme not in ("http", "https") or not p0.hostname:
        result["error"] = "Only http/https URLs can be inspected."
        return result
    try:
        if f"{p0.hostname}:{p0.port}" not in test_allow:
            static._check_host_is_public(p0.hostname)
    except static.UnsafeTarget as e:
        result["error"] = str(e)
        return result

    state = {"capturing": False, "requests": 0, "blocked": [], "captured": [], "nav_chain": [], "net": []}
    steps = []
    t_start = time.time()

    def step(title, detail, image=None):
        steps.append({"t": round(time.time() - t_start, 1), "title": title, "detail": detail, "image": image})

    def net(method, u, outcome, rtype=""):
        if len(state["net"]) < 80:
            pu = urlparse(u)
            state["net"].append({"method": method, "host": pu.hostname or pu.scheme, "path": (pu.path or "/")[:70],
                                 "type": rtype, "outcome": outcome})
    deadline = time.time() + MAX_TOTAL_S
    allowed_cache = {}

    def host_ok(u):
        pu = urlparse(u)
        if pu.scheme in ("data", "blob", "about"):
            return True
        if pu.scheme not in ("http", "https") or not pu.hostname:
            return False
        key = f"{pu.hostname}:{pu.port}"
        if key in test_allow:
            return True
        if pu.hostname not in allowed_cache:
            try:
                static._check_host_is_public(pu.hostname)
                allowed_cache[pu.hostname] = True
            except static.UnsafeTarget:
                allowed_cache[pu.hostname] = False
        return allowed_cache[pu.hostname]

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True, accept_downloads=False, service_workers="block",
                                  permissions=[], locale="en-US", viewport={"width": 1280, "height": 900},
                                  user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                             "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
        page = ctx.new_page()
        page.set_default_timeout(8000)

        def handler(route, request):
            u = request.url
            state["requests"] += 1
            if state["requests"] > MAX_REQUESTS or request.resource_type in ("media", "font", "websocket", "eventsource"):
                net(request.method, u, "refused by sandbox limits", request.resource_type)
                return route.abort()
            if not host_ok(u):
                state["blocked"].append(u[:200])
                net(request.method, u, "BLOCKED: internal address", request.resource_type)
                return route.abort()
            if state["capturing"]:
                is_nav = request.is_navigation_request() and request.frame == page.main_frame
                if request.method != "GET" or (is_nav and u != state["page_url"]):
                    body, names = _body_info(request)
                    state["captured"].append({
                        "url": u, "method": request.method, "fields_sent": names,
                        "carries_synthetic_password": SYN["password"] in body or "Synthetic-Pass" in u,
                        "carries_synthetic_otp": bool(re.search(r"(^|[=&\":,])000000($|[&\",}])", body + u)),
                        "carries_synthetic_card": SYN["card"] in body or SYN["card"] in u,
                    })
                    net(request.method, u, "CANCELLED: data never left the sandbox", request.resource_type)
                    return route.abort()
            net(request.method, u, "allowed (read only)", request.resource_type)
            return route.continue_()

        ctx.route("**/*", handler)
        page.on("framenavigated", lambda f: state["nav_chain"].append(f.url) if f == page.main_frame else None)

        try:
            resp = page.goto(url, wait_until="domcontentloaded", timeout=12000)
            page.wait_for_timeout(1200)
        except Exception as e:
            browser.close()
            result["error"] = f"Could not open the page ({type(e).__name__}). It may be offline or blocking scanners."
            return result

        state["page_url"] = page.url
        result.update(fetched=True, status=resp.status if resp else None, final_url=page.url,
                      title=(page.title() or "")[:200], redirect_chain=state["nav_chain"][:8])
        page_domain = brands.registered_domain(urlparse(page.url).hostname or "")
        if replay:
            step("Opened the page in an isolated browser",
                 f"Title: {(page.title() or '(none)')[:80]}. A fresh browser with no cookies, no logins and no saved data. Nothing of yours is inside it.",
                 _shot(page, "opened"))

        requested, forms_out, rounds = {}, [], []
        for rnd in range(MAX_ROUNDS):
            if time.time() > deadline:
                break
            fields = page.evaluate(SCAN_JS)
            todo = []
            for f in fields:
                if f["filled"] or not f["visible"]:
                    continue
                hay = " ".join([f["name"], f["id"], f["placeholder"], f["autocomplete"], f["aria"], f["label"]])
                c = static.classify_attrs(f["type"], hay)
                if c:
                    todo.append((f, c))
            if not todo:
                break
            filled = []
            for f, (cat, label, risk) in todo:
                key = LABEL_TO_KEY.get(label, "text")
                try:
                    page.locator(f'[data-phishx="{f["idx"]}"]').fill(SYN[key], timeout=2000)
                    page.evaluate("(i) => document.querySelector('[data-phishx=\"'+i+'\"]').setAttribute('data-phishx-filled','1')", str(f["idx"]))
                    filled.append({"label": label, "category": cat, "risk": risk})
                    requested[label] = {"label": label, "category": cat, "risk": risk}
                except Exception:
                    continue
            if not filled:
                break
            if replay:
                try:
                    page.evaluate(HIGHLIGHT_JS)
                except Exception:
                    pass
                step(f"Round {rnd + 1}: the page asks for {len(filled)} thing(s). PHISH-X types FAKE data",
                     "Typed: " + ", ".join(f"{f['label']} = {SYN[LABEL_TO_KEY.get(f['label'], 'text')]}" for f in filled)
                     + ". Highlighted in red in the screenshot. These values are made up, never your real details.", _shot(page, "filled"))
            before = len(state["captured"])
            state["capturing"] = True
            how = page.evaluate(SUBMIT_JS)
            page.wait_for_timeout(2500)
            state["capturing"] = False
            new = state["captured"][before:]
            if replay:
                if new:
                    dests = ", ".join(sorted({(urlparse(c["url"]).hostname or "?") for c in new}))
                    step(f"Pressed submit. PHISH-X cancelled {len(new)} request(s)",
                         f"The page tried to send the fake data to: {dests}. The request was stopped inside the sandbox, so nothing was delivered.",
                         _shot(page, "submitted"))
                else:
                    step("Pressed the button. No data left the page yet", "The page did not send anything this time. Multi-step kits often reveal the next question first, so PHISH-X keeps going.", _shot(page, "submitted"))
            rounds.append({"round": rnd + 1, "filled": [f["label"] for f in filled], "submit_method": how,
                           "submissions_cancelled": len(new)})
            for cap in new:
                th = urlparse(cap["url"]).hostname or ""
                forms_out.append({
                    "action": cap["url"], "method": cap["method"], "fields": filled,
                    "fields_sent": cap["fields_sent"],
                    "sends_to_other_domain": bool(th) and brands.registered_domain(th) != page_domain,
                    "insecure_transport": cap["url"].startswith("http://"),
                    "transmits_password": cap["carries_synthetic_password"],
                    "transmits_otp": cap["carries_synthetic_otp"], "transmits_card": cap["carries_synthetic_card"],
                })
            if how == "none":
                break

        try:
            page.screenshot(path="/tmp/phishx_last.png", full_page=False)
            result["screenshot"] = "/tmp/phishx_last.png"
        except Exception:
            pass
        browser.close()

    info = sorted(requested.values(), key=lambda r: -static.RISK_ORDER[r["risk"]])
    findings = []
    for f in forms_out:
        host = urlparse(f["action"]).hostname
        if f["sends_to_other_domain"]:
            findings.append(f"Submitting the form sent data toward a different domain ({host}) than the page itself.")
        if f["insecure_transport"] and any(x["risk"] == "critical" for x in f["fields"]):
            findings.append("Sensitive fields were submitted over unencrypted HTTP.")
        if f["transmits_password"]:
            findings.append("The password field was included in the submission.")
        if f["transmits_otp"]:
            findings.append("The one-time-code field was included in the submission.")
    if len(rounds) > 1:
        findings.append(f"Multi-step kit: new fields kept appearing across {len(rounds)} rounds (e.g. email, then password, then code).")
    if len(state["nav_chain"]) > 3:
        findings.append(f"The page redirected {len(state['nav_chain']) - 1} times.")
    if state["blocked"]:
        findings.append(f"{len(state['blocked'])} request(s) to internal or non-web addresses were blocked by the sandbox.")
    if not info:
        findings.append("No data-collection fields were visible after the page's scripts ran.")

    if replay:
        sends = [f for f in forms_out]
        step("Result", "; ".join(findings[:3]) or "No suspicious behaviour observed.")
        result["replay"] = {
            "steps": steps, "network": state["net"],
            "flow": {"page_host": urlparse(result.get("final_url") or url).hostname,
                     "fake_values": [f"{k}" for k in requested.keys()],
                     "destinations": sorted({urlparse(f["action"]).hostname or "?" for f in sends}),
                     "other_domain": any(f["sends_to_other_domain"] for f in sends),
                     "cancelled": len(state["captured"]), "blocked": len(state["blocked"]),
                     "real_data_used": 0},
        }
    result.update(forms=forms_out, information_requested=info, likely_objectives=static._infer_objectives(info),
                  findings=findings, blocked_requests=state["blocked"],
                  interaction=f"{len(rounds)} round(s): filled synthetic data and cancelled {len(state['captured'])} submission(s); nothing was sent",
                  rounds=rounds)
    return result
