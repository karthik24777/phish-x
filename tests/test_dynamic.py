"""Dynamic sandbox safety + behaviour test.  Run: python tests/test_dynamic.py
Proves: synthetic data is filled, multi-step JS kits are followed, submissions are CANCELLED
(collector receives nothing) and requests to internal addresses are blocked."""
import os, sys, threading, http.server, functools, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import sandbox_dynamic as dyn

DEMO = os.path.join(os.path.dirname(__file__), "..", "demo")
hits = {"collector": [], "meta": []}

def make(port, key, serve_dir=None):
    class H(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a): pass
        def _rec(self):
            if key: hits[key].append((self.command, self.path))
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        def do_GET(self):
            return super().do_GET() if serve_dir else self._rec()
        def do_POST(self): self._rec()
    if serve_dir:
        H = functools.partial(H, directory=serve_dir)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

pages = make(9100, None, DEMO); make(9999, "collector"); make(9998, "meta")
ALLOW = {"127.0.0.1:9100", "127.0.0.1:9999"}   # collector reachable on purpose: only cancellation can protect it
ok = True
def t(name, cond):
    global ok; ok &= bool(cond); print(("PASS " if cond else "FAIL ") + name)

print("--- A: JavaScript-only 3-step kit ---")
r = dyn.investigate("http://127.0.0.1:9100/js_kit_page.html", test_allow=ALLOW)
labels = [i["label"] for i in r.get("information_requested", [])]
t("page opened", r.get("fetched"))
t("found email + password + OTP built by JavaScript", {"Email address", "Password", "One-time password (OTP)"} <= set(labels))
t("followed 3 rounds", len(r.get("rounds", [])) == 3)
t("captured the exfiltration request", any(f["action"].endswith("/collect") for f in r["forms"]))
t("saw that password + OTP were in the submission", any(f["transmits_password"] and f["transmits_otp"] for f in r["forms"]))
t("COLLECTOR RECEIVED NOTHING (submission was cancelled)", hits["collector"] == [])
t("internal 'metadata' request was blocked", hits["meta"] == [] and any("9998" in b for b in r["blocked_requests"]))
t("objectives include account takeover", any(o["objective"] == "Account takeover" for o in r["likely_objectives"]))

print("--- B: classic HTML form ---")
r2 = dyn.investigate("http://127.0.0.1:9100/fake_phishing_page.html", test_allow=ALLOW)
labels2 = {i["label"] for i in r2["information_requested"]}
t("found card + CVV + password + OTP", {"Card number", "CVV / security code", "Password", "One-time password (OTP)"} <= labels2)
t("submission cancelled again", hits["collector"] == [])
t("form POST recorded with destination", any(f["method"] == "POST" and f["action"].endswith("/steal.php") for f in r2["forms"]))

print("--- C: refuses internal targets outright ---")
for u in ("http://127.0.0.1:9100/js_kit_page.html", "http://169.254.169.254/", "file:///etc/passwd"):
    rr = dyn.investigate(u)       # no test_allow -> guard active
    t(f"refused {u}", rr.get("fetched") is False)
print("\nALL PASSED" if ok else "\nSOME CHECKS FAILED"); sys.exit(0 if ok else 1)
