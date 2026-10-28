"""
Agent vs fixed pipeline on a small demonstration set.   Run: python benchmark_agent.py

Honest scope: 10 hand-picked cases (5 local pages we control, 5 link-only cases that cannot be
fetched from the development sandbox). This shows HOW the agent behaves (fewer tool calls on easy
cases, same verdicts), not a statistically meaningful accuracy comparison.
"""
import os
os.environ["PHISHX_ALLOW_LOCAL"] = "1"      # demo pages live on localhost
import functools, http.server, json, threading
from pathlib import Path

import agent, core

DEMO = Path(__file__).resolve().parent.parent / "demo"
REPORTS = Path(__file__).resolve().parent.parent / "reports"


def serve(port, directory=None):
    class H(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self): self.send_response(200); self.end_headers()
    h = functools.partial(H, directory=str(directory)) if directory else H
    s = http.server.ThreadingHTTPServer(("127.0.0.1", port), h)
    threading.Thread(target=s.serve_forever, daemon=True).start()


serve(9100, DEMO); serve(9999)
B = "http://localhost:9100/"
CASES = [  # (label 1 = phishing, description, url)
    (0, "harmless blog page (local)", B + "benign_blog.html"),
    (0, "harmless contact form (local)", B + "benign_contact.html"),
    (0, "ordinary member login (local)", B + "benign_login.html"),
    (1, "fake bank page: card, CVV, OTP (local)", B + "fake_phishing_page.html"),
    (1, "JavaScript 3-step kit (local)", B + "js_kit_page.html"),
    (0, "official PayPal sign-in", "https://www.paypal.com/signin"),
    (0, "Wikipedia", "https://www.wikipedia.org/wiki/Phishing"),
    (0, "ordinary news article", "https://www.thehindu.com/news/national/some-story/article67891234.ece"),
    (1, "PayPal look-alike", "http://paypa1-secure-login.com/account/verify?session=8f3a"),
    (1, "HDFC look-alike", "http://hdfc-netbanking-update.xyz/login"),
]


def run(fn, url):
    core.assess.cache_clear(); core.inspect_page.cache_clear()
    return fn(url)


rows = []
for label, desc, url in CASES:
    a = run(agent.investigate, url)
    f = run(agent.fixed_pipeline, url)
    rows.append({"case": desc, "truth": "phishing" if label else "benign",
                 "agent": {"verdict": a["verdict"], "score": a["risk_score"], "calls": a["n_tool_calls"], "seconds": a["seconds"], "tools": a["tools_used"]},
                 "fixed": {"verdict": f["verdict"], "score": f["risk_score"], "calls": f["n_tool_calls"], "seconds": f["seconds"]},
                 "agent_correct": (a["verdict"] == "PHISHING") == bool(label),
                 "fixed_correct": (f["verdict"] == "PHISHING") == bool(label)})
    print(f"{desc:42s} truth={'phish ' if label else 'benign'} | agent {a['verdict']:11s} {a['risk_score']:3d} {a['n_tool_calls']} calls {a['seconds']:5.1f}s | fixed {f['verdict']:11s} {f['risk_score']:3d} {f['n_tool_calls']} calls {f['seconds']:5.1f}s")

n = len(rows)
summary = {"cases": n,
           "agent": {"correct": sum(r["agent_correct"] for r in rows), "avg_calls": round(sum(r["agent"]["calls"] for r in rows) / n, 2), "total_seconds": round(sum(r["agent"]["seconds"] for r in rows), 1)},
           "fixed": {"correct": sum(r["fixed_correct"] for r in rows), "avg_calls": round(sum(r["fixed"]["calls"] for r in rows) / n, 2), "total_seconds": round(sum(r["fixed"]["seconds"] for r in rows), 1)}}
(REPORTS / "agent_benchmark.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
print("\nSUMMARY", json.dumps(summary))
