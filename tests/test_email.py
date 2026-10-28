import glob, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import email_analyzer as ea
bad = 0
for f in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "emails", "*.eml"))):
    n = os.path.basename(f); r = ea.analyze(open(f, "rb").read())
    want_phish = n.startswith("phish_")
    ok = (r["verdict"] == "PHISHING") if want_phish else (r["verdict"] == "LIKELY SAFE")
    print(("ok  " if ok else "FAIL"), n, r["verdict"], r["risk_score"]); bad += not ok
print("ALL PASSED" if not bad else f"{bad} FAILED"); sys.exit(bad)
