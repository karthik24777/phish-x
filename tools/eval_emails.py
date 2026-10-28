"""Evaluate email_analyzer on labelled email CSVs (columns: sender, subject, body, label).
Usage: python tools/eval_emails.py <csv> [<csv> ...]   (from the project root)
Only text is available in these files, so header checks (SPF/DKIM, reply-to) do not take part."""
import sys, os, json, time, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import pandas as pd
from email.message import EmailMessage
import email_analyzer as ea

def build(r):
    m = EmailMessage()
    m["From"] = str(r.get("sender") or "unknown@unknown.invalid")[:200].replace("\n", " ")
    m["Subject"] = str(r.get("subject") or "")[:300].replace("\n", " ")
    m.set_content(str(r.get("body") or "")[:20000])
    return m.as_bytes()

def main(paths, n_per=None, seed=1):
    parts = []
    for p in paths:
        d = pd.read_csv(p); d["source"] = os.path.basename(p)
        d = d[~d["sender"].astype(str).str.contains("MAILER-DAEMON", na=False)]
        parts.append(d)
    d = pd.concat(parts, ignore_index=True)
    if n_per:
        d = pd.concat([g.sample(min(len(g), n_per), random_state=seed) for _, g in d.groupby(["source", "label"])], ignore_index=True)
    rows, t0 = [], time.time()
    for _, r in d.iterrows():
        try:
            a = ea.analyze(build(r)); rows.append((r["source"], int(r["label"]), a["risk_score"], a["verdict"]))
        except Exception as e:
            rows.append((r["source"], int(r["label"]), None, "ERROR"))
    df = pd.DataFrame(rows, columns=["source", "label", "score", "verdict"])
    print("analysed", len(df), "in", round(time.time() - t0), "s; errors:", int((df.verdict == "ERROR").sum()))
    df = df[df.verdict != "ERROR"]
    out = {}
    for thr in (40, 70):
        pred = df.score >= thr
        tp = int(((df.label == 1) & pred).sum()); fn = int(((df.label == 1) & ~pred).sum())
        fp = int(((df.label == 0) & pred).sum()); tn = int(((df.label == 0) & ~pred).sum())
        out[str(thr)] = {"threshold": thr, "phishing_or_spam_caught_pct": round(100 * tp / max(tp + fn, 1), 1),
                         "legit_flagged_pct": round(100 * fp / max(fp + tn, 1), 1),
                         "accuracy_pct": round(100 * (tp + tn) / len(df), 1), "tp": tp, "fn": fn, "fp": fp, "tn": tn}
    out["by_source"] = {s: {"n": int(len(g)), "mean_score": round(g.score.mean(), 1),
                            "flagged_at_40_pct": round(100 * (g.score >= 40).mean(), 1)} for s, g in df.groupby("source")}
    print(json.dumps(out, indent=1))
    return out

if __name__ == "__main__":
    main(sys.argv[1:], n_per=int(os.environ.get("N_PER", "0")) or None)
