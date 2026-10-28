"""Honest evaluation of the full email analyzer: train the wording model on 80% of the emails, run the
complete analyzer (rules + links + wording model) on the 20% it never saw. Writes reports/email_metrics.json."""
import sys, os, json, warnings
warnings.filterwarnings("ignore")
HERE = os.path.dirname(__file__); sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "src"))
import joblib, pandas as pd
from sklearn.model_selection import train_test_split
import train_email_model as T
from eval_emails import build
import email_analyzer as ea

d = T.load(sys.argv[1:])
tr, te = train_test_split(d, test_size=0.2, random_state=1, stratify=d.label)
vec, clf = T.fit(tr)
tmp = os.path.join(HERE, "_heldout_model.joblib"); joblib.dump({"vec": vec, "clf": clf}, tmp)
os.environ["PHISHX_EMAIL_MODEL"] = tmp
rows = []
for _, r in te.iterrows():
    a = ea.analyze(build(r)); rows.append((r["source"], int(r["label"]), a["risk_score"]))
os.remove(tmp)
df = pd.DataFrame(rows, columns=["source", "label", "score"])
res = {}
for thr in (40, 70):
    pred = df.score >= thr
    tp = int(((df.label == 1) & pred).sum()); fn = int(((df.label == 1) & ~pred).sum())
    fp = int(((df.label == 0) & pred).sum()); tn = int(((df.label == 0) & ~pred).sum())
    res[f"threshold_{thr}"] = {"caught_pct": round(100 * tp / (tp + fn), 1), "legit_flagged_pct": round(100 * fp / (fp + tn), 1),
                               "accuracy_pct": round(100 * (tp + tn) / len(df), 1), "n": len(df), "tp": tp, "fn": fn, "fp": fp, "tn": tn}
print(json.dumps(res, indent=1))
p = os.path.join(HERE, "..", "reports", "email_metrics.json")
m = json.load(open(p)); m["full_analyzer_heldout"] = res; json.dump(m, open(p, "w"), indent=1)
