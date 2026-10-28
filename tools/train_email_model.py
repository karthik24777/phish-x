"""Train the email text model (TF-IDF + logistic regression) and measure it honestly.
Usage: python tools/train_email_model.py <csv> [<csv> ...]
Label 1 = phishing/scam/spam, 0 = legitimate. Writes models/email_text.joblib and reports/email_metrics.json."""
import sys, os, json, re, warnings
warnings.filterwarnings("ignore")
import numpy as np, pandas as pd, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
# words that identify the 2002 SpamAssassin/mailing-list collection rather than phishing
ARTEFACT = {"spamassassin","spambayes","razor","sightings","rpm","linux","urltoken","emailtoken","wrote","list","mailing","users","utf","date","supplied","said","url","jim","tom","unsubscribe","listinfo","sourceforge","net","lists","org","com","www","http","https","html","mime","charset"}
STOP = set(ENGLISH_STOP_WORDS) | ARTEFACT
ROOT = os.path.join(os.path.dirname(__file__), "..")

def clean(subject, body):
    t = f"{subject or ''} {body or ''}"[:6000]
    t = re.sub(r"https?://\S+", " URLTOKEN ", t)
    t = re.sub(r"_{3,}|-{3,}|={3,}", " ", t)               # mailing-list footer lines
    t = re.sub(r"\d+", " ", t)                              # years, ids: collection artefacts
    t = re.sub(r"\S+@\S+", " EMAILTOKEN ", t)
    return t

def load(paths):
    parts = []
    for p in paths:
        d = pd.read_csv(p)[["sender", "subject", "body", "label"]]
        d["source"] = os.path.basename(p).split("-", 1)[-1]
        d = d[~d["sender"].astype(str).str.contains("MAILER-DAEMON", na=False)].dropna(subset=["body"])
        parts.append(d)
    d = pd.concat(parts, ignore_index=True).drop_duplicates(subset=["subject", "body"])
    d["text"] = [clean(s, b) for s, b in zip(d.subject, d.body)]
    return d

def fit(d):
    vec = TfidfVectorizer(token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z]+\b", ngram_range=(1, 1), min_df=3, max_features=60000, sublinear_tf=True, lowercase=True, stop_words=list(STOP))
    X = vec.fit_transform(d.text)
    clf = LogisticRegression(C=4, max_iter=2000, class_weight="balanced").fit(X, d.label)
    return vec, clf

def metrics(y, p, thr=0.5):
    yh = (p >= thr).astype(int)
    fp = int(((y == 0) & (yh == 1)).sum()); tn = int(((y == 0) & (yh == 0)).sum())
    return {"n": int(len(y)), "accuracy": round(accuracy_score(y, yh), 4), "precision": round(precision_score(y, yh), 4),
            "recall": round(recall_score(y, yh), 4), "f1": round(f1_score(y, yh), 4),
            "auc": round(roc_auc_score(y, p), 4), "legit_flagged_pct": round(100 * fp / max(fp + tn, 1), 2)}

if __name__ == "__main__":
    d = load(sys.argv[1:])
    print(d.groupby(["source", "label"]).size())
    tr, te = train_test_split(d, test_size=0.2, random_state=1, stratify=d.label)
    vec, clf = fit(tr)
    p = clf.predict_proba(vec.transform(te.text))[:, 1]
    out = {"counts": {f"{s}|{l}": int(n) for (s, l), n in d.groupby(["source", "label"]).size().items()},
           "random_split": metrics(te.label.values, p)}
    print("random split:", out["random_split"])
    # harder test: leave one source out (does it work on a collection it never saw?)
    out["leave_one_source_out"] = {}
    for s in d.source.unique():
        tr2, te2 = d[d.source != s], d[d.source == s]
        if tr2.label.nunique() < 2: continue
        v2, c2 = fit(tr2); p2 = c2.predict_proba(v2.transform(te2.text))[:, 1]
        yh = (p2 >= 0.5).astype(int); y = te2.label.values
        r = {"n": int(len(te2)), "flagged_pct": round(100 * yh.mean(), 1)}
        r["accuracy"] = round(float((yh == y).mean()), 4)
        out["leave_one_source_out"][s] = r; print("hold out", s, r)
    # final model trained on all data
    vec, clf = fit(d)
    joblib.dump({"vec": vec, "clf": clf}, os.path.join(ROOT, "models", "email_text.joblib"), compress=3)
    fn = np.array(vec.get_feature_names_out()); co = clf.coef_[0]
    out["top_phishing_words"] = fn[np.argsort(-co)[:25]].tolist()
    out["top_legit_words"] = fn[np.argsort(co)[:25]].tolist()
    json.dump(out, open(os.path.join(ROOT, "reports", "email_metrics.json"), "w"), indent=1)
    print(out["top_phishing_words"]); print(out["top_legit_words"])
