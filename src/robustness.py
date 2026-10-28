"""
PHISH-X — adversarial robustness experiment (research contribution #5).

Question: how easily can an attacker slip a phishing URL past the model by making small,
controlled edits to it, and does training on such edits ("adversarial training") help?

Method
  1. Take phishing URLs the model never trained on that it currently DETECTS.
  2. Apply each evasion transform. Count how many are no longer detected (evasion rate).
  3. Retrain with transformed phishing URLs added to the training set; repeat step 2 on
     transforms of NEW URLs, and check that normal-link accuracy did not get worse.
Detection is reported at the deployed warning level (risk score >= 70).

Run:  python robustness.py
"""
import json
import random
import re
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from ensemble import Ensemble
from features import SUSPICIOUS_WORDS
from train import (RANDOM_STATE, load_data, load_external_holdout, matrix, new_xgb)

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"
WARN = 0.70
rng = random.Random(1234)

LEET = str.maketrans({"o": "0", "e": "3", "a": "4", "i": "1"})


def _split(u):
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*://)?([^/?#]*)(.*)$", u)
    return (m.group(1) or ""), m.group(2), m.group(3)


# --- evasion transforms: each returns a modified URL string -------------------------------
def homoglyph_host(u):
    sch, host, rest = _split(u)
    h = list(host)
    idx = [i for i, c in enumerate(h) if c in "lo"]
    for i in rng.sample(idx, min(2, len(idx))):
        h[i] = "1" if h[i] == "l" else "0"
    return sch + "".join(h) + rest


def leet_keywords(u):
    out = u
    for w in SUSPICIOUS_WORDS:
        out = re.sub(w, lambda m: m.group(0).translate(LEET), out, flags=re.I)
    return out


def split_keywords(u):
    out = u
    for w in SUSPICIOUS_WORDS:
        if len(w) >= 5:
            out = re.sub(w, lambda m: m.group(0)[:3] + "-" + m.group(0)[3:], out, flags=re.I)
    return out


def percent_encode_path(u):
    sch, host, rest = _split(u)
    rest = "".join(f"%{ord(c):02X}" if c.isalpha() and rng.random() < 0.3 else c for c in rest)
    return sch + host + rest


def strip_query(u):
    return re.split(r"[?#]", u)[0]


def trim_path(u):
    sch, host, rest = _split(u)
    seg = rest.split("?")[0].split("/")
    return sch + host + ("/" + seg[1] if len(seg) > 1 and seg[1] else "")


def benign_padding(u):
    return u.rstrip("/") + "/wiki/Main_Page/en/index.html"


def remove_hyphens_host(u):
    sch, host, rest = _split(u)
    return sch + host.replace("-", "") + rest


def combined(u):
    return remove_hyphens_host(trim_path(split_keywords(u)))


TRANSFORMS = {
    "homoglyph_host": homoglyph_host, "leet_keywords": leet_keywords, "split_keywords": split_keywords,
    "percent_encode_path": percent_encode_path, "strip_query": strip_query, "trim_path": trim_path,
    "benign_padding": benign_padding, "remove_hyphens_host": remove_hyphens_host, "combined": combined,
}
LABELS = {
    "homoglyph_host": "Swap letters in the domain (l→1, o→0)", "leet_keywords": "Disguise scam words (login→l0g1n)",
    "split_keywords": "Break scam words with a hyphen (log-in)", "percent_encode_path": "Percent-encode parts of the path",
    "strip_query": "Remove the query string", "trim_path": "Cut the path to one segment",
    "benign_padding": "Append harmless-looking path", "remove_hyphens_host": "Remove hyphens from the domain",
    "combined": "Combined: split + trim + remove hyphens",
}


def build_ensemble(X, y):
    sc = StandardScaler().fit(X)
    lr = LogisticRegression(max_iter=2000, random_state=RANDOM_STATE).fit(sc.transform(X), y)
    rf = RandomForestClassifier(n_estimators=250, max_depth=24, n_jobs=-1, random_state=RANDOM_STATE).fit(X, y)
    xgb = new_xgb().fit(X, y)
    return Ensemble(lr, sc, rf, xgb)


def detection(model, urls):
    return model.predict_proba(matrix(urls))[:, 1] >= WARN


def evaluate(model, phish_urls, legit_urls):
    base = detection(model, phish_urls)
    detected = [u for u, d in zip(phish_urls, base) if d]
    rows = {}
    for name, fn in TRANSFORMS.items():
        still = detection(model, [fn(u) for u in detected])
        rows[name] = {"evaded_pct": round(100 * (1 - still.mean()), 1)}
    return {"clean_detection_pct": round(100 * base.mean(), 1),
            "legit_flagged_pct": round(100 * detection(model, legit_urls).mean(), 1),
            "evasion": rows, "n_detected_tested": len(detected)}


def main():
    df = load_data()
    ext = load_external_holdout(n_per_class=6000)
    phish_test = ext[ext.label == 1]["URL"].tolist()
    legit_test = ext[ext.label == 0]["URL"].tolist()

    X, y = matrix(df["URL"]), df["label"].values
    print("Training baseline ensemble ...")
    base_model = build_ensemble(X, y)
    before = evaluate(base_model, phish_test, legit_test)

    print("Adversarial training: adding transformed phishing URLs to the training set ...")
    train_phish = df[df.label == 1]["URL"].sample(60000, random_state=3).tolist()
    aug = [rng.choice(list(TRANSFORMS.values()))(u) for u in train_phish]
    X2 = np.vstack([X, matrix(aug)])
    y2 = np.concatenate([y, np.ones(len(aug), dtype=int)])
    hard_model = build_ensemble(X2, y2)
    after = evaluate(hard_model, phish_test, legit_test)

    out = {"warn_threshold": WARN * 100, "labels": LABELS, "before": before, "after_adversarial_training": after}
    (REPORT_DIR / "adversarial.json").write_text(json.dumps(out, indent=2))

    print(f"\nClean detection at warn level: before {before['clean_detection_pct']}%  after {after['clean_detection_pct']}%")
    print(f"Normal links wrongly flagged : before {before['legit_flagged_pct']}%  after {after['legit_flagged_pct']}%\n")
    print(f"{'Evasion trick':50s} {'evaded before':>14s} {'evaded after':>13s}")
    for k in TRANSFORMS:
        print(f"{LABELS[k]:50s} {before['evasion'][k]['evaded_pct']:13.1f}% {after['evasion'][k]['evaded_pct']:12.1f}%")


if __name__ == "__main__":
    main()
