"""
PHISH-X — train and compare the URL detection models.

Models: Logistic Regression, Random Forest, XGBoost, and a soft-voting Ensemble.
Evaluation: (a) 20% split of the training sample, (b) an EXTERNAL hold-out of URLs that were
never in the training sample, used to build the threshold / false-alarm table.

Run:  python train.py
"""
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from ensemble import Ensemble
from features import FEATURE_NAMES, features_to_row

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "raw_urls.csv"
MODEL_DIR = ROOT / "models"
REPORT_DIR = ROOT / "reports"
MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

SAMPLE_PER_CLASS = 100_000
RANDOM_STATE = 42


def _read():
    df = pd.read_csv(DATA_PATH).dropna(subset=["URL", "Label"])
    df["label"] = (df["Label"].str.lower() == "bad").astype(int)  # 1 = phishing
    return df


def load_data():
    """Balanced training sample."""
    df = _read()
    parts = []
    for lab in (1, 0):
        sub = df[df["label"] == lab]
        parts.append(sub.sample(n=min(SAMPLE_PER_CLASS, len(sub)), random_state=RANDOM_STATE))
    return pd.concat(parts).sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)


def load_external_holdout(n_per_class=10_000):
    df = _read()
    used = set(load_data()["URL"])
    df = df[~df["URL"].isin(used)]
    parts = [df[df["label"] == lab].sample(n=min(n_per_class, (df["label"] == lab).sum()), random_state=7)
             for lab in (1, 0)]
    return pd.concat(parts).reset_index(drop=True)


def matrix(urls):
    return np.array([features_to_row(str(u)) for u in urls], dtype=float)


def metrics(y, pred, proba):
    return {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred),
            "recall": recall_score(y, pred), "f1": f1_score(y, pred), "roc_auc": roc_auc_score(y, proba)}


def new_xgb():
    return XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1, subsample=0.8,
                         colsample_bytree=0.8, tree_method="hist", n_jobs=-1,
                         eval_metric="logloss", random_state=RANDOM_STATE)


def main():
    t0 = time.time()
    df = load_data()
    print(f"Training sample: {len(df)} URLs ({int(df.label.sum())} phishing / {int((1 - df.label).sum())} legitimate)")
    X, y = matrix(df["URL"]), df["label"].values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y)

    scaler = StandardScaler().fit(Xtr)
    lr = LogisticRegression(max_iter=2000, random_state=RANDOM_STATE).fit(scaler.transform(Xtr), ytr)
    print("  LR done")
    rf = RandomForestClassifier(n_estimators=250, max_depth=24, n_jobs=-1, random_state=RANDOM_STATE).fit(Xtr, ytr)
    print("  RF done")
    xgb = new_xgb().fit(Xtr, ytr)
    print("  XGB done")
    ens = Ensemble(lr, scaler, rf, xgb)

    results = {}
    for name, model, Xt in (("logistic_regression", lr, scaler.transform(Xte)), ("random_forest", rf, Xte),
                            ("xgboost", xgb, Xte), ("ensemble", ens, Xte)):
        p = model.predict_proba(Xt)[:, 1]
        results[name] = metrics(yte, (p >= 0.5).astype(int), p)

    # External hold-out (never seen in training) -> threshold table for the ensemble
    ext = load_external_holdout()
    Xe, ye = matrix(ext["URL"]), ext["label"].values
    pe = ens.predict_proba(Xe)[:, 1] * 100
    thresholds = []
    for t in (40, 55, 70, 80, 90):
        thresholds.append({"threshold": t,
                           "legit_flagged_pct": float(100 * (pe[ye == 0] >= t).mean()),
                           "phishing_caught_pct": float(100 * (pe[ye == 1] >= t).mean())})
    external = metrics(ye, (pe >= 50).astype(int), pe / 100)

    cm = confusion_matrix(yte, (ens.predict_proba(Xte)[:, 1] >= 0.5).astype(int)).tolist()
    imp = sorted(zip(FEATURE_NAMES, xgb.feature_importances_), key=lambda x: -x[1])

    joblib.dump(lr, MODEL_DIR / "logistic_regression.joblib")
    joblib.dump(scaler, MODEL_DIR / "scaler.joblib")
    joblib.dump(rf, MODEL_DIR / "random_forest.joblib")
    joblib.dump(xgb, MODEL_DIR / "xgboost.joblib")

    out = {"train_size": len(Xtr), "test_size": len(Xte), "external_holdout_size": len(ext),
           "results": results, "external_holdout_ensemble": external, "threshold_table": thresholds,
           "confusion_matrix_ensemble": cm,
           "top_features_xgboost": [{"feature": n, "importance": float(i)} for n, i in imp],
           "seconds": round(time.time() - t0, 1)}
    (REPORT_DIR / "metrics.json").write_text(json.dumps(out, indent=2))

    print("\n=== Test-split results ===")
    for k, v in results.items():
        print(f"{k:20s} acc={v['accuracy']:.4f} f1={v['f1']:.4f} auc={v['roc_auc']:.4f}")
    print("\n=== External hold-out (ensemble) ===")
    for r in thresholds:
        print(f"  warn >= {r['threshold']:2d}: legit flagged {r['legit_flagged_pct']:5.1f}%  phishing caught {r['phishing_caught_pct']:5.1f}%")
    print(f"\nSaved to {MODEL_DIR}  ({out['seconds']}s)")


if __name__ == "__main__":
    main()
