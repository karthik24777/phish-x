"""Model loading + soft-voting ensemble (LR + Random Forest + XGBoost)."""
import numpy as np
import joblib
from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"


class Ensemble:
    """Weighted average of the three models' phishing probabilities."""

    def __init__(self, lr, scaler, rf, xgb, weights=(0.15, 0.35, 0.50)):
        self.lr, self.scaler, self.rf, self.xgb = lr, scaler, rf, xgb
        self.weights = weights

    def predict_proba(self, X):
        X = np.asarray(X, dtype=float)
        p = (self.weights[0] * self.lr.predict_proba(self.scaler.transform(X))[:, 1]
             + self.weights[1] * self.rf.predict_proba(X)[:, 1]
             + self.weights[2] * self.xgb.predict_proba(X)[:, 1])
        return np.vstack([1 - p, p]).T


class XGBOnly:
    """LITE mode: XGBoost alone (about 3 MB). Used on phones/servers/the Windows app, where the 400 MB
    Random Forest is not shipped. Measured accuracy is within about 1 point of the full ensemble."""

    def __init__(self, xgb):
        self.xgb = xgb

    def predict_proba(self, X):
        return self.xgb.predict_proba(np.asarray(X, dtype=float))


def load_all(model_dir=MODEL_DIR):
    import os
    d = Path(model_dir)
    xgb = joblib.load(d / "xgboost.joblib")
    full = (d / "random_forest.joblib").exists() and os.environ.get("PHISHX_LITE") != "1"
    if not full:
        return {"lr": None, "scaler": None, "rf": None, "xgb": xgb, "ensemble": XGBOnly(xgb), "mode": "lite"}
    lr = joblib.load(d / "logistic_regression.joblib")
    scaler = joblib.load(d / "scaler.joblib")
    rf = joblib.load(d / "random_forest.joblib")
    return {"lr": lr, "scaler": scaler, "rf": rf, "xgb": xgb,
            "ensemble": Ensemble(lr, scaler, rf, xgb), "mode": "full"}
