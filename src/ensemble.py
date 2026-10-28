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


def load_all(model_dir=MODEL_DIR):
    d = Path(model_dir)
    lr = joblib.load(d / "logistic_regression.joblib")
    scaler = joblib.load(d / "scaler.joblib")
    rf = joblib.load(d / "random_forest.joblib")
    xgb = joblib.load(d / "xgboost.joblib")
    return {"lr": lr, "scaler": scaler, "rf": rf, "xgb": xgb,
            "ensemble": Ensemble(lr, scaler, rf, xgb)}
