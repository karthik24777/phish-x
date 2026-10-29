"""
PHISH-X — Phase 1: Detection Engine
Command-line demo: give it a URL, get a verdict, a risk score, and
plain-language evidence — the report format the rest of the project
builds on.

Usage:
    python predict.py "http://paypa1-secure-login.com/verify"
    python predict.py            (interactive mode)
"""

import sys
import numpy as np
import xgboost as xgb_lib

from features import features_to_row, explain, FEATURE_NAMES
from ensemble import load_all

_M = load_all()
_ens = _M["ensemble"]
MODE = _M.get("mode", "full")
_booster = _M["xgb"].get_booster()

FEATURE_LABELS = {
    "url_length": "URL length", "host_length": "domain length", "path_length": "path length",
    "num_dots": "number of dots", "num_hyphens": "number of hyphens", "num_at": "'@' symbols",
    "num_question": "'?' characters", "num_equal": "'=' characters", "num_underscore": "underscores",
    "num_ampersand": "'&' characters", "num_digits": "digit count", "digit_ratio": "share of digits",
    "has_ip_host": "IP address as host", "num_subdomains": "number of subdomains",
    "uses_https_scheme": "HTTPS", "https_token_in_path": "'https' inside the path",
    "is_shortener": "link shortener", "num_query_params": "query parameters",
    "entropy": "character randomness", "suspicious_word_count": "scam keywords (login, verify...)",
    "double_slash_in_path": "'//' in the path", "has_port": "non-standard port",
}


def top_factors(row, k=5):
    """Per-prediction explanation: each feature's contribution in XGBoost log-odds. These are exact
    TreeSHAP values (XGBoost computes them natively; verified identical to the shap library)."""
    sv = _booster.predict(xgb_lib.DMatrix(row), pred_contribs=True)[0][:-1]
    order = np.argsort(-np.abs(sv))[:k]
    return [{"feature": FEATURE_NAMES[i], "label": FEATURE_LABELS.get(FEATURE_NAMES[i], FEATURE_NAMES[i]),
             "value": float(row[0][i]), "contribution": round(float(sv[i]), 3),
             "direction": "raises risk" if sv[i] > 0 else "lowers risk"} for i in order]


def investigate(url: str) -> dict:
    row = np.array([features_to_row(url)], dtype=float)
    proba_phish = _ens.predict_proba(row)[0][1]
    risk_score = round(proba_phish * 100)

    if risk_score >= 70:
        verdict, level = "PHISHING", "CRITICAL"
    elif risk_score >= 40:
        verdict, level = "SUSPICIOUS", "MEDIUM"
    else:
        verdict, level = "LIKELY SAFE", "LOW"

    return {
        "url": url,
        "verdict": verdict,
        "risk_level": level,
        "risk_score": risk_score,
        "confidence": round(max(proba_phish, 1 - proba_phish) * 100, 1),
        "evidence": explain(url),
        "top_factors": top_factors(row),
    }


def print_report(result: dict):
    bar_len = 30
    filled = round(result["risk_score"] / 100 * bar_len)
    bar = "#" * filled + "-" * (bar_len - filled)

    print("\n" + "=" * 60)
    print(" PHISH-X — THREAT REPORT")
    print("=" * 60)
    print(f" URL       : {result['url']}")
    print(f" Verdict   : {result['verdict']}  ({result['risk_level']} risk)")
    print(f" Risk score: {result['risk_score']:3d}/100  [{bar}]")
    print(f" Confidence: {result['confidence']}%")
    print("-" * 60)
    print(" Evidence:")
    for e in result["evidence"]:
        print(f"   - {e}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        url = " ".join(sys.argv[1:])
        print_report(investigate(url))
    else:
        print("PHISH-X detection engine — interactive mode. Ctrl+C to exit.\n")
        while True:
            try:
                url = input("Enter a URL to investigate: ").strip()
                if not url:
                    continue
                print_report(investigate(url))
            except (KeyboardInterrupt, EOFError):
                print("\nExiting.")
                break
