"""PHISH-X — shared scoring logic used by the service, the agent and the fixed-pipeline baseline."""
import os
import threading
from functools import lru_cache

import brands
from predict import investigate as _model_investigate
from sandbox import inspect as static_inspect
import sandbox_dynamic as dyn

SANDBOX_MODE = os.environ.get("PHISHX_SANDBOX_MODE", "auto")   # auto | static
_sem = threading.BoundedSemaphore(2)


def verdict_for(score: int):
    if score >= 70:
        return "PHISHING", "CRITICAL"
    if score >= 40:
        return "SUSPICIOUS", "MEDIUM"
    return "LIKELY SAFE", "LOW"


@lru_cache(maxsize=2048)
def assess(url: str):
    """URL-only tier: ML ensemble + brand trust / impersonation rules (+ campaign note)."""
    base = dict(_model_investigate(url))
    base["model_score"] = base["risk_score"]
    base["trusted"] = False
    base["impersonates"] = None
    base["campaign"] = None

    reason = brands.trusted(url)
    if reason:
        base.update(risk_score=min(base["risk_score"], 10), trusted=True, evidence=[reason])
    else:
        imp = brands.impersonation(url)
        if imp:
            brand, official, tok = imp
            base["risk_score"] = min(100, max(base["risk_score"] + 25, 80))
            base["impersonates"] = brand
            base["evidence"] = [f"Impersonation: the domain uses '{tok}' to look like {brand}, "
                                f"but {brand}'s real domain is {official}."] + base["evidence"]
        try:
            import campaigns
            m = campaigns.match_campaign(url)
        except Exception:
            m = None
        if m:   # supporting evidence only: does NOT change the score (see campaigns.py limits)
            base["campaign"] = m
            base["evidence"] = base["evidence"] + [
                f"URL layout matches a pattern seen on {m['domains']} different domains in known phishing data (campaign #{m['campaign_id']})."]
    base["verdict"], base["risk_level"] = verdict_for(base["risk_score"])
    base["confidence"] = max(base["risk_score"], 100 - base["risk_score"])
    return base


@lru_cache(maxsize=512)
def inspect_page(url: str):
    """Dynamic sandbox when Playwright + Chromium are available, else the static inspector."""
    if SANDBOX_MODE != "static" and dyn.available():
        try:
            with _sem:
                r = dyn.investigate(url)
            r.pop("screenshot", None)
            return r
        except Exception as e:  # browser missing / crashed -> fall back, and say so
            r = static_inspect(url)
            r["sandbox_note"] = f"Dynamic sandbox unavailable ({type(e).__name__}); used static inspection."
            return r
    return static_inspect(url)


def combine(base: dict, page: dict):
    """Fold the page evidence into the URL-tier score. Returns (score, reasons)."""
    score, reasons = base["risk_score"], []
    if page.get("fetched"):
        info = page.get("information_requested", [])
        crit = [r for r in info if r["risk"] == "critical"]
        if base["trusted"]:
            reasons.append("Trusted domain: the information this page asks for is normal for the real site.")
        else:
            nonpw = [r for r in crit if r["label"] != "Password"]
            if nonpw:
                score += 15
                reasons.append(f"Page asks for {len(crit)} critical item(s): " + ", ".join(r["label"] for r in crit) + ".")
            elif crit:
                # A password box alone is what every ordinary login page has, so it only adds a little.
                score += 5
                reasons.append("Page asks for a password.")
            if any(f["sends_to_other_domain"] for f in page.get("forms", [])):
                score += 15
                reasons.append("A form sends data to a different domain than the page.")
            if any(f["insecure_transport"] for f in page.get("forms", [])) and crit:
                score += 5
            score += min(len(page.get("findings", [])) * 2, 8)
            kinds = {r["category"] for r in crit}
            if sum(k in kinds for k in ("financial", "authentication", "credentials")) >= 2:
                # Password + card/OTP, or card + OTP, in one place on an untrusted domain is the
                # classic data-trap combination, whatever the link text looks like.
                if score < 75:
                    score = 75
                reasons.append("The page combines requests (e.g. password + card or one-time code) that legitimate sites rarely put together.")
            cross = any(f["sends_to_other_domain"] for f in page.get("forms", []))
            if crit and not nonpw and not cross and not base["impersonates"] and score >= 70:
                # Only an ordinary login form: the page alone cannot tell a real login from a clone,
                # so don't call it PHISHING on link text alone. (Costs some recall on password-only kits.)
                score = 69
                reasons.append("Only an ordinary login form was found. Sign in only if you are sure this is the right website.")
            if not info and not base["impersonates"] and score >= 70:
                score = 60
                reasons.append("No data-collection form was found in the page, so the verdict is capped at SUSPICIOUS.")
    return max(0, min(100, score)), reasons


def full_report(url: str):
    base = dict(assess(url))
    page = inspect_page(url)
    score, reasons = combine(base, page)
    verdict, level = verdict_for(score)
    return {"url": url, "verdict": verdict, "risk_level": level, "risk_score": score,
            "url_model_score": base["model_score"], "trusted": base["trusted"], "impersonates": base["impersonates"],
            "campaign": base["campaign"], "top_factors": base.get("top_factors", []),
            "evidence": base["evidence"] + reasons, "page": page}
