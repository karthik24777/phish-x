"""
PHISH-X — Phase 1: Detection Engine
Lexical / structural feature extraction for a raw URL string.

Every feature here is computable from the URL text alone — no network
calls, no WHOIS, no live page fetch. This keeps the detection engine
fast and safe to run on arbitrary, unverified input.
"""

import re
import math
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "bank", "password", "pay", "billing", "webscr",
    "suspend", "unlock", "security", "ebayisapi", "alert",
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "cutt.ly", "rb.gy",
]

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def _ensure_scheme(url: str) -> str:
    """urlparse needs a scheme to split host/path correctly."""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        return "http://" + url
    return url


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_features(raw_url: str) -> dict:
    url = raw_url.strip()
    try:
        parsed = urlparse(_ensure_scheme(url))
        host = parsed.netloc.split(":")[0].lower()
        path = parsed.path or ""
        query = parsed.query or ""
        scheme = parsed.scheme
        port = parsed.port
    except ValueError:
        # malformed URL (e.g. stray '[' ']') — fall back to a crude manual split
        host, path, query, scheme, port = "", url, "", "", None
        m = re.match(r"^[a-zA-Z]+://([^/?#]+)([^?#]*)", _ensure_scheme(url))
        if m:
            host = m.group(1).split(":")[0].lower()
            path = m.group(2) or ""
    full = url.lower()
    # The training data has no "http(s)://" prefix, so length/entropy/count features
    # are computed on the URL without its scheme. Otherwise every live URL looks
    # 7-8 characters longer than anything the model was trained on.
    core = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", url)

    labels_in_host = host.split(".") if host else []
    # crude subdomain count: parts beyond domain + tld
    num_subdomains = max(len(labels_in_host) - 2, 0)

    features = {
        "url_length": len(core),
        "host_length": len(host),
        "path_length": len(path),
        "num_dots": core.count("."),
        "num_hyphens": core.count("-"),
        "num_at": core.count("@"),
        "num_question": core.count("?"),
        "num_equal": core.count("="),
        "num_underscore": core.count("_"),
        "num_ampersand": core.count("&"),
        "num_digits": sum(c.isdigit() for c in core),
        "digit_ratio": (sum(c.isdigit() for c in core) / len(core)) if core else 0,
        "has_ip_host": 1 if IP_PATTERN.match(host) else 0,
        "num_subdomains": num_subdomains,
        "uses_https_scheme": 1 if scheme == "https" else 0,
        "https_token_in_path": 1 if "https" in (path + query).lower() else 0,
        "is_shortener": 1 if any(s in host for s in SHORTENERS) else 0,
        "num_query_params": query.count("=") if query else 0,
        "entropy": round(_shannon_entropy(core), 3),
        "suspicious_word_count": sum(1 for w in SUSPICIOUS_WORDS if w in full),
        "double_slash_in_path": 1 if "//" in path else 0,
        "has_port": 1 if port else 0,
    }
    return features


FEATURE_NAMES = list(extract_features("http://example.com/").keys())


def features_to_row(raw_url: str) -> list:
    feats = extract_features(raw_url)
    return [feats[name] for name in FEATURE_NAMES]


def explain(raw_url: str) -> list:
    """Human-readable evidence lines for a URL, used in the final report."""
    f = extract_features(raw_url)
    notes = []
    if f["has_ip_host"]:
        notes.append("Hostname is a raw IP address, not a domain name.")
    if f["is_shortener"]:
        notes.append("URL uses a link-shortening service, hiding the real destination.")
    if f["num_subdomains"] >= 3:
        notes.append(f"Unusually high number of subdomains ({f['num_subdomains']}).")
    if f["https_token_in_path"] and not f["uses_https_scheme"]:
        notes.append("The word 'https' appears in the path/query — a common spoofing trick.")
    if f["num_at"] > 0:
        notes.append("Contains '@', which can hide the real destination after it.")
    if f["suspicious_word_count"] >= 2:
        notes.append(f"Contains {f['suspicious_word_count']} credential/urgency-related keywords (e.g. login, verify, secure).")
    if f["url_length"] > 75:
        notes.append(f"Unusually long URL ({f['url_length']} characters).")
    if f["entropy"] > 4.3:
        notes.append("High character randomness — consistent with an auto-generated or obfuscated URL.")
    if not f["uses_https_scheme"]:
        notes.append("Does not use HTTPS.")
    if not notes:
        notes.append("No strong lexical red flags found in the URL text alone.")
    return notes
