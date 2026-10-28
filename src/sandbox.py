"""
PHISH-X — Sandbox Inspector (v1: static, server-side)

The suspicious page is fetched by the PHISH-X *server*, never by the user's
browser, and it is only parsed — no JavaScript runs and no form is ever
submitted. That keeps the user's device, cookies and real data completely out
of the loop.

What it reports:
  * every form on the page and where it would submit to
  * what information the form asks for (password, card, CVV, OTP, ...)
  * whether data would be sent to a different domain than the page itself
  * hidden iframes, redirect tricks, and the likely attacker objective

Limits (be upfront about these in the viva): because JavaScript is not
executed, pages that build their forms dynamically will look emptier than
they really are. Phase 2b replaces this with a real isolated browser.
"""

import os
import re
import socket
import ipaddress
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

MAX_BYTES = 1_500_000        # never read more than ~1.5 MB of a page
TIMEOUT = 8                  # seconds
MAX_REDIRECTS = 5
USER_AGENT = "Mozilla/5.0 (compatible; PHISH-X-Inspector/1.0; research)"

# Local/private targets are blocked so the inspector can't be abused to probe
# internal networks (SSRF). Set PHISHX_ALLOW_LOCAL=1 only for local testing.
ALLOW_LOCAL = os.environ.get("PHISHX_ALLOW_LOCAL") == "1"


class UnsafeTarget(Exception):
    pass


def _check_host_is_public(host: str):
    if ALLOW_LOCAL:
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise UnsafeTarget("Domain does not resolve.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            raise UnsafeTarget("Target resolves to a private or reserved address; refusing to fetch.")


def _safe_get(url: str):
    """GET with manual redirect handling so every hop is re-validated."""
    chain = []
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        p = urlparse(current)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise UnsafeTarget("Only http/https URLs can be inspected.")
        _check_host_is_public(p.hostname)
        resp = requests.get(
            current, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT,
            allow_redirects=False, stream=True,
        )
        chain.append({"url": current, "status": resp.status_code})
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            nxt = resp.headers.get("Location")
            resp.close()
            if not nxt:
                break
            current = urljoin(current, nxt)
            continue
        body = b""
        for chunk in resp.iter_content(65536):
            body += chunk
            if len(body) >= MAX_BYTES:
                break
        resp.close()
        return resp, body, chain, current
    raise UnsafeTarget("Too many redirects.")


# ---- what is this field asking for? -------------------------------------

FIELD_RULES = [
    # (category, label, risk, regex over name/id/placeholder/label/autocomplete)
    ("authentication", "One-time password (OTP)", "critical", r"\botp\b|one.?time|verification.?code|sms.?code|passcode|2fa|mfa"),
    ("financial", "CVV / security code", "critical", r"\bcvv\b|\bcvc\b|card.?security|security.?code"),
    ("financial", "Card number", "critical", r"card.?(number|no)|cc.?num|credit.?card|debit.?card|cardnumber|ccnumber"),
    ("financial", "Card expiry", "high", r"expir|exp.?date|mm.?/?.?yy"),
    ("financial", "Bank account / UPI / PIN", "critical", r"account.?(number|no)|\biban\b|\bifsc\b|\bupi\b|\bpin\b|routing"),
    ("identity", "Government ID (SSN / Aadhaar / PAN)", "critical", r"\bssn\b|aadhaar|aadhar|\bpan\b|passport|national.?id"),
    ("identity", "Date of birth", "high", r"\bdob\b|birth"),
    ("personal", "Email address", "medium", r"e.?mail"),
    ("identity", "Home address", "medium", r"address|street|postal|zip|pincode"),
    ("credentials", "Password", "critical", r"pass(word|wd)?\b"),
    ("credentials", "Username / login ID", "high", r"user.?name|user.?id|login|customer.?id"),
    ("personal", "Phone number", "medium", r"phone|mobile|\btel\b"),
    ("personal", "Full name", "low", r"full.?name|first.?name|last.?name|\bname\b"),
]


def classify_attrs(ftype: str, haystack: str):
    """Classify one input from its type and its name/id/placeholder/label text."""
    ftype = (ftype or "text").lower()
    if ftype in ("hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file"):
        return None
    if ftype == "password":
        return ("credentials", "Password", "critical")
    haystack = haystack.lower()
    if ftype == "email":
        haystack += " email"
    if ftype == "tel":
        haystack += " phone"
    for category, label, risk, pattern in FIELD_RULES:
        if re.search(pattern, haystack):
            return (category, label, risk)
    return None


def _classify_field(tag, label_text: str):
    haystack = " ".join([
        tag.get("name", ""), tag.get("id", ""), tag.get("placeholder", ""),
        tag.get("autocomplete", ""), tag.get("aria-label", ""), label_text,
    ])
    return classify_attrs(tag.get("type") or "text", haystack)


def _label_for(soup, tag) -> str:
    fid = tag.get("id")
    if fid:
        lab = soup.find("label", attrs={"for": fid})
        if lab:
            return lab.get_text(" ", strip=True)
    parent_label = tag.find_parent("label")
    return parent_label.get_text(" ", strip=True) if parent_label else ""


def _registered_domain(host: str) -> str:
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "").lower()


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _infer_objectives(requested: list) -> list:
    cats = {r["category"] for r in requested}
    labels = {r["label"] for r in requested}
    objs = []
    if "financial" in cats:
        objs.append({"objective": "Financial fraud", "level": "high",
                     "why": "Page asks for card, CVV or bank details."})
    if "credentials" in cats:
        objs.append({"objective": "Credential theft", "level": "high",
                     "why": "Page asks for a login or password."})
    if "credentials" in cats and "authentication" in cats:
        objs.append({"objective": "Account takeover", "level": "high",
                     "why": "Password plus OTP together lets an attacker log in and defeat 2-factor protection."})
    elif "One-time password (OTP)" in labels:
        objs.append({"objective": "OTP theft", "level": "high",
                     "why": "Page asks for a one-time code, usually to authorise a fraudulent transaction."})
    if "Government ID (SSN / Aadhaar / PAN)" in labels or ("identity" in cats and len(cats) > 1):
        objs.append({"objective": "Identity theft", "level": "high",
                     "why": "Page asks for identity documents or personal identifiers."})
    if not objs and requested:
        objs.append({"objective": "Personal data harvesting", "level": "medium",
                     "why": "Page collects personal details with no sensitive credentials."})
    return objs


def inspect(url: str) -> dict:
    result = {"url": url, "fetched": False}
    try:
        resp, body, chain, final_url = _safe_get(url)
    except UnsafeTarget as e:
        result["error"] = str(e)
        return result
    except requests.RequestException as e:
        result["error"] = f"Could not fetch the page ({type(e).__name__}). It may be offline or blocking scanners."
        return result

    result["fetched"] = True
    result["status"] = resp.status_code
    result["redirect_chain"] = chain
    result["final_url"] = final_url
    page_host = urlparse(final_url).hostname or ""
    page_domain = _registered_domain(page_host)

    soup = BeautifulSoup(body, "html.parser")
    title = soup.title.get_text(strip=True) if soup.title else ""
    result["title"] = title

    findings = []
    forms_out = []
    requested = []

    for form in soup.find_all("form"):
        action = form.get("action") or ""
        target = urljoin(final_url, action) if action else final_url
        target_host = urlparse(target).hostname or ""
        cross = bool(target_host) and _registered_domain(target_host) != page_domain
        method = (form.get("method") or "get").upper()

        fields = []
        for tag in form.find_all(["input", "textarea", "select"]):
            c = _classify_field(tag, _label_for(soup, tag))
            if c:
                category, label, risk = c
                fields.append({"label": label, "category": category, "risk": risk})
                requested.append({"label": label, "category": category, "risk": risk})

        if not fields:
            continue
        forms_out.append({
            "action": target, "method": method,
            "sends_to_other_domain": cross,
            "insecure_transport": target.startswith("http://"),
            "fields": fields,
        })
        if cross:
            findings.append(f"A form submits to a different domain ({target_host}) than the page itself ({page_host}).")
        if target.startswith("http://") and any(f["risk"] == "critical" for f in fields):
            findings.append("Sensitive fields would be sent over unencrypted HTTP.")

    # de-duplicate requested info, keep highest risk
    merged = {}
    for r in requested:
        k = r["label"]
        if k not in merged or RISK_ORDER[r["risk"]] > RISK_ORDER[merged[k]["risk"]]:
            merged[k] = r
    requested = sorted(merged.values(), key=lambda r: -RISK_ORDER[r["risk"]])

    # hidden / suspicious iframes
    for fr in soup.find_all("iframe"):
        style = (fr.get("style") or "").replace(" ", "").lower()
        if fr.get("width") in ("0", "1") or fr.get("height") in ("0", "1") \
                or "display:none" in style or "visibility:hidden" in style:
            findings.append("Page contains a hidden iframe, often used to load content invisibly.")
            break

    # meta-refresh / JS redirects
    if soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        findings.append("Page uses a meta-refresh redirect.")
    if re.search(rb"window\.location(\.href)?\s*=|location\.replace\(", body):
        findings.append("Page contains a script-based redirect.")
    if len(chain) > 2:
        findings.append(f"URL redirected {len(chain) - 1} times before reaching this page.")

    if re.search(rb"event\.button\s*==\s*2|contextmenu", body, re.I):
        findings.append("Page tries to disable right-click, a trick used to hinder inspection.")

    # password/OTP page with very little content = typical credential trap
    if any(r["label"] == "Password" for r in requested) and len(soup.get_text(" ", strip=True)) < 400:
        findings.append("Login page with almost no real content around it.")

    if requested and not forms_out:
        forms_out = []
    if not requested:
        findings.append("No data-collection forms found in the static HTML (the page may build its forms with JavaScript).")

    result["forms"] = forms_out
    result["information_requested"] = requested
    result["likely_objectives"] = _infer_objectives(requested)
    result["findings"] = findings
    result["sandbox_mode"] = "static (page is parsed on the PHISH-X server; no scripts run, nothing is submitted)"
    result["interaction"] = "none — no form was filled or submitted in this version"
    return result
