"""
PHISH-X — email phishing analysis + NLP social-engineering detector.

Input: a raw email (RFC-822 text, e.g. "Show original" in Gmail or a saved .eml file).
It checks three kinds of evidence and combines them:
  1. HEADERS   - sender display name vs real address, Reply-To / Return-Path mismatch, SPF/DKIM/DMARC results
  2. LINKS     - every link is run through the URL model; links whose visible text shows one site while
                 the real target is another are flagged; shorteners are flagged
  3. LANGUAGE  - a rule-based lexicon of social-engineering tactics (urgency, threat, reward, authority,
                 credential request, payment pressure), plus risky attachment types

Limits (say these): the language part is a keyword/phrase lexicon, not a trained model, and there was no
labelled email dataset available during development, so its accuracy is UNMEASURED. It is tuned on a
handful of sample emails in tests/emails. Training a classifier needs a labelled phishing-email corpus.
"""
import re
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from urllib.parse import urlparse

from bs4 import BeautifulSoup

import brands
import core

LEXICON = {
    "urgency": (r"\b(urgent|immediately|right away|asap|within \d+ ?(hours?|hrs?|days?|minutes?)|last warning|final notice|"
                r"expires? (today|soon|in)|act now|as soon as possible|before it'?s too late)\b", 8),
    "threat": (r"\b(suspend(ed)?|deactivat(e|ed)|terminat(e|ed)|blocked|locked|restricted|unauthori[sz]ed|legal action|"
               r"arrest|penalty|permanently (closed|disabled)|will be closed|compromised)\b", 9),
    "reward": (r"\b(you('ve| have)? won|winner|prize|lottery|gift card|cashback|refund|reward|congratulations|free (gift|iphone)|claim (your|now))\b", 8),
    "authority": (r"\b(security (team|department|alert)|it (support|department|helpdesk)|customer (care|support) team|"
                  r"income tax|reserve bank|\brbi\b|\bkyc\b|compliance|official notice|administrator)\b", 6),
    "credential_request": (r"\b(verify your (account|identity|details|password)|confirm your (password|identity|account|details)|"
                           r"update your (kyc|password|billing|payment|account)|re-?enter your|enter your (otp|pin|password|card)|"
                           r"log ?in to (verify|confirm|restore|unlock)|sign in to (verify|confirm|keep))\b", 12),
    "payment_pressure": (r"\b(pay (now|immediately)|outstanding (balance|payment)|invoice|wire transfer|overdue|processing fee|"
                         r"service charge|payment (failed|declined|pending))\b", 7),
    "generic_greeting": (r"\b(dear (customer|user|member|client|account holder|sir/madam)|valued customer)\b", 4),
}
INTENT_FROM = {
    "credential_request": "Credential theft / account takeover", "threat": "Account takeover (fear of losing access)",
    "reward": "Advance-fee / reward scam", "payment_pressure": "Payment fraud", "authority": "Impersonation of an authority",
}
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at")
RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".iso", ".img", ".lnk", ".docm", ".xlsm", ".html", ".htm", ".zip", ".rar", ".7z")
_MODEL = {"loaded": False, "m": None}


def _text_model():
    """Optional TF-IDF + logistic-regression wording model (models/email_text.joblib, built by tools/train_email_model.py)."""
    if not _MODEL["loaded"]:
        _MODEL["loaded"] = True
        import os
        path = os.environ.get("PHISHX_EMAIL_MODEL") or os.path.join(os.path.dirname(__file__), "..", "models", "email_text.joblib")
        try:
            import joblib
            _MODEL["m"] = joblib.load(path)
        except Exception:
            _MODEL["m"] = None
    return _MODEL["m"]


def _clean_for_model(subject, body):
    t = f"{subject or ''} {body or ''}"[:6000]
    t = re.sub(r"https?://\S+", " URLTOKEN ", t)
    t = re.sub(r"\S+@\S+", " EMAILTOKEN ", t)
    t = re.sub(r"_{3,}|-{3,}|={3,}", " ", t)
    return re.sub(r"\d+", " ", t)


def text_model_probability(subject, body):
    m = _text_model()
    if not m:
        return None, []
    X = m["vec"].transform([_clean_for_model(subject, body)])
    p = float(m["clf"].predict_proba(X)[0, 1])
    idx = X.nonzero()[1]
    names = m["vec"].get_feature_names_out()
    contrib = sorted(((float(m["clf"].coef_[0][i] * X[0, i]), names[i]) for i in idx), reverse=True)
    return p, [w for c, w in contrib[:5] if c > 0]


URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


def _parse(raw):
    if isinstance(raw, bytes):
        return BytesParser(policy=policy.default).parsebytes(raw)
    return Parser(policy=policy.default).parsestr(raw)


def _body_parts(msg):
    text, html, atts = "", "", []
    for part in msg.walk():
        ctype = part.get_content_type()
        fn = part.get_filename()
        if fn:
            atts.append(fn)
            continue
        if ctype == "text/plain":
            try: text += part.get_content()
            except Exception: pass
        elif ctype == "text/html":
            try: html += part.get_content()
            except Exception: pass
    return text, html, atts


def _links(text, html):
    out = []   # (visible_text, href)
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            out.append((a.get_text(" ", strip=True), a["href"]))
        text = text + " " + soup.get_text(" ", strip=True)
    seen = {h for _, h in out}
    for u in URL_RE.findall(text):
        if u not in seen:
            out.append((u, u)); seen.add(u)
    return [(t, h) for t, h in out if h.lower().startswith(("http://", "https://"))], text


def _domain(addr):
    return brands.registered_domain(addr.split("@")[-1].lower()) if "@" in addr else ""


def analyze(raw):
    msg = _parse(raw)
    subject = str(msg.get("subject", "") or "")
    disp, from_addr = parseaddr(str(msg.get("from", "") or ""))
    from_dom = _domain(from_addr)
    findings, score = [], 0

    # ---- 1. headers
    _, reply_to = parseaddr(str(msg.get("reply-to", "") or ""))
    _, ret_path = parseaddr(str(msg.get("return-path", "") or ""))
    if reply_to and _domain(reply_to) != from_dom:
        score += 12; findings.append({"area": "headers", "text": f"Replies go to a different domain ({_domain(reply_to)}) than the sender ({from_dom})."})
    if ret_path and _domain(ret_path) != from_dom:
        score += 6; findings.append({"area": "headers", "text": "The hidden return address is on a different domain than the visible sender."})
    auth = str(msg.get("authentication-results", "") or "").lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(mech + r"=(\w+)", auth)
        if m and m.group(1) in ("fail", "softfail", "none", "permerror", "temperror"):
            score += 8; findings.append({"area": "headers", "text": f"{mech.upper()} check result: {m.group(1)} (the sender could not be verified)."})
    if disp:  # display name claims a brand, address does not belong to it
        low = disp.lower().translate(brands._HOMOGLYPH)
        for brand, (kws, official) in brands.BRANDS.items():
            if any(k in low for k in kws if len(k) >= 4) and not brands._is_official_or_subdomain(from_addr.split("@")[-1].lower()):
                score += 18; findings.append({"area": "headers", "text": f"The sender name says '{disp}' but the address ({from_addr}) is not a {brand} domain ({official[0]})."})
                break
    if from_addr and brands.impersonation("http://" + from_addr.split("@")[-1]) :
        score += 10; findings.append({"area": "headers", "text": f"The sending domain {from_dom} looks like a copy of a well-known brand."})

    # ---- 2. links
    text, html, atts = _body_parts(msg)
    links, full_text = _links(text, html)
    link_results = []
    worst = 0
    for vis, href in links[:10]:
        h = brands.hostname(href)
        r = core.assess(href)
        item = {"url": href[:200], "verdict": r["verdict"], "risk_score": r["risk_score"]}
        if r["risk_score"] > worst:
            worst = r["risk_score"]
        shown = URL_RE.search(vis or "")
        if shown and brands.registered_domain(brands.hostname(shown.group(0))) != brands.registered_domain(h):
            score += 20; item["deceptive_text"] = True
            findings.append({"area": "links", "text": f"A link shows '{vis[:60]}' but really goes to {h}."})
        if any(h == s or h.endswith("." + s) for s in SHORTENERS):
            score += 8; findings.append({"area": "links", "text": f"Uses a link shortener ({h}), which hides the real destination."})
        if r["verdict"] == "PHISHING":
            findings.append({"area": "links", "text": f"Link {h} scored {r['risk_score']}/100: " + (r["evidence"][0] if r["evidence"] else "")})
        link_results.append(item)
    score += round(worst * 0.30) if worst >= 70 else (round(worst * 0.10) if worst >= 40 else 0)

    # ---- 3. language
    tactics, lang_score = {}, 0
    for name, (pat, w) in LEXICON.items():
        hits = re.findall(pat, subject + " " + full_text, flags=re.I)
        if hits:
            tactics[name] = len(hits); lang_score += min(w * len(hits), w * 2)
    if tactics:
        findings.append({"area": "language", "text": "Pressure tactics found: " + ", ".join(t.replace("_", " ") for t in tactics) + "."})
    score += min(lang_score, 34)
    if sum(1 for t in tactics if t in ("urgency", "threat")) == 2 and "credential_request" in tactics:
        score += 10; findings.append({"area": "language", "text": "Urgency + threat + a request to verify credentials is the classic phishing pattern."})

    # ---- wording model (trained on real phishing / scam / genuine emails)
    model_p = None
    try:
        model_p, words = text_model_probability(subject, full_text)
    except Exception:
        words = []
    if model_p is not None and model_p >= 0.5:
        score += round((model_p - 0.5) * 2 * 45)
        findings.append({"area": "language", "text": f"The wording resembles known phishing/scam emails (model confidence {round(model_p * 100)}%; key words: {', '.join(words)})."})

    # ---- attachments
    risky = [f for f in atts if f.lower().endswith(RISKY_EXT)]
    if risky:
        score += 18; findings.append({"area": "attachments", "text": "Risky attachment type: " + ", ".join(risky[:3]) + "."})

    score = max(0, min(100, score))
    verdict, level = core.verdict_for(score)
    intents = sorted({INTENT_FROM[t] for t in tactics if t in INTENT_FROM})
    if risky:
        intents.append("Malware delivery")
    return {"subject": subject[:200], "from": f"{disp} <{from_addr}>".strip(), "verdict": verdict, "risk_level": level,
            "risk_score": score, "wording_model_probability": None if model_p is None else round(model_p, 3), "tactics": tactics, "likely_objectives": intents, "findings": findings,
            "links": link_results, "attachments": atts,
            "note": "Wording uses a model trained on public phishing/scam/genuine emails plus a rule lexicon. See reports/email_metrics.json for measured accuracy and its limits."}
