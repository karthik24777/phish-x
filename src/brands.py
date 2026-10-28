"""
PHISH-X — brand awareness.

Two jobs:
  1. Trust: if a URL's registered domain is an official domain of a known brand,
     it is not a phishing candidate (fixes the "legit login pages look scary" problem
     that a text-only model has).
  2. Impersonation: if the host *mentions* a brand (including look-alikes such as
     paypa1 -> paypal) but is NOT one of that brand's official domains, that is strong
     evidence of impersonation.

Limits: the brand table is hand-curated (~40 brands, India-heavy) and a trusted domain
can still serve a malicious page (compromised site, open redirect). The table is meant
to be extended, not treated as complete.
"""

import re
from urllib.parse import urlparse

# Common two-level public suffixes. Not the full Public Suffix List.
TWO_LEVEL_SUFFIXES = {
    "co.in", "ac.in", "gov.in", "nic.in", "org.in", "net.in", "res.in", "edu.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz", "co.jp", "com.br",
    "com.cn", "co.za", "com.sg", "com.my", "com.pk", "co.id", "com.mx",
}

# brand -> (keywords to look for in a hostname, official registered domains)
BRANDS = {
    "PayPal":        (["paypal"],                 ["paypal.com", "paypal.me"]),
    "Google":        (["google", "gmail"],        ["google.com", "gmail.com", "youtube.com", "google.co.in", "goo.gl", "gstatic.com", "googleapis.com", "googleusercontent.com"]),
    "Microsoft":     (["microsoft", "office365", "outlook", "onedrive"],
                      ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "bing.com", "windows.com", "sharepoint.com", "office365.com", "msn.com", "azure.com", "azurewebsites.net"]),
    "Apple":         (["apple", "icloud"],        ["apple.com", "icloud.com"]),
    "Amazon":        (["amazon"],                 ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "primevideo.com", "amazonaws.com"]),
    "Meta":          (["facebook", "instagram", "whatsapp"],
                      ["facebook.com", "fb.com", "instagram.com", "whatsapp.com", "whatsapp.net", "meta.com", "messenger.com"]),
    "Netflix":       (["netflix"],                ["netflix.com"]),
    "LinkedIn":      (["linkedin"],               ["linkedin.com"]),
    "X / Twitter":   (["twitter"],                ["twitter.com", "x.com"]),
    "Dropbox":       (["dropbox"],                ["dropbox.com"]),
    "GitHub":        (["github"],                 ["github.com", "githubusercontent.com", "github.io"]),
    "Adobe":         (["adobe"],                  ["adobe.com"]),
    "DHL":           (["dhl"],                    ["dhl.com"]),
    "FedEx":         (["fedex"],                  ["fedex.com"]),
    "SBI":           (["sbi", "onlinesbi", "sbicard"], ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbi.bank.in", "sbiyono.sbi"]),
    "HDFC Bank":     (["hdfc", "hdfcbank"],       ["hdfcbank.com", "hdfc.com", "hdfcbank.net", "hdfclife.com", "hdfcergo.com"]),
    "ICICI Bank":    (["icici", "icicibank"],     ["icicibank.com", "icicidirect.com", "icicilombard.com", "iciciprulife.com"]),
    "Axis Bank":     (["axisbank"],               ["axisbank.com", "axis.bank.in"]),
    "Kotak":         (["kotak"],                  ["kotak.com", "kotak.bank.in"]),
    "PNB":           (["pnbindia"],               ["pnbindia.in"]),
    "Bank of Baroda": (["bankofbaroda"],          ["bankofbaroda.in", "bankofbaroda.com"]),
    "Canara Bank":   (["canarabank"],             ["canarabank.com", "canarabank.in"]),
    "Paytm":         (["paytm"],                  ["paytm.com", "paytmbank.com"]),
    "PhonePe":       (["phonepe"],                ["phonepe.com"]),
    "Google Pay":    (["gpay", "googlepay"],      ["pay.google.com"]),
    "IRCTC":         (["irctc"],                  ["irctc.co.in"]),
    "Flipkart":      (["flipkart"],               ["flipkart.com"]),
    "Myntra":        (["myntra"],                 ["myntra.com"]),
    "Swiggy":        (["swiggy"],                 ["swiggy.com"]),
    "Zomato":        (["zomato"],                 ["zomato.com"]),
    "Income Tax India": (["incometax", "incometaxindia"], ["incometax.gov.in", "incometaxindia.gov.in"]),
    "Aadhaar / UIDAI": (["uidai", "aadhaar"],     ["uidai.gov.in"]),
    "Chase":         (["chase"],                  ["chase.com"]),
    "Wells Fargo":   (["wellsfargo"],             ["wellsfargo.com"]),
    "Bank of America": (["bankofamerica"],        ["bankofamerica.com"]),
    "Citibank":      (["citibank"],               ["citibank.com", "citi.com"]),
    "Binance":       (["binance"],                ["binance.com"]),
    "Coinbase":      (["coinbase"],               ["coinbase.com"]),
}

# Trusted without being a "brand" we check impersonation for.
EXTRA_TRUSTED = {
    "wikipedia.org", "stackoverflow.com", "python.org", "mozilla.org", "npmjs.com",
    "reddit.com", "medium.com", "bbc.com", "bbc.co.uk", "nytimes.com", "github.com",
    "kct.ac.in",
}
TRUSTED_TLD_SUFFIXES = ("gov.in", "nic.in", "ac.in", "edu", "gov")

OFFICIAL = {}
for _brand, (_kw, _doms) in BRANDS.items():
    for _d in _doms:
        OFFICIAL[_d] = _brand

_HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "$": "s", "@": "a"})


def hostname(url: str) -> str:
    u = url if "://" in url else "http://" + url
    try:
        return (urlparse(u).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def registered_domain(host: str) -> str:
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""):
        return host  # an IP address has no registered domain; keep it whole
    labels = [l for l in host.split(".") if l]
    if len(labels) < 2:
        return host
    last2 = ".".join(labels[-2:])
    if last2 in TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last2


def _is_official_or_subdomain(host: str):
    """Match on the registered domain, NOT on substrings, so
    'paypal.com.evil.ru' and 'notpaypal.com' do not match."""
    rd = registered_domain(host)
    if rd in OFFICIAL:
        return OFFICIAL[rd]
    # official entries that are themselves subdomains (e.g. pay.google.com)
    for dom, brand in OFFICIAL.items():
        if host == dom or host.endswith("." + dom):
            return brand
    return None


def trusted(url: str):
    """Return a human-readable reason if the URL is on a trusted domain, else None."""
    host = hostname(url)
    if not host:
        return None
    brand = _is_official_or_subdomain(host)
    if brand:
        return f"Official {brand} domain ({registered_domain(host)})."
    rd = registered_domain(host)
    if rd in EXTRA_TRUSTED:
        return f"{rd} is on the built-in trusted list."
    if any(host == s or host.endswith("." + s) for s in TRUSTED_TLD_SUFFIXES):
        return "Government / academic domain."
    return None


def impersonation(url: str):
    """Return (brand, official_domain, matched_token) if the host looks like it
    impersonates a known brand, else None."""
    host = hostname(url)
    if not host or _is_official_or_subdomain(host):
        return None
    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    for brand, (keywords, official) in BRANDS.items():
        for tok in tokens:
            variants = {tok, tok.translate(_HOMOGLYPH)}
            if "1" in tok:
                variants.add(tok.replace("1", "i"))
            for v in variants:
                for kw in keywords:
                    hit = (v == kw) if len(kw) <= 4 else (kw in v)
                    if hit:
                        return brand, official[0], tok
    return None
