"""
PHISH-X — autonomous investigation agent (research contribution #2).

The agent investigates a link the way an analyst would: it picks the NEXT tool based on what it has
found so far, stops as soon as the evidence is clear, and writes a reasoning trail.

Tools: url_analysis (ML + brand + campaign), dns_lookup, redirect_trace, tls_check,
       static_inspect (page HTML), dynamic_sandbox (isolated browser + synthetic data), finish.

Planner (who chooses the next tool):
  * RulePlanner  - default, works offline, deterministic. A hand-written policy: this is an
                   *adaptive* agent, but it is NOT a language model.
  * LLMPlanner   - optional. Set PHISHX_PLANNER=llm and ANTHROPIC_API_KEY, `pip install anthropic`.
                   The model only chooses WHICH tool runs next; it never sees raw page text (only
                   structured summaries), so a hostile page cannot inject instructions into it, and it
                   cannot run anything outside the fixed tool list. NOTE: written but not exercised in
                   the development environment (no API key there); any error falls back to RulePlanner.

fixed_pipeline() runs every tool in a fixed order and is the baseline for the comparison.
"""
import json
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import core
import sandbox as static

TOOL_ORDER = ["url_analysis", "dns_lookup", "redirect_trace", "tls_check", "static_inspect", "dynamic_sandbox"]


class State:
    def __init__(self, url):
        self.url = url
        self.host = (urlparse(url if "://" in url else "http://" + url).hostname or "")
        self.obs, self.raw, self.steps = {}, {}, []


# ------------------------------------------------------------------ tools
def t_url_analysis(st):
    a = core.assess(st.url)
    st.raw["url_analysis"] = a
    return {"model_score": a["model_score"], "risk_score": a["risk_score"], "trusted": a["trusted"],
            "impersonates": a["impersonates"], "campaign_match": bool(a["campaign"]),
            "scheme_https": st.url.lower().startswith("https://"),
            "top_factors": [f"{f['label']} {f['direction']}" for f in a["top_factors"][:3]]}


def t_dns_lookup(st):
    try:
        static._check_host_is_public(st.host)
        ips = sorted({i[4][0] for i in socket.getaddrinfo(st.host, None)})
        return {"resolves": True, "ips": ips[:4], "private": False}
    except static.UnsafeTarget as e:
        if "does not resolve" in str(e):
            return {"resolves": False}
        return {"resolves": True, "private": True}
    except Exception:
        return {"resolves": False}


def t_redirect_trace(st):
    try:
        _, _, chain, final = static._safe_get(st.url)
        fh = urlparse(final).hostname or ""
        return {"ok": True, "hops": len(chain) - 1, "changes_domain": fh != st.host}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}


def t_tls_check(st):
    p = urlparse(st.url)
    if p.scheme != "https":
        return {"applicable": False}
    try:
        static._check_host_is_public(st.host)
        ctx = ssl.create_default_context()
        with socket.create_connection((st.host, p.port or 443), timeout=4) as s:
            with ctx.wrap_socket(s, server_hostname=st.host) as ss:
                cert = ss.getpeercert()
        nb = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return {"applicable": True, "valid": True, "cert_age_days": (datetime.now(timezone.utc) - nb).days}
    except ssl.SSLCertVerificationError:
        return {"applicable": True, "valid": False}
    except Exception as e:
        return {"applicable": True, "valid": None, "error": type(e).__name__}


def t_static_inspect(st):
    r = static.inspect(st.url)
    st.raw["static_inspect"] = r
    return {"fetched": r.get("fetched", False), "requested": [i["label"] for i in r.get("information_requested", [])],
            "cross_domain_form": any(f["sends_to_other_domain"] for f in r.get("forms", []))}


def t_dynamic_sandbox(st):
    r = core.inspect_page(st.url)
    st.raw["dynamic_sandbox"] = r
    return {"fetched": r.get("fetched", False), "requested": [i["label"] for i in r.get("information_requested", [])],
            "rounds": len(r.get("rounds", [])), "cross_domain_form": any(f["sends_to_other_domain"] for f in r.get("forms", [])),
            "password_sent": any(f.get("transmits_password") for f in r.get("forms", []))}


TOOLS = {"url_analysis": t_url_analysis, "dns_lookup": t_dns_lookup, "redirect_trace": t_redirect_trace,
         "tls_check": t_tls_check, "static_inspect": t_static_inspect, "dynamic_sandbox": t_dynamic_sandbox}


# ------------------------------------------------------------------ evidence -> score
def assess_state(st):
    base = dict(core.assess(st.url))
    page = (st.raw.get("dynamic_sandbox") or st.raw.get("static_inspect"))
    score, reasons = core.combine(base, page) if page else (base["risk_score"], [])
    notes = list(base["evidence"]) + reasons
    d, tls, rd = st.obs.get("dns_lookup"), st.obs.get("tls_check"), st.obs.get("redirect_trace")
    if d and not d.get("resolves"):
        notes.append("The domain does not resolve, so the page could not be inspected; verdict rests on the link alone.")
    if tls and tls.get("valid") is False:
        score += 8; notes.append("The site's HTTPS certificate failed verification.")
    elif tls and tls.get("cert_age_days") is not None and tls["cert_age_days"] <= 7:
        score += 4; notes.append("The HTTPS certificate was issued within the last week.")
    if rd and rd.get("hops", 0) >= 3:
        score += 4; notes.append(f"The link bounced through {rd['hops']} redirects.")
    if rd and rd.get("changes_domain") and rd.get("hops", 0) >= 1:
        score += 4; notes.append("The link ends up on a different domain than it started on.")
    score = max(0, min(100, score))
    return score, notes, (page or {})


# ------------------------------------------------------------------ planners
class RulePlanner:
    def next(self, st):
        o = st.obs
        if "url_analysis" not in o:
            return "Start with the cheap checks: link text, brand, and known-campaign pattern.", "url_analysis"
        a = o["url_analysis"]
        if a["trusted"]:
            return "This is an official domain of a known brand, so deeper checks are unnecessary.", "finish"
        if a["risk_score"] <= 15 and not a["impersonates"]:
            return "The link looks ordinary and nothing suggests impersonation, so stop here.", "finish"
        if "dns_lookup" not in o:
            return "Not clear-cut yet. Check whether the domain exists and where it points.", "dns_lookup"
        if not o["dns_lookup"].get("resolves"):
            return "The domain does not resolve, so the page cannot be inspected. Decide on the link evidence alone.", "finish"
        strong = a["risk_score"] >= 90
        if "redirect_trace" not in o and not strong:
            return "Follow the redirects: scam links often hop through several sites.", "redirect_trace"
        if a["scheme_https"] and "tls_check" not in o and not strong:
            return "The link claims HTTPS, so check the certificate.", "tls_check"
        if "static_inspect" not in o:
            return "Fetch the page HTML and see which forms it contains.", "static_inspect"
        s = o["static_inspect"]
        score, _, _ = assess_state(st)
        if "dynamic_sandbox" not in o:
            if s.get("requested") and score >= 95:
                return "The page asks for sensitive data and every signal agrees. Evidence is overwhelming.", "finish"
            why = ("Forms found: confirm in the sandbox where the data really goes by filling synthetic details."
                   if s.get("requested") else
                   "No forms in the raw HTML, but the page may build them with JavaScript. Open it in the sandbox.")
            return why, "dynamic_sandbox"
        return "All useful evidence has been gathered.", "finish"


class LLMPlanner:
    def __init__(self):
        import anthropic
        self.client = anthropic.Anthropic()
        self.model = os.environ.get("PHISHX_LLM_MODEL", "claude-sonnet-5-5")
        self.fallback = RulePlanner()

    def next(self, st):
        remaining = [t for t in TOOL_ORDER if t not in st.obs]
        prompt = ("You are a phishing analyst choosing the next investigation step. Observations so far (structured, "
                  "already sanitised):\n" + json.dumps(st.obs) + "\nTools still available: " + json.dumps(remaining) +
                  "\nStop with tool 'finish' as soon as the evidence is clear. Prefer cheap tools first. "
                  'Reply with JSON only: {"thought": "<one sentence>", "tool": "<tool name or finish>"}')
        try:
            msg = self.client.messages.create(model=self.model, max_tokens=200, messages=[{"role": "user", "content": prompt}])
            text = msg.content[0].text
            data = json.loads(text[text.index("{"): text.rindex("}") + 1])
            tool = data["tool"]
            if tool != "finish" and tool not in remaining:
                raise ValueError("invalid tool")
            if "url_analysis" not in st.obs:
                tool = "url_analysis"
            return str(data.get("thought", ""))[:300], tool
        except Exception:
            return self.fallback.next(st)


def make_planner():
    if os.environ.get("PHISHX_PLANNER") == "llm" and os.environ.get("ANTHROPIC_API_KEY"):
        try:
            return LLMPlanner(), "llm"
        except Exception:
            pass
    return RulePlanner(), "rules"


# ------------------------------------------------------------------ run
def _summ(tool, o):
    if tool == "url_analysis":
        return f"model {o['model_score']}, risk {o['risk_score']}" + (f", impersonates {o['impersonates']}" if o["impersonates"] else "") + (", trusted" if o["trusted"] else "")
    if tool == "dns_lookup":
        return "resolves" if o.get("resolves") else "does not resolve"
    if tool == "redirect_trace":
        return f"{o.get('hops', '?')} redirect(s)" if o.get("ok") else "could not trace"
    if tool == "tls_check":
        return "not HTTPS" if not o.get("applicable") else ("certificate valid" if o.get("valid") else "certificate problem")
    return (f"asks for: {', '.join(o['requested'])}" if o.get("requested") else "no data-collection fields") if o.get("fetched") else "page could not be opened"


def _finalize(st, planner_name, mode, elapsed):
    score, notes, page = assess_state(st)
    verdict, level = core.verdict_for(score)
    level_ev = ("link + page + interaction" if "dynamic_sandbox" in st.obs and st.obs["dynamic_sandbox"].get("fetched")
                else "link + page" if "static_inspect" in st.obs and st.obs["static_inspect"].get("fetched") else "link only")
    return {"url": st.url, "verdict": verdict, "risk_level": level, "risk_score": score,
            "uncertain": 40 <= score < 70, "evidence_level": level_ev, "mode": mode, "planner": planner_name,
            "tools_used": [s["tool"] for s in st.steps], "n_tool_calls": len(st.steps), "seconds": round(elapsed, 2),
            "reasoning_trail": st.steps, "evidence": notes,
            "information_requested": page.get("information_requested", []),
            "likely_objectives": page.get("likely_objectives", []),
            "forms": page.get("forms", [])}


def investigate(url, max_steps=8):
    st, (planner, pname), t0 = State(url), make_planner(), time.time()
    for n in range(1, max_steps + 1):
        thought, tool = planner.next(st)
        if tool == "finish":
            st.steps.append({"n": n, "thought": thought, "tool": "finish", "result": "verdict issued"})
            st.steps_finish = True
            break
        t1 = time.time()
        res = TOOLS[tool](st)
        st.obs[tool] = res
        st.steps.append({"n": n, "thought": thought, "tool": tool, "result": _summ(tool, res), "seconds": round(time.time() - t1, 2)})
    out = _finalize(st, pname, "agent", time.time() - t0)
    out["n_tool_calls"] = len([s for s in st.steps if s["tool"] != "finish"])
    out["tools_used"] = [s["tool"] for s in st.steps if s["tool"] != "finish"]
    return out


def fixed_pipeline(url):
    """Baseline: run every tool, in the same order, every time."""
    st, t0 = State(url), time.time()
    for n, tool in enumerate(TOOL_ORDER, 1):
        t1 = time.time()
        res = TOOLS[tool](st)
        st.obs[tool] = res
        st.steps.append({"n": n, "thought": "fixed order", "tool": tool, "result": _summ(tool, res), "seconds": round(time.time() - t1, 2)})
    out = _finalize(st, "none", "fixed_pipeline", time.time() - t0)
    return out


if __name__ == "__main__":
    import sys
    r = investigate(sys.argv[1])
    print(f"{r['verdict']} ({r['risk_score']}/100)  evidence: {r['evidence_level']}  tools: {r['n_tool_calls']}  planner: {r['planner']}")
    for s in r["reasoning_trail"]:
        print(f"  {s['n']}. [{s['tool']}] {s['thought']}  ->  {s['result']}")
