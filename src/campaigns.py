"""
PHISH-X — phishing campaign detection + threat relationship graph (research contribution #4).

Idea: criminals deploy the same phishing kit on many compromised sites, so the URL *path
template* (directory layout + file names, with IDs/hashes/digits normalised) repeats across
many different domains. We group URLs by template, keep groups that are (a) large,
(b) spread over several domains and (c) almost purely phishing in the labelled data, and
call each one a campaign. A new URL that matches a known template is linked to its campaign.

Limits: the dataset has no timestamps, IPs, certificates or page content, so campaigns are
inferred from URL structure only. They are "probable same-kit" groups, not proof of one actor.

Run:  python campaigns.py      ->  reports/campaigns.json, reports/campaign_graph.png
"""
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import networkx as nx
import pandas as pd

import brands

ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = ROOT / "reports"
DATA_PATH = ROOT / "data" / "raw_urls.csv"
CAMPAIGNS_FILE = REPORT_DIR / "campaigns.json"

MIN_URLS, MIN_DOMAINS, MIN_PURITY = 8, 4, 0.95


def template(url: str):
    """Normalised path template, or None if the URL has no distinctive path."""
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", url.strip().lower())
    host, _, rest = u.partition("/")
    path = rest.split("#")[0]
    path, _, query = path.partition("?")
    segs = [s for s in path.split("/") if s]
    if len(segs) < 2 and not (segs and "." in segs[-1]):
        return None
    norm = []
    for s in segs:
        s = re.sub(r"[0-9a-f]{8,}", "<id>", s)          # hashes / long ids
        s = re.sub(r"\d+", "#", s)                       # numbers
        s = re.sub(r"[a-z0-9]{14,}", "<id>", s)          # long random tokens
        norm.append(s)
    qkeys = ",".join(sorted(re.findall(r"([a-z0-9_]+)=", query)))
    t = "/" + "/".join(norm) + (("?" + qkeys) if qkeys else "")
    return t if len(t) >= 12 else None


def host_of(url):
    return brands.hostname(url)


def target_brand(urls):
    """Most common brand mentioned anywhere in the group's URLs (host or path)."""
    c = Counter()
    for u in urls:
        low = re.sub(r"^[a-z]+://", "", u.lower())
        low = low.translate(brands._HOMOGLYPH)
        for brand, (kws, _) in brands.BRANDS.items():
            if any(k in low for k in kws if len(k) >= 4):
                c[brand] += 1
    return c.most_common(1)[0][0] if c else None


def build(max_urls=None):
    df = pd.read_csv(DATA_PATH).dropna()
    df["bad"] = (df["Label"].str.lower() == "bad").astype(int)
    df["tpl"] = df["URL"].map(template)
    df = df[df.tpl.notna()]
    # purity of each template across the WHOLE labelled set (so benign-looking templates drop out)
    stats = df.groupby("tpl")["bad"].agg(["size", "sum"])
    stats["purity"] = stats["sum"] / stats["size"]
    keep = stats[(stats["size"] >= MIN_URLS) & (stats["purity"] >= MIN_PURITY)].index
    bad = df[(df.bad == 1) & df.tpl.isin(keep)].copy()
    bad["host"] = bad["URL"].map(host_of)
    bad["rd"] = bad["host"].map(brands.registered_domain)

    campaigns = []
    for tpl, g in bad.groupby("tpl"):
        domains = g["rd"].nunique()
        if domains < MIN_DOMAINS:
            continue
        urls = g["URL"].tolist()
        tlds = Counter(h.rsplit(".", 1)[-1] for h in g["host"] if "." in h)
        campaigns.append({"template": tpl, "urls": len(g), "domains": int(domains),
                          "target_brand": target_brand(urls), "top_tlds": tlds.most_common(3),
                          "example_domains": g["rd"].drop_duplicates().head(5).tolist(),
                          "example_urls": urls[:2], "purity_pct": round(100 * float(stats.loc[tpl, "purity"]), 1)})
    campaigns.sort(key=lambda c: (-c["domains"], -c["urls"]))
    for i, c in enumerate(campaigns, 1):
        c["id"] = i
        c["risk"] = "CRITICAL" if c["domains"] >= 40 else "HIGH" if c["domains"] >= 15 else "MEDIUM"
    out = {"params": {"min_urls": MIN_URLS, "min_domains": MIN_DOMAINS, "min_purity": MIN_PURITY},
           "labelled_urls_with_template": int(len(df)), "campaigns": campaigns}
    REPORT_DIR.mkdir(exist_ok=True)
    CAMPAIGNS_FILE.write_text(json.dumps(out, indent=1))
    return out, bad


_index = None


def match_campaign(url: str):
    """Link a new URL to a known campaign (by path template). Returns dict or None."""
    global _index
    if _index is None:
        _index = {}
        if CAMPAIGNS_FILE.exists():
            for c in json.loads(CAMPAIGNS_FILE.read_text())["campaigns"]:
                _index[c["template"]] = c
    t = template(url)
    c = _index.get(t) if t else None
    if not c:
        return None
    return {"campaign_id": c["id"], "domains": c["domains"], "urls": c["urls"], "risk": c["risk"],
            "target_brand": c["target_brand"]}


def draw_graph(out, bad, top=6):
    G = nx.Graph()
    for c in out["campaigns"][:top]:
        cid = f"Campaign #{c['id']}"
        G.add_node(cid, kind="campaign", size=c["domains"])
        if c["target_brand"]:
            G.add_node(c["target_brand"], kind="brand")
            G.add_edge(cid, c["target_brand"])
        for d in c["example_domains"][:5]:
            G.add_node(d, kind="domain")
            G.add_edge(cid, d)
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(11, 7))
    pos = nx.spring_layout(G, k=0.9, seed=4)
    col = {"campaign": "#C1443A", "brand": "#D98E2B", "domain": "#2E8B77"}
    for kind in col:
        ns = [n for n, d in G.nodes(data=True) if d["kind"] == kind]
        nx.draw_networkx_nodes(G, pos, nodelist=ns, node_color=col[kind], ax=ax,
                               node_size=[900 if kind == "campaign" else 450 if kind == "brand" else 220 for _ in ns], label=kind)
    nx.draw_networkx_edges(G, pos, ax=ax, alpha=0.35)
    nx.draw_networkx_labels(G, pos, font_size=7, ax=ax)
    ax.legend(loc="lower left"); ax.axis("off")
    ax.set_title("Phishing campaigns: campaign → target brand → domains hosting the same kit")
    fig.savefig(REPORT_DIR / "campaign_graph.png", dpi=130, bbox_inches="tight")


if __name__ == "__main__":
    out, bad = build()
    cs = out["campaigns"]
    print(f"{len(cs)} campaigns found from {out['labelled_urls_with_template']} URLs with a distinctive path")
    for c in cs[:8]:
        print(f"#{c['id']:<3d} {c['risk']:8s} {c['domains']:3d} domains {c['urls']:4d} urls  brand={c['target_brand']}  {c['template'][:70]}")
    draw_graph(out, bad)
    print("graph saved")
