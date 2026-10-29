#!/usr/bin/env bash
# Review demo mode: demo phishing pages (harmless, local only) + the PHISH-X service + dashboard.
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt
python3 -m playwright install chromium >/dev/null 2>&1
[ -f models/random_forest.joblib ] || (cd src && python3 train.py)
(cd demo && python3 -m http.server 9100 >/dev/null 2>&1 &)
cd src && PHISHX_ALLOW_LOCAL=1 exec python3 server.py
