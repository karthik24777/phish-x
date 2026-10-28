#!/usr/bin/env bash
# Starts the PHISH-X protection service + dashboard on http://127.0.0.1:8765
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt || exit 1
python3 -m playwright install chromium >/dev/null 2>&1 || echo "Note: Chromium not installed; the sandbox will use the static fallback."
[ -f models/random_forest.joblib ] || (cd src && python3 train.py)
cd src && exec python3 server.py
