#!/usr/bin/env bash
# Demo mode: serves a harmless FAKE phishing page on http://127.0.0.1:9100/ and starts
# the service with local inspection allowed (normally blocked, to prevent misuse).
cd "$(dirname "$0")"
python3 -m http.server 9100 --bind 127.0.0.1 >/dev/null 2>&1 &
echo "Fake phishing page: http://127.0.0.1:9100/fake_phishing_page.html"
cd ../src && PHISHX_ALLOW_LOCAL=1 exec python3 server.py
