"""
PHISH-X system-wide link guard.

Windows hands every link you click in other apps (WhatsApp Desktop, Outlook, Word, Telegram...) to your
DEFAULT BROWSER. install_link_handler.py registers this script as a browser, you pick it as default once,
and from then on every link comes here first:

    safe link       -> opened straight away in your real browser, no popup
    grey zone       -> page is inspected quietly first, popup only if it looks like a data trap
    dangerous link  -> a small popup window: verdict, reasons, "check in sandbox?", "open anyway"

It FAILS OPEN: if anything goes wrong (service down and cannot be started, no popup possible) the link is
simply opened in your real browser, so a bug here can never leave you unable to open links.
Standard library only (it runs before anything else is installed).
"""
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
API = "http://127.0.0.1:8765"
CONFIG = os.path.join(HERE, "config.json")

CANDIDATES = [
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/microsoft-edge",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def real_browser():
    """The browser we hand safe links to. Never the PHISH-X handler itself."""
    env = os.environ.get("PHISHX_BROWSER")
    if env and os.path.exists(env):
        return env
    try:
        with open(CONFIG) as f:
            p = json.load(f).get("browser")
        if p and os.path.exists(p):
            return p
    except Exception:
        pass
    for c in CANDIDATES:
        p = os.path.expandvars(c)
        if os.path.exists(p):
            return p
    return None


def post(path, url, timeout):
    req = urllib.request.Request(API + path, json.dumps({"url": url}).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def service_up():
    try:
        with urllib.request.urlopen(API + "/health", timeout=1.5):
            return True
    except Exception:
        return False


def start_service():
    """Start the PHISH-X service in the background if it is not running (waits up to ~15 s)."""
    if service_up():
        return True
    server = os.path.join(ROOT, "src", "server.py")
    exe = sys.executable
    if os.name == "nt":
        pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        exe = pyw if os.path.exists(pyw) else exe
    flags = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW
    try:
        subprocess.Popen([exe, server], cwd=os.path.join(ROOT, "src"), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=flags)
    except Exception:
        return False
    for _ in range(30):
        time.sleep(0.5)
        if service_up():
            return True
    return False


def open_in_browser(url):
    b = real_browser()
    if b:
        subprocess.Popen([b, url])
        return True
    return False


def open_popup(url):
    """Small standalone window (Chrome/Edge --app mode) showing the warning page."""
    b = real_browser()
    if not b:
        return False
    page = API + "/guard?u=" + urllib.parse.quote(url, safe="")
    subprocess.Popen([b, "--app=" + page, "--window-size=680,760"])
    return True


def decide(url):
    """Return 'open' or 'warn'. Same policy as the browser extension."""
    r = post("/check", url, 5)
    if r["verdict"] == "PHISHING":
        return "warn"
    if r["verdict"] == "SUSPICIOUS":
        try:
            if post("/sandbox", url, 20)["verdict"] == "PHISHING":
                return "warn"
        except Exception:
            pass          # inspection failed: do not interrupt on a grey-zone score alone
    return "open"


def main(argv):
    url = argv[1].strip() if len(argv) > 1 else ""
    if not url:
        print("Usage: linkguard.py <url>")
        return 2
    if not url.lower().startswith(("http://", "https://")):
        open_in_browser(url)          # mailto:, file:, etc. are none of our business
        return 0
    try:
        if not start_service():
            raise RuntimeError("service not available")
        action = decide(url)
    except Exception:
        action = "open"               # fail open
    if action == "warn":
        try:
            if open_popup(url):
                return 0
        except Exception:
            pass
    open_in_browser(url)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
