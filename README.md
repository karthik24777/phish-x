# PHISH-X — AI-Powered Phishing Detection, Investigation & Defense

Runs locally. A browser extension warns before you open a risky link; a local service (127.0.0.1:8765)
does the analysis; a dashboard at http://127.0.0.1:8765/ shows results.

## Start
`./start.sh` (Linux/Mac) or `start.bat` (Windows). First run trains the models (a few minutes) and installs
Chromium for the sandbox. Then load `extension/` in Chrome: chrome://extensions -> Developer mode -> Load unpacked.
Dataset: `data/raw_urls.csv` (labelled good/bad URLs).

## Run like an app (Windows)
- `start.bat` starts everything and opens the dashboard.
- `install_autostart.bat` (run once, after start.bat has trained the models) makes the service start silently at every login, so the extension always has protection. `uninstall_autostart.bat` reverses it.
- The autostart scripts were written for Windows but could not be tested on Windows by the author of this package.

## System-wide link guard (links clicked in WhatsApp, Outlook, Word, etc.)
Windows sends every link clicked in another app to the default browser. `install_link_handler.bat` registers
PHISH-X Link Guard as a browser; set it as default once (Settings > Apps > Default apps). Then:
- safe link: opens straight away in your real browser (no popup);
- dangerous link: a small popup window shows the verdict, reasons, "Check it in the sandbox" and "Open anyway";
- if anything fails (service cannot start etc.) it fails OPEN and just opens the link.
`uninstall_link_handler.bat` removes it. Tested: decision logic, popup page, fail-open (with a stub browser on Linux).
NOT tested: the Windows registry registration and Windows' own default-app prompt (no Windows machine available).
Phones (WhatsApp on Android/iOS) cannot be covered this way: that needs a native mobile app, which is not built.
If you use both the extension and this guard, a link can be checked twice. Pick one for daily use.

## Sandbox replay
Press "Open it in the sandbox" (dashboard or popup) to watch what PHISH-X did: screenshots of the page, the fake
data typed in (highlighted), the submission cancelled, the destination, and every network request.

## Review demo
`start_demo.bat` (Windows) or `./start_demo.sh` starts the dashboard plus two harmless local demo phishing pages so the
sandbox replay can be shown. Full demo script, numbers and Q&A: `docs/REVIEW_GUIDE.md`.

## Hosted (optional) and roadmap
`Dockerfile` / `render.yaml` run a lite (XGBoost-only), privacy-mode copy of the service online
(no links stored, rate-limited, static sandbox only). Planned next: Android app (registers as a browser so links in
WhatsApp are checked first) and a Windows installer, then store listings.

## Modules
| Module | File(s) | What it does |
|---|---|---|
| Detection engine | features.py, train.py, ensemble.py, predict.py | 22 URL features; LR / Random Forest / XGBoost / voting ensemble; SHAP explanations |
| Brand protection | brands.py | Trusted official domains; catches look-alike domains (homoglyphs, brand in subdomain) |
| Warning extension | extension/ | Checks each navigation; shows a warning page; offers "inspect in sandbox"; "always trust this site" button (two-click confirm, exact host, removable in the popup; not offered for brand look-alikes) |
| Sandbox (static) | sandbox.py | Fetches the page on the server, parses forms, no scripts run |
| Sandbox (dynamic) | sandbox_dynamic.py | Isolated headless Chromium, fills SYNTHETIC data, cancels every submission, reports what the page asks for and the likely attacker objective |
| Investigation agent | agent.py, benchmark_agent.py | Chooses which tools to run per link (URL, DNS, redirects, TLS, static, dynamic) and explains its reasoning |
| Adversarial testing | robustness.py | Disguises phishing URLs and measures evasion before/after adversarial training |
| Campaign clustering | campaigns.py | Groups phishing URLs by shared page path across domains; graph in reports/ |
| Email analyzer | email_analyzer.py, tools/train_email_model.py | Headers (spoofing, SPF/DKIM/DMARC), link mismatches, rule lexicon + trained wording model (TF-IDF + logistic regression), risky attachments |
| Dashboard | dashboard.html, server.py | Counters, recent checks, model/threshold/evasion/agent/campaign tables, analyse box |

Tests: `python tests/test_core.py`, `tests/test_dynamic.py`, `tests/test_email.py`.

## Measured results (see reports/)
- URL model, held-out test: Random Forest 86.7%, XGBoost 85.5%, Ensemble 86.2% accuracy; LR 72.0%.
  The ensemble did NOT beat Random Forest alone.
- At the warning threshold (70): 68% of phishing caught, 2.85% of genuine links flagged.
- Adversarial training cuts evasion (e.g. combined disguise 39.1% -> 15.5%) but raises false alarms (2.7% -> 6.5%).
- Agent vs fixed pipeline: both 10/10 correct on 10 cases; agent 3.3 vs 6.0 tool calls on average.

## Honest limits
- URL-only detection has a ceiling (~86% here); the dataset mixes sources, so some patterns reflect collection bias.
- The extension cannot truly block navigation (Chrome MV3); it redirects to a warning page and fails open if the service is down.
- Sandbox: DNS-rebinding race exists; real isolation needs a container/VM. Some kits hide from headless browsers.
- An ordinary unknown login page is capped at SUSPICIOUS (cannot be told apart from a clone by the page alone).
- The optional LLM planner in agent.py is untested; the default rule-based planner is what was benchmarked.
- Email analyzer, measured on 2,140 emails it never trained on (Nazario phishing, Nigerian-fraud scams, SpamAssassin ham+spam; text only, so no header checks):
  at score >= 40 it catches 87.4% of phishing/scam/spam and wrongly flags 0.7% of legitimate mail (accuracy 91.9%); at >= 70 only 14.4% (text alone rarely reaches 70).
  CAUTION: the "legitimate" mail is 2002 technical mailing-list traffic, so the false-alarm rate on modern bank/receipt/college mail is NOT measured;
  a leave-one-collection-out test caught only 56% of Nazario phishing when it was never seen in training. Treat these as optimistic.
  Reproduce: `python tools/eval_emails_heldout.py Nazario.csv Nigerian_Fraud.csv SpamAssasin.csv` (datasets from Kaggle "Phishing Email Dataset"; not shipped).
- Not built: screenshot / visual-similarity (computer vision) module; phone app (extension is desktop Chrome only).
