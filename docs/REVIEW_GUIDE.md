# PHISH-X: review guide (demo script, numbers, honest Q&A)

**One line:** PHISH-X warns you before you open a phishing link or email, explains why, and can safely open the
page in an isolated sandbox to show what it is trying to steal. It runs in the background on your laptop.

## 1. Before the review (10 minutes, do it the night before)
1. Run `start_demo.bat` (first run trains the models; later runs start in seconds). Keep that window open.
2. The dashboard opens at http://127.0.0.1:8765/. If not, open that address yourself.
3. Load the extension: `chrome://extensions` > Developer mode > Load unpacked > the `extension` folder.
4. Do one full dry run of section 2.

## 2. Five-minute demo
| Step | What you do | What the audience sees |
|---|---|---|
| 1 | Show the dashboard tiles | Measured accuracy: links 86.7%, emails 91.9%, agent 10/10 (small sample) |
| 2 | Click **fake bank link**, **Check link** | Red card, score 100. Reason: "uses 'sbi' to look like SBI; the real domain is sbi.co.in" |
| 3 | Click **Wikipedia**, **Check link** | Green card: no warning signs. Safe links never interrupt you |
| 4 | Click **demo fake bank page**, **Open it in the sandbox** | The **replay plays**: the page asks for username, password, card, CVV, OTP. PHISH-X types FAKE values (highlighted red). The submit is cancelled. The log shows `POST /steal.php  CANCELLED: data never left the sandbox`. Counter: real details used = 0 |
| 5 | Click **demo 3-step kit**, sandbox | Multi-step phishing kit: email, then password, then OTP. Still no real data used |
| 6 | **Check an email** > **Paste a sample phishing email** | Flags: fake sender, reply-to mismatch, urgency/threat wording. Shows what the attacker wants |
| 7 | Paste `http://paypa1-secure-login.top/signin`, **Full investigation** | The agent's reasoning trail: it chooses which checks to run and explains why |
| 8 | In Chrome, open `http://127.0.0.1:9100/fake_phishing_page.html` | The extension shows a warning page BEFORE the page loads, with "Check it in the sandbox" and "always trust" buttons |
| 9 | Scroll to **How well does it work?** | Disguise tests, threshold trade-off, campaigns found (449) |

## 3. What is built
URL model (LR, Random Forest, XGBoost, ensemble) with explanations; brand-impersonation detection; Chrome
extension with warning page; static and dynamic sandbox with visual replay; investigation agent; disguise
(adversarial) testing and training; phishing-campaign clustering; email analyzer (headers, links, wording model);
dashboard; Windows system-wide link guard; hosted-service version (Dockerfile, privacy mode, rate limits).

## 4. Measured numbers (and what they do NOT prove)
| Part | Result | Caveat |
|---|---|---|
| URL model, 40,000 unseen test links | RF 86.7%, XGBoost 85.5%, Ensemble 86.2%, LR 72.0% | Link text only. Papers quoting 97-99% add domain age, WHOIS and page content |
| Separate 20,000-link set | Ensemble 85.5% | Same data source as training |
| At the warning level (70) | Catches 68% of phishing, flags 2.85% of genuine links | Lower level catches more but annoys more (table on dashboard) |
| Lite model (what the hosted service uses) | XGBoost alone, 3 MB, within about 1 point | One model instead of three |
| Disguise tests | Combined disguise slips past 39.1% before training, 15.5% after | Genuine links wrongly flagged rose 2.7% to 6.5% (a trade-off) |
| Investigation agent | 10/10 right, 3.3 checks per link vs 6.0 for a fixed checklist | Only 10 hand-made cases |
| Campaigns | 449 groups of links sharing a page path across many sites | Dataset mixes sources, so some patterns reflect collection |
| Email analyzer | 91.9% accuracy, 87.4% caught, 0.7% genuine flagged on 2,140 unseen emails | Genuine mail is 2002 mailing-list traffic; unseen-collection test caught only 56% of Nazario phishing |

## 5. Questions you may get (honest answers)
**Why is accuracy 86% and not 99%?** The model only reads the link text. Adding page content, domain age and
WHOIS is what lifts published results; our sandbox adds the page-content signal, but we have only tested it on
10 cases, so we do not claim a combined accuracy.

**Why did the ensemble not beat Random Forest?** It was within 0.5 point. We kept it for stability and because
XGBoost gives exact per-link explanations (TreeSHAP).

**Is the sandbox really safe?** It uses a fresh browser with no cookies or logins, fills only made-up data,
cancels every submission, and blocks requests to internal addresses. Known limit: a DNS-rebinding trick could
slip past; real isolation needs a container or VM. Some phishing kits hide from automated browsers.

**How is this different from Google Safe Browsing?** Safe Browsing is a blocklist. PHISH-X also judges brand-new
links, explains why, and shows what the page would steal.

**Does it send my links anywhere?** Not in local mode: everything runs on your laptop. The hosted version
(optional) receives only the link, stores nothing and rate-limits requests.

**Why can it not run on iPhone?** Apple does not let an app intercept links from other apps. Android and
Windows allow it (roadmap).

**What would you do with more time?** Android and Windows apps (Play Store / Microsoft Store), a screenshot
similarity module trained on a phishing-screenshot dataset (e.g. Phish-IRIS), a larger labelled email set with
modern genuine mail, and testing the optional LLM planner for the agent.

## 6. Known limits (say these before you are asked)
- Unknown login pages are capped at "suspicious" (a real login and a clone look the same without more evidence).
- The extension cannot truly block a page; it redirects to a warning and fails open if the service is down.
- Phones are not covered yet. The Windows registry parts of the link guard were not testable on Windows by the author of this package.
- The LLM planner for the agent exists but is untested; the benchmarked agent uses the built-in rule planner.
- Visual (screenshot) similarity is not built.
