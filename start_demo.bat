@echo off
REM Review demo mode: starts the two demo phishing pages AND the PHISH-X service, then opens the dashboard.
REM The demo pages are fake and harmless. They only run on your own computer (127.0.0.1).
cd /d "%~dp0"
python -m pip install -q -r requirements.txt
python -m playwright install chromium
if not exist models\random_forest.joblib ( cd src & python train.py & cd .. )
start "PHISH-X demo pages" /min cmd /c "cd /d %~dp0demo && python -m http.server 9100"
set PHISHX_ALLOW_LOCAL=1
start "" cmd /c "timeout /t 7 >nul & start http://127.0.0.1:8765/"
cd src
python server.py
