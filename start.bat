@echo off
REM Starts PHISH-X (service + dashboard) and opens the dashboard in your browser.
cd /d "%~dp0"
python -m pip install -q -r requirements.txt
python -m playwright install chromium
if not exist models\random_forest.joblib ( cd src & python train.py & cd .. )
REM open the dashboard a few seconds after the service starts
start "" cmd /c "timeout /t 6 >nul & start http://127.0.0.1:8765/"
cd src
python server.py
