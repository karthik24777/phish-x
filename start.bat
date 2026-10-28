@echo off
REM Starts the PHISH-X protection service + dashboard on http://127.0.0.1:8765
cd /d "%~dp0"
python -m pip install -q -r requirements.txt
python -m playwright install chromium
if not exist models\random_forest.joblib ( cd src & python train.py & cd .. )
cd src
python server.py
