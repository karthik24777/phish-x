@echo off
REM Makes PHISH-X check links you click in WhatsApp, Outlook, Word etc. (Windows).
REM Run start.bat once first so the models are trained.
cd /d "%~dp0"
if not exist models\random_forest.joblib ( echo Run start.bat once first. & pause & exit /b 1 )
python desktop\install_link_handler.py
pause
