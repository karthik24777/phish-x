@echo off
REM Makes PHISH-X start silently in the background every time you log in to Windows.
REM Run start.bat once first, so the models are trained.
if not exist "%~dp0models\random_forest.joblib" (
  echo Models not found. Run start.bat once first, then run this again.
  pause & exit /b 1
)
set "T=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\PHISH-X.vbs"
> "%T%" echo CreateObject("WScript.Shell").Run """%~dp0run_background.vbs""", 0, False
echo Done. PHISH-X will now start silently when you log in.
echo To start it right now without restarting, double-click run_background.vbs
pause
