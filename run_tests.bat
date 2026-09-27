@echo off
rem ProtoForge test runner
cd /d "%~dp0"
set PYTHONUTF8=1
set QT_QPA_PLATFORM=offscreen
python -m pytest tests -q
pause
