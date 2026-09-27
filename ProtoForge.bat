@echo off
rem ProtoForge GUI launcher
cd /d "%~dp0"
set PYTHONUTF8=1
python -m protoforge.app.main_window
if errorlevel 1 pause
