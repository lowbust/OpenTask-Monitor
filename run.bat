@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Create the virtual environment first. See README.md.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m opentask
if errorlevel 1 pause
