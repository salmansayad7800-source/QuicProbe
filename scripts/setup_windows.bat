@echo off
setlocal
cd /d "%~dp0.."

where py >nul 2>&1
if errorlevel 1 (
    echo Python 3.10 or newer is required.
    echo Install Python from https://www.python.org/downloads/windows/
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 exit /b 1
)

call ".venv\Scripts\activate.bat"
python -m quicprobe info
echo.
echo Setup complete. Use scripts\run_windows.bat --help
endlocal
