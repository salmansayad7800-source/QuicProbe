@echo off
setlocal
cd /d "%~dp0.."

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m quicprobe %*
) else (
    py -3 -m quicprobe %*
)

set EXIT_CODE=%errorlevel%
endlocal & exit /b %EXIT_CODE%
