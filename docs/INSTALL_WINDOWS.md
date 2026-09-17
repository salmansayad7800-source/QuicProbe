# Windows Installation

## Requirements

- Windows 10 or newer
- Python 3.10 or newer

## Recommended setup

Open PowerShell or Command Prompt in the project folder and run:

```powershell
scripts\setup_windows.bat
```

The script creates `.venv` and checks the project directly. No third-party package is installed.

## Run the tool

```powershell
scripts\run_windows.bat --help
scripts\run_windows.bat info
scripts\run_windows.bat scan examples\sample_quic_log.txt --json
scripts\run_windows.bat log examples\sample_security_log.txt --json
```

## Run tests

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Without installation

```powershell
py -3 -m quicprobe --help
```
