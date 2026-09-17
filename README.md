# QuicProbe

QuicProbe is a Pure Python cybersecurity utility designed to inspect QUIC/HTTP3 indicators and detect suspicious login activity from security logs.

## Overview
This project was built as a lightweight and practical security analysis tool using only Python standard libraries. It is intended for educational, defensive, and research use in network and log analysis workflows.

## Features
- QUIC and HTTP/3 indicator scanning
- Security log analysis for repeated failed login attempts
- Suspicious IP detection based on repeated failure patterns
- Security event classification for failed logins, firewall drops, web attacks, and port scans
- Per-event source IP lists and event-aware risk scoring
- Additional QUIC ecosystem markers including ALPN, HTTP/3, TLS, 0-RTT, and transport parameters
- CLI interface for quick usage in terminal environments
- Color-coded risk levels in interactive CLI output
- Multi-path scan statistics: files scanned, QUIC files, and aggregate score
- Responsive HTML dashboard with risk-colored summary metrics
- Pure Python implementation with no third-party dependencies

## Project structure
- `quicprobe/` — main package
- `quicprobe/cli.py` — command-line entry point
- `quicprobe/core/analyzer.py` — detection logic
- `examples/` — safe sample input files
- `reports/` — generated and demonstration reports
- `scripts/` — Windows and Kali/Linux setup and run scripts
- `docs/` — installation and project documentation
- `tests/` — automated tests
- `pyproject.toml` — package metadata and CLI registration

## Installation

### Windows

Requirements: Windows 10+ and Python 3.10+.

```powershell
scripts\setup_windows.bat
scripts\run_windows.bat --help
```

### Kali Linux

Requirements: Python 3.10+ and the `python3-venv` package.

```bash
chmod +x scripts/setup_kali.sh scripts/run_kali.sh
./scripts/setup_kali.sh
./scripts/run_kali.sh --help
```

The setup scripts create a local `.venv` and run the package directly from the project folder. Internet access is not required because the tool uses only the Python standard library.

Or run directly from the project folder:

```bash
python -m quicprobe --help
```

## Usage

```bash
python -m quicprobe --help
python -m quicprobe --version
python -m quicprobe info
python -m quicprobe scan examples/sample_quic_log.txt --json
python -m quicprobe log examples/sample_security_log.txt --json
python -m quicprobe scan examples/sample_quic_log.txt examples --export reports/demo.html
python -m quicprobe --no-color scan examples/sample_quic_log.txt
```

Use `--no-color` when output is redirected to a file or when the terminal does not support ANSI colors.

### Scan external files

QuicProbe accepts absolute paths outside the project directory. Examples:

```powershell
python -m quicprobe scan "C:\Users\Public\Downloads\traffic.log" --json
python -m quicprobe log "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" --export reports\external.html
```

On Kali/Linux:

```bash
python3 -m quicprobe log /var/log/auth.log --json
python3 -m quicprobe scan /media/usb/security-logs --export reports/external.html
```

Directories are scanned recursively. The tool reads files as text and does not modify or delete the original external files.

For system-specific commands, see [`docs/INSTALL_WINDOWS.md`](docs/INSTALL_WINDOWS.md) and [`docs/INSTALL_KALI.md`](docs/INSTALL_KALI.md).

## Example output

### QUIC scan

```json
{
  "path": "C:\\Users\\example\\sample_quic_log.txt",
  "is_quic_likely": true,
  "score": 9,
  "markers_found": ["QUIC", "HTTP/3", "Connection ID", "UDP"],
  "summary": "QUIC-like indicators detected."
}
```

### Security log analysis

```json
{
  "failed_login_attempts": 6,
  "suspicious_ips": ["10.0.0.7", "10.0.0.5"],
  "high_risk": true,
  "summary": "Repeated failed login attempts detected."
}
```

## Important note
This tool is built for defensive analysis and learning purposes. It does not decode encrypted QUIC traffic or perform full packet-level deep inspection without additional context or capture data.

## License
MIT
