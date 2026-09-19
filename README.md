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
- PCAP packet metadata and TCP/UDP flow analysis
- Statistical indicators for possible exfiltration and periodic C2 behavior
- Standard-library core with optional scikit-learn ML support

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
python -m quicprobe scan https://example.com --json
python -m quicprobe log examples/sample_security_log.txt --json
python -m quicprobe pcap "C:\\Users\\Public\\Captures\\traffic.pcap" --json
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

### Scan website URLs

The `scan` command also accepts `http://` and `https://` URLs. It reads the response
version and `Alt-Svc` header to identify servers advertising HTTP/3 over QUIC, scans
the visible page text, and lists unique external HTTP(S) links. It does not follow
those links automatically.

If the network is unavailable, the tool still inspects the URL locally and reports
its scheme, hostname, port, path, query, and fragment. HTTP/3/QUIC cannot be verified
offline.

```powershell
python -m quicprobe scan "https://example.com" --json
python -m quicprobe scan "https://example.com" --export reports\\beacon.html
```

### Runtime checks and live capture controls

```powershell
python -m quicprobe doctor --json
python -m quicprobe live --list-ifaces
python -m quicprobe live --iface wireless_0 --count 1000 --timeout 30 --json
python -m quicprobe live --iface wireless_0 --count 1000 --timeout 30 --verbose --json
```

The process exits with code `0` when no anomaly is reported and `2` when the report
has medium/high risk or the environment is not ready. Other execution errors return
`1`, which makes the command suitable for scripts and CI/CD.

### Analyze a PCAP or PCAP-NG file

The `pcap` command reads classic PCAP and PCAP-NG files and summarizes IPv4 TCP/UDP flows:

```powershell
python -m quicprobe pcap "C:\\Users\\Public\\Captures\\traffic.pcap" --json
python -m quicprobe pcap "C:\\Users\\Public\\Captures\\traffic.pcap" --export reports\\traffic.json
python -m quicprobe pcap "C:\\Users\\Public\\Captures\\traffic.pcapng" --json
python -m quicprobe pcap "C:\\Users\\Public\\Captures\\traffic.pcapng" --check-amplification --detect-downgrade --track-cid --verbose --json
python -m quicprobe pcap "C:\\Users\\Public\\Captures\\traffic.pcapng" --detect-flood --check-padding --track-migration --inspect-headers
```

The security checks report rapid unanswered QUIC Initial packets, client Initial
packets below the RFC 9000 1200-byte minimum, endpoint changes associated with a CID,
and cleartext Long/Short header fields. These checks operate on visible metadata and
do not decrypt protected packet payloads.

Capture live traffic for ten seconds and analyze it:

```powershell
# Open PowerShell as Administrator on Windows
python -m quicprobe live --duration 10 --output reports\\live_capture.pcap --json
```

On Linux, run the command with the required capture permission, for example:

```bash
sudo python3 -m quicprobe live --duration 10 --interface eth0 --json
```

Live capture requires Administrator/root privileges. On Windows, raw-socket capture
is limited by the operating system and may require selecting a local interface address.

Enable the optional IsolationForest anomaly model:

```powershell
python -m pip install -e ".[ml]"
python -m quicprobe pcap "C:\\Users\\Public\\Captures\\traffic.pcapng" --ml --json
```

Train and reuse a model:

```powershell
python -m quicprobe ml-train "C:\\Users\\Public\\Captures\\clean-1.pcap" "C:\\Users\\Public\\Captures\\clean-2.pcap" --output reports\\quicprobe_model.pkl
python -m quicprobe pcap "C:\\Users\\Public\\Captures\\traffic.pcapng" --ml --ml-model reports\\quicprobe_model.pkl --json
```

You may provide a browser or application TLS key log for availability reporting:

```powershell
python -m quicprobe pcap "C:\\Users\\Public\\Captures\\traffic.pcapng" --keylog "$env:SSLKEYLOGFILE" --json
```

It reports packet counts, payload sizes, directional byte ratios, periodicity, UDP/443
QUIC candidates, and possible exfiltration or periodic C2 indicators. These are
statistical signals for investigation, not proof of malicious activity. Live Raw Socket
capture is available through the `live` command, but QUIC/TLS payload decryption is not
included. A key log is reported but is not currently used to decrypt payloads.

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
This tool is built for defensive analysis and learning purposes. It does not decode
encrypted QUIC traffic. PCAP analysis uses metadata and statistical flow heuristics;
it does not prove exfiltration or C2 activity and does not replace full packet
inspection.

## License
MIT
