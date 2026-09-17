# Quick Demonstration

Run a QUIC scan:

```bash
python -m quicprobe scan examples/sample_quic_log.txt --json
```

Analyze a security log:

```bash
python -m quicprobe log examples/sample_security_log.txt --json
```

The log result also classifies event types: `failed_login`, `firewall_drop`, `web_attack`, and `port_scan`. Each event keeps its source IP list, and non-login threats affect the final risk level.

External file example on Windows:

```powershell
python -m quicprobe log "C:\Users\Public\Downloads\security.log" --export reports\external.html
```

The original external file remains unchanged.

Analyze multiple paths and export a report:

```bash
python -m quicprobe scan examples/sample_quic_log.txt examples --export reports/demo.html
```

Supported report extensions are `.json`, `.csv`, and `.html`.

The interactive output highlights `LOW`, `MEDIUM`, and `HIGH` risk levels with colors when the terminal supports them. Disable this behavior with:

```bash
python -m quicprobe --no-color scan examples/sample_quic_log.txt
```
