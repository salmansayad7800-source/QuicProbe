# Kali Linux Installation

## Requirements

- Kali Linux with Python 3.10 or newer
- `python3-venv` available

If the virtual-environment module is missing:

```bash
sudo apt update
sudo apt install -y python3-venv
```

## Recommended setup

From the project folder:

```bash
chmod +x scripts/setup_kali.sh scripts/run_kali.sh
./scripts/setup_kali.sh
```

## Run the tool

```bash
./scripts/run_kali.sh --help
./scripts/run_kali.sh info
./scripts/run_kali.sh scan examples/sample_quic_log.txt --json
./scripts/run_kali.sh log examples/sample_security_log.txt --json
```

## Run tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Without installation

```bash
python3 -m quicprobe --help
```
