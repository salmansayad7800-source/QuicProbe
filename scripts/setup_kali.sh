#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3.10 or newer is required."
    exit 1
fi

if [ ! -x ".venv/bin/python" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

. .venv/bin/activate
python -m quicprobe info

echo
echo "Setup complete. Use: ./scripts/run_kali.sh --help"
