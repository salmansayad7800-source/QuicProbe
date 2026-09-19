# Project Structure

```text
QuicProbe/
├── quicprobe/                 # Application package
│   ├── cli.py                 # Command-line interface
│   └── core/analyzer.py       # QUIC, URL, and security-log analysis logic
│   └── core/pcap_analyzer.py  # PCAP/PCAP-NG flow and anomaly analysis
│   └── core/live_capture.py   # Platform raw-socket capture to PCAP
├── examples/                  # Safe sample input files
├── reports/                   # Example/generated report files
├── scripts/                   # Windows and Kali/Linux setup and run scripts
├── tests/                     # Automated regression tests
├── docs/                      # Installation and project documentation
├── pyproject.toml             # Package metadata and CLI registration
├── requirements.txt           # Optional ML dependency
├── README.md                  # English documentation
└── README_AR.md               # Arabic documentation
```

The core uses Python standard-library modules. Optional ML analysis uses scikit-learn;
install it with `python -m pip install -e ".[ml]"`.
