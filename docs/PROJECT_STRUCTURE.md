# Project Structure

```text
QuicProbe/
├── quicprobe/                 # Application package
│   ├── cli.py                 # Command-line interface
│   └── core/analyzer.py       # QUIC and security-log analysis logic
├── examples/                  # Safe sample input files
├── reports/                   # Example/generated report files
├── scripts/                   # Windows and Kali/Linux setup and run scripts
├── tests/                     # Automated regression tests
├── docs/                      # Installation and project documentation
├── pyproject.toml             # Package metadata and CLI registration
├── requirements.txt           # Third-party dependency declaration (empty)
├── README.md                  # English documentation
└── README_AR.md               # Arabic documentation
```

QuicProbe uses only Python standard-library modules. No external runtime package is required.
