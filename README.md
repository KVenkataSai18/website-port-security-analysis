# Website Open Port Scanning and Security Analysis

## Overview

A defensive reconnaissance project. An **authorized** target is scanned with Nmap from Kali Linux, the XML output is parsed with Python into CSV/JSON, and each open port is analyzed for its function, benefits, threats and recommended protections.

**Windows** is used for development and GitHub management. **Kali Linux** is used for Nmap scanning and running the analysis scripts.

## Objectives

- Identify open TCP ports and the services behind them
- Explain the function and benefit of each exposed service
- Describe the security threats of each exposure
- Separate *open port*, *service*, *exposure*, *misconfiguration* and *vulnerability*
- Produce a professional, reproducible report on GitHub

## Technologies

Nmap, Python 3 (standard library only), Git/GitHub, VS Code, Kali Linux.

## Architecture

```
Authorized target -> Kali Linux -> Nmap (-sV) -> raw scan (.xml/.nmap)
   -> app.py (Automated Pipeline) OR Modular Scripts:
      - scripts/parse_nmap.py    -> results/scan_results.csv & .json
      - scripts/analyze_ports.py -> results/port_analysis.md
      - scripts/report.py        -> reports/<target>_report.md & results/dashboard.html
   -> Final Presentation & Git/GitHub Repository
```

## Project Structure

```
website-port-security-analysis/
├── README.md
├── LICENSE
├── .gitignore
├── .gitattributes
├── requirements.txt
├── app.py                      # End-to-end pipeline automation
├── BIA_Port_Scanning_Project_Presentation_Final.pptx # Original deck
├── BIA_Port_Scanning_Project_Revised.pptx           # Revised presentation
├── scans/
│   ├── raw/                    # Nmap output (.nmap, .gnmap, .xml)
│   └── screenshots/            # Terminal / evidence screenshots
├── results/
│   ├── scan_results.csv        # Parsed ports (generated)
│   ├── scan_results.json       # Parsed ports (generated)
│   ├── port_analysis.md        # Port analysis breakdown (generated)
│   └── dashboard.html          # Interactive HTML security dashboard (generated)
├── samples/
│   └── sample_nmap.xml         # Mock sample data for parser/pipeline testing only
├── scripts/
│   ├── scanner.py              # URL validation, DNS resolution and Nmap execution
│   ├── parse_nmap.py           # Nmap XML -> CSV/JSON converter
│   ├── analyze_ports.py        # CSV -> port analysis & exposure assessment
│   └── report.py               # Markdown report & HTML dashboard generator
├── tests/
│   ├── test_scanner.py         # Tests for URL validation and host resolution
│   ├── test_parse_nmap.py      # Tests for XML parser and output formats
│   ├── test_analyze_ports.py   # Tests for port database and exposure ratings
│   ├── test_report.py          # Tests for report and dashboard generation
│   └── test_pipeline.py        # End-to-end pipeline integration tests
├── reports/
│   └── security_report.md      # Structured security report
└── docs/
    ├── methodology.md          # Defensive scanning methodology
    └── port_reference.md       # Knowledge base of port functions, benefits and threats
```

## Environment

### Windows Development Environment

Windows 10/11 with Antigravity / VS Code and Git. Used to develop code, run automated tests (`pytest`), inspect artifacts, and manage the repository. No unauthorized live scanning occurs on Windows.

### Kali Execution Environment

Kali Linux VM (VirtualBox/VMware). Used to pull the repository, run authorized Nmap service scans, execute `app.py` or modular analysis scripts, and commit verified results back to GitHub.

## Installation & Dependencies

The core pipeline uses only the **Python standard library** (`xml.etree.ElementTree`, `csv`, `json`, `argparse`, `pathlib`, `socket`, `subprocess`). No third-party packages are required to run scans or generate reports.

For running the automated test suite and PowerPoint validation on Windows:
```powershell
pip install pytest python-pptx
```

## Windows Setup

```powershell
git clone https://github.com/KVenkataSai18/website-port-security-analysis.git
cd website-port-security-analysis
pytest -v
```

## Kali Setup

```bash
git --version && nmap --version && python3 --version   # check tools
sudo apt update && sudo apt install -y git nmap python3  # install if needed
git clone https://github.com/KVenkataSai18/website-port-security-analysis.git
cd website-port-security-analysis
git pull   # fetch latest updates
```

## Execution Workflows

### Option 1: End-to-End Automated Pipeline (Recommended)

Run `app.py` to perform the full automated sequence (validation → DNS resolution → authorization check → Nmap scan → XML parsing → port analysis → Markdown report → interactive HTML dashboard):

```bash
# Interactive prompt:
python3 app.py

# Direct target scan (requires explicit authorization):
python3 app.py --url http://192.168.56.101 --authorized

# Full 65,535 TCP port scan (authorized lab targets only):
python3 app.py --url http://192.168.56.101 --full --authorized

# Offline analysis / Windows testing from an existing XML scan:
python3 app.py --xml scans/raw/target_scan.xml
```

### Option 2: Modular Step-by-Step Execution

#### Step 1: Authorized Nmap Scan (Kali Linux)
```bash
nmap -sV TARGET -oA scans/raw/target_scan
```
*Options:* `-sV` enables service/version detection; `-Pn` skips host ping; `-oA` saves `.nmap`, `.gnmap` and `.xml`.

#### Step 2: Parse XML to CSV & JSON
```bash
python3 scripts/parse_nmap.py scans/raw/target_scan.xml --outdir results
```

#### Step 3: Security & Exposure Analysis
```bash
python3 scripts/analyze_ports.py --input results/scan_results.csv --output results/port_analysis.md
```

#### Step 4: Generate Markdown Report & HTML Dashboard
```bash
python3 scripts/report.py --csv results/scan_results.csv --xml scans/raw/target_scan.xml --output reports/security_report.md --dashboard results/dashboard.html
```

## Security Analysis

```bash
python3 scripts/analyze_ports.py
```

Reads `results/scan_results.csv`, analyzes only **open** ports, and writes `results/port_analysis.md`.

> An open port is not automatically a vulnerability. Further authorized investigation is required before declaring a misconfiguration or vulnerability.

### Testing the scripts with sample data

```bash
python3 scripts/parse_nmap.py samples/sample_nmap.xml --outdir /tmp/sample_test
python3 scripts/analyze_ports.py --input /tmp/sample_test/scan_results.csv --output /tmp/sample_test/port_analysis.md
```

The sample file is fictional (host `192.0.2.10`) and is written to `/tmp` so it never mixes with real results.

## Results

> Results will be added after the authorized scan is completed. See `results/` and `reports/security_report.md`.

## Screenshots

> Add terminal screenshots to `scans/screenshots/` and link them here.

## Report

Full report: [`reports/security_report.md`](reports/security_report.md)
Methodology: [`docs/methodology.md`](docs/methodology.md)
Port reference: [`docs/port_reference.md`](docs/port_reference.md)

## Limitations

- Single scan, single network position, single point in time
- Firewalls can hide or filter services
- Service/version detection is best effort
- TCP only by default
- No vulnerability testing is performed

## Ethical and Legal Disclaimer

Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal. This project performs reconnaissance and analysis only and contains no exploitation, brute-force, evasion or denial-of-service functionality. The author accepts no responsibility for misuse.

## Future Improvements

- UDP scanning of common services
- Comparing scans over time
- TLS configuration review
- Authorized vulnerability scanning with explicit permission

## References

- Nmap Reference Guide: https://nmap.org/book/man.html
- IANA Port Registry: https://www.iana.org/assignments/service-names-port-numbers/
- NIST SP 800-115