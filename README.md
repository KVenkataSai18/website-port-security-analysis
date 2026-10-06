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
Authorized target -> Kali Linux -> Nmap -> raw results (.nmap/.gnmap/.xml)
   -> parse_nmap.py -> CSV / JSON -> analyze_ports.py -> port_analysis.md
   -> security_report.md -> GitHub
```

## Project Structure

```
website-port-security-analysis/
├── README.md
├── LICENSE
├── .gitignore
├── .gitattributes
├── requirements.txt
├── scans/
│   ├── raw/                # Nmap output (.nmap, .gnmap, .xml)
│   └── screenshots/        # Evidence screenshots
├── results/
│   ├── scan_results.csv    # Parsed ports (generated)
│   ├── scan_results.json   # Parsed ports (generated)
│   └── port_analysis.md    # Security analysis (generated)
├── samples/
│   └── sample_nmap.xml     # SAMPLE DATA for testing only - not a real scan
├── scripts/
│   ├── parse_nmap.py       # Nmap XML -> CSV/JSON
│   └── analyze_ports.py    # CSV -> security analysis
├── reports/
│   └── security_report.md  # Final report
└── docs/
    ├── methodology.md
    └── port_reference.md
```

## Environment

### Windows Development Environment

Windows 10/11 with VS Code and Git. Used to write code and documentation, commit, and push to GitHub. No scanning happens here.

### Kali Execution Environment

Kali Linux VM (VirtualBox/VMware). Used to pull the repository, run Nmap, run the Python scripts, and push results back.

## Installation

Python 3.8+ and the standard library are all the scripts need. There is nothing to `pip install`.

## Windows Setup

```powershell
git clone https://github.com/YOUR_USERNAME/website-port-security-analysis.git
cd website-port-security-analysis
code .
```

Commit and push changes with `git add .`, `git commit -m "message"`, `git push`.

## Kali Setup

```bash
git --version && nmap --version && python3 --version   # check tools
sudo apt update && sudo apt install -y git nmap python3  # only if something is missing
git clone https://github.com/YOUR_USERNAME/website-port-security-analysis.git
cd website-port-security-analysis
git pull   # later, to fetch new changes from Windows
```

## Nmap Scanning

Run only against a target you own or have written permission to test (for example a lab VM on a host-only network).

```bash
nmap TARGET                                         # default scan, 1000 common ports
nmap -sV TARGET -oA scans/raw/target_scan           # service detection + save all formats
nmap -p- -sV TARGET -oA scans/raw/target_full_scan  # optional full TCP scan, authorized lab only
```

`-sV` detects service versions, `-p-` scans all 65,535 TCP ports, `-oA` writes `.nmap`, `.gnmap` and `.xml` files.

## Processing Results

```bash
python3 scripts/parse_nmap.py scans/raw/target_scan.xml
```

Creates `results/scan_results.csv` and `results/scan_results.json`.

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