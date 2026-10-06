# Methodology

## 1. Project Objective

Identify which TCP ports are open on an authorized target, identify the services behind them, and analyze the function, benefits and security implications of each exposed service. The project is reconnaissance, service identification and defensive analysis only.

## 2. Scope

**In scope:** TCP port discovery and service/version detection on the single authorized target named in section 4; analysis of the resulting data; defensive recommendations.

**Out of scope:** exploitation, brute force, credential attacks, firewall/IDS/IPS evasion, denial of service, persistence, malware, and any testing of systems not named in section 4.

## 3. Authorization

Only systems that are owned by the author, or for which explicit written permission exists, may be scanned. Where no authorized website is available, a local lab virtual machine on an isolated (host-only or internal) network is used instead.

- Authorization basis: `[ ] Own system  [ ] Lab VM  [ ] Written permission from owner`
- Authorizing party / date: `[TO BE FILLED IN]`

## 4. Target

- Target name: `[TO BE FILLED IN]`
- Target address: `[TO BE FILLED IN]`
- Target type: `[Lab VM / owned website / permitted website]`

## 5. Environment

| Role | System |
|---|---|
| Development | Windows 10/11, VS Code, Git |
| Version control | GitHub |
| Execution | Kali Linux virtual machine (VirtualBox/VMware) |
| Scanner | Nmap (version recorded in the report) |
| Analysis | Python 3 (standard library only) |

Windows is used to write code and documentation and to manage the repository. Kali Linux is used to run Nmap and the Python scripts.

## 6. Tools

Nmap, Python 3, Git, GitHub, VS Code, Kali Linux.

## 7. Nmap Methodology

Scanning is performed progressively, starting with the least intrusive step and only widening when justified:

1. `nmap TARGET` - default scan of the 1,000 most common TCP ports.
2. `nmap -sV TARGET -oA scans/raw/NAME` - adds service and version detection, and saves all output formats.
3. `nmap -p- -sV TARGET -oA scans/raw/NAME_full` - optional full 65,535-port TCP scan, used only on an authorized lab target or with explicit permission, because it generates more traffic and takes longer.

No timing, evasion, or intrusive script options are used.

## 8. Result Collection

Nmap's `-oA` option writes three files per scan into `scans/raw/`: `.nmap` (human-readable), `.gnmap` (grepable) and `.xml` (structured). The XML file is the input for automated processing. Screenshots of terminal output are stored in `scans/screenshots/` as evidence.

## 9. XML Parsing

`scripts/parse_nmap.py` reads the Nmap XML with Python's standard `xml.etree.ElementTree` module and extracts IP address, hostname, port, protocol, state, service, product and version into `results/scan_results.csv` and `results/scan_results.json`. The script performs no scanning.

## 10. Security Analysis

`scripts/analyze_ports.py` reads the CSV, keeps only ports in the `open` state, and matches each against a built-in port reference. For each open port it records function, legitimate use, potential threats, considerations and defensive measures, and writes `results/port_analysis.md`.

The analysis separates five concepts:

| Term | Meaning | Established by this project? |
|---|---|---|
| Open port | A service is listening | Yes (Nmap) |
| Service | Software behind the port | Yes (Nmap `-sV`, best effort) |
| Exposure | Who can reach it | Partly (depends on scan vantage point) |
| Misconfiguration | Insecure settings | No (needs authorized review) |
| Vulnerability | Confirmed exploitable flaw | No (needs authorized testing) |

## 11. Risk Classification

Ports receive a **preliminary exposure rating** based on the port's typical risk if reachable from untrusted networks:

| Rating | Meaning | Typical examples |
|---|---|---|
| Low | Expected and generally encrypted public service | 443 |
| Medium | Often legitimate, needs hardening and review | 22, 80, 25, 53, 8080 |
| High | Should rarely be publicly reachable | 21, 23, 445, 3306, 3389, 5432 |
| Unknown | Not in the reference; needs manual identification | uncommon ports |

These are exposure indicators, **not vulnerability severities**. The final report may adjust ratings using context about the target (for example, a database port on an isolated lab network).

## 12. Reporting

Findings are written in `reports/security_report.md`, using only data from real scans. Sample data in `samples/` exists solely for testing the scripts and never appears in findings.

## 13. Limitations

- Results reflect one scan, from one network position, at one point in time.
- Firewalls may cause ports to appear filtered or hide services.
- Service/version detection is best effort and can be inaccurate.
- Only TCP is covered unless UDP scanning is explicitly added.
- No vulnerability testing is performed; open ports cannot be declared vulnerable from this data alone.
- Risk ratings are generalized and do not replace a full security assessment.