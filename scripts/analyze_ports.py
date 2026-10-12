#!/usr/bin/env python3
"""
analyze_ports.py - Security analysis of OPEN ports from scan_results.csv.

This script does NOT scan anything. It reads the CSV produced by
parse_nmap.py, keeps only ports whose state is "open", and describes each
one using a built-in port reference.

IMPORTANT: An open port is NOT automatically a vulnerability.
  OPEN PORT        - something is listening (what Nmap observed)
  SERVICE          - the software behind the port (what -sV identified)
  EXPOSURE         - who can reach it (needs network context)
  MISCONFIGURATION - insecure settings (needs authorized review)
  VULNERABILITY    - a confirmed, exploitable flaw (needs authorized testing)
Nmap service detection alone can only establish the first two.

Usage:
    python3 scripts/analyze_ports.py
    python3 scripts/analyze_ports.py --input results/scan_results.csv --output results/port_analysis.md
"""

import argparse
import csv
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Port reference.  exposure = preliminary rating of how much attention the
# port deserves IF it is reachable from untrusted networks. It is NOT a
# vulnerability rating.
# ---------------------------------------------------------------------------
PORT_DB = {
    21: {
        "name": "FTP", "exposure": "High",
        "function": "File Transfer Protocol: transfers files between client and server.",
        "benefit": "Simple, widely supported file exchange and legacy system integration.",
        "threats": ["Credentials and data sent in clear text (sniffing)",
                    "Anonymous login left enabled", "Brute-force attempts against accounts",
                    "Outdated server software with known flaws"],
        "considerations": "Plain FTP has no encryption. Check whether anonymous access is allowed (requires authorized review).",
        "defenses": ["Replace with SFTP or FTPS", "Disable anonymous login",
                     "Restrict access by IP / firewall", "Keep the FTP server patched"],
    },
    22: {
        "name": "SSH", "exposure": "Medium",
        "function": "Secure Shell: encrypted remote login, command execution and file transfer.",
        "benefit": "Secure remote administration with strong encryption and key-based authentication.",
        "threats": ["Brute-force / password guessing", "Weak or default credentials",
                    "Outdated SSH versions with known flaws", "Stolen or unprotected private keys"],
        "considerations": "Generally appropriate for administration, but should not be open to the whole internet without hardening.",
        "defenses": ["Use key-based authentication, disable password login", "Disable direct root login",
                     "Restrict source IPs or use a VPN/bastion host", "Use fail2ban or rate limiting", "Patch OpenSSH"],
    },
    23: {
        "name": "Telnet", "exposure": "High",
        "function": "Unencrypted remote terminal access.",
        "benefit": "Largely obsolete; occasionally used for legacy network devices.",
        "threats": ["All traffic including passwords in clear text", "Session hijacking",
                    "Frequent target for automated credential attacks"],
        "considerations": "Telnet should rarely be exposed. Its presence usually indicates a legacy or unmanaged device.",
        "defenses": ["Disable Telnet and use SSH", "Block port 23 at the firewall",
                     "Isolate legacy devices that cannot be upgraded"],
    },
    25: {
        "name": "SMTP", "exposure": "Medium",
        "function": "Simple Mail Transfer Protocol: sends and relays email between servers.",
        "benefit": "Required for email delivery from a mail server.",
        "threats": ["Open relay abused for spam", "User enumeration", "Phishing/spoofing via weak SPF/DKIM/DMARC",
                    "Cleartext mail transfer without TLS"],
        "considerations": "A web-only server normally does not need public SMTP. Verify relay settings during authorized review.",
        "defenses": ["Disable open relay", "Require STARTTLS", "Configure SPF, DKIM and DMARC",
                     "Close the port if no mail service is intended"],
    },
    53: {
        "name": "DNS", "exposure": "Medium",
        "function": "Domain Name System: resolves domain names to IP addresses.",
        "benefit": "Essential for name resolution on authoritative or recursive DNS servers.",
        "threats": ["DNS amplification (DDoS reflection) via open resolvers", "Zone transfer information leakage",
                    "Cache poisoning on unpatched resolvers"],
        "considerations": "Check whether the server is an open recursive resolver or permits zone transfers (authorized review).",
        "defenses": ["Disable recursion for external clients", "Restrict zone transfers (AXFR) to secondary servers",
                     "Patch DNS software", "Consider DNSSEC"],
    },
    80: {
        "name": "HTTP", "exposure": "Medium",
        "function": "Hypertext Transfer Protocol: serves web pages without encryption.",
        "benefit": "Delivers web content; commonly used to redirect visitors to HTTPS.",
        "threats": ["Traffic can be read or modified in transit", "Web application flaws (XSS, SQL injection, etc.)",
                    "Information leakage via server banners or default pages", "Outdated web server software"],
        "considerations": "Expected on a web server. Best practice is to redirect all traffic to HTTPS.",
        "defenses": ["Redirect HTTP to HTTPS and enable HSTS", "Hide version banners", "Patch web server and application",
                     "Use a web application firewall (WAF) where appropriate"],
    },
    110: {
        "name": "POP3", "exposure": "Medium",
        "function": "Post Office Protocol v3: downloads email from a mail server.",
        "benefit": "Simple mailbox retrieval for legacy email clients.",
        "threats": ["Clear-text credentials when TLS is not used", "Brute-force login attempts"],
        "considerations": "Prefer the encrypted variant (POP3S, port 995).",
        "defenses": ["Use POP3S (995) or enforce STARTTLS", "Disable if not needed", "Enforce strong passwords / MFA"],
    },
    143: {
        "name": "IMAP", "exposure": "Medium",
        "function": "Internet Message Access Protocol: accesses and manages email on the server.",
        "benefit": "Lets users sync mail across multiple devices.",
        "threats": ["Clear-text credentials when TLS is not used", "Brute-force login attempts"],
        "considerations": "Prefer the encrypted variant (IMAPS, port 993).",
        "defenses": ["Use IMAPS (993) or enforce STARTTLS", "Disable if not needed", "Enforce strong passwords / MFA"],
    },
    443: {
        "name": "HTTPS", "exposure": "Low",
        "function": "HTTP over TLS: serves web content over an encrypted connection.",
        "benefit": "Confidentiality, integrity and server authentication for web traffic.",
        "threats": ["Weak TLS versions or ciphers", "Expired or misconfigured certificates",
                    "Web application flaws still apply (encryption does not fix them)", "Outdated web server software"],
        "considerations": "Expected and desirable on a website. Review TLS configuration and certificate validity.",
        "defenses": ["Enable only TLS 1.2/1.3", "Keep certificates valid and renewed", "Enable HSTS",
                     "Patch the web server and application"],
    },
    445: {
        "name": "SMB", "exposure": "High",
        "function": "Server Message Block: Windows file and printer sharing.",
        "benefit": "File sharing inside trusted internal networks.",
        "threats": ["Wormable remote code execution flaws in unpatched systems (e.g. EternalBlue / MS17-010)",
                    "Anonymous or weak-credential share access", "Ransomware spread",
                    "Information disclosure"],
        "considerations": "SMB should not be exposed to the internet. Exposure indicates a serious network design concern.",
        "defenses": ["Block 445 at the perimeter firewall", "Disable SMBv1", "Apply Windows security updates",
                     "Require authentication and disable null sessions"],
    },
    3306: {
        "name": "MySQL", "exposure": "High",
        "function": "MySQL/MariaDB database server.",
        "benefit": "Stores application data for websites and services.",
        "threats": ["Brute-force or default credentials", "Direct data exposure if accounts are weak",
                    "Unpatched database server flaws"],
        "considerations": "Databases should normally listen only on localhost or a private network, not the internet.",
        "defenses": ["Bind to 127.0.0.1 or an internal interface", "Firewall the port", "Use least-privilege accounts and strong passwords",
                     "Patch the database server"],
    },
    3389: {
        "name": "RDP", "exposure": "High",
        "function": "Remote Desktop Protocol: graphical remote access to Windows systems.",
        "benefit": "Convenient remote administration of Windows machines.",
        "threats": ["Brute-force attacks", "Credential theft", "Past critical flaws (e.g. BlueKeep)",
                    "A common entry point for ransomware"],
        "considerations": "RDP should not be directly exposed to the internet.",
        "defenses": ["Place behind a VPN or gateway", "Enable Network Level Authentication (NLA)", "Enforce MFA and account lockout",
                     "Restrict by IP and patch regularly"],
    },
    5432: {
        "name": "PostgreSQL", "exposure": "High",
        "function": "PostgreSQL database server.",
        "benefit": "Stores application data for websites and services.",
        "threats": ["Brute-force or default credentials", "Overly permissive pg_hba.conf rules",
                    "Unpatched database server flaws"],
        "considerations": "Databases should normally listen only on localhost or a private network.",
        "defenses": ["Limit listen_addresses and pg_hba.conf rules", "Firewall the port", "Use strong passwords and least privilege",
                     "Patch PostgreSQL"],
    },
    8080: {
        "name": "HTTP alternate", "exposure": "Medium",
        "function": "Alternate HTTP port, often used for proxies, application servers or admin panels.",
        "benefit": "Runs a second web service or a development/application server beside the main site.",
        "threats": ["Forgotten test or admin interfaces", "Default credentials on management consoles",
                    "Unencrypted traffic", "Unpatched application servers (e.g. Tomcat, Jenkins)"],
        "considerations": "Identify exactly what is running here; non-standard web ports are often unintended exposure.",
        "defenses": ["Close the port if not needed", "Require authentication and HTTPS", "Restrict to internal networks",
                     "Patch the application server"],
    },
    # Extra common ports that frequently appear in results
    139: {
        "name": "NetBIOS Session", "exposure": "High",
        "function": "NetBIOS session service used by older Windows file sharing.",
        "benefit": "Legacy Windows network file/printer sharing.",
        "threats": ["Information disclosure", "Null-session enumeration", "Legacy SMB flaws"],
        "considerations": "Should not be reachable from untrusted networks.",
        "defenses": ["Block at the firewall", "Disable NetBIOS over TCP/IP if unused"],
    },
    993: {
        "name": "IMAPS", "exposure": "Low",
        "function": "IMAP over TLS: encrypted email access.",
        "benefit": "Secure mailbox access for email clients.",
        "threats": ["Brute-force login attempts", "Weak TLS configuration"],
        "considerations": "Appropriate on a mail server; review TLS and authentication settings.",
        "defenses": ["Enforce strong passwords / MFA", "Use modern TLS only", "Rate-limit failed logins"],
    },
    995: {
        "name": "POP3S", "exposure": "Low",
        "function": "POP3 over TLS: encrypted email retrieval.",
        "benefit": "Secure mailbox download for email clients.",
        "threats": ["Brute-force login attempts", "Weak TLS configuration"],
        "considerations": "Appropriate on a mail server; review TLS and authentication settings.",
        "defenses": ["Enforce strong passwords / MFA", "Use modern TLS only", "Rate-limit failed logins"],
    },
    8443: {
        "name": "HTTPS alternate", "exposure": "Medium",
        "function": "Alternate HTTPS port, often used for admin consoles and application servers.",
        "benefit": "Encrypted access to a secondary web service or management interface.",
        "threats": ["Exposed admin panels", "Default credentials", "Weak TLS configuration", "Unpatched application servers"],
        "considerations": "Identify what is running here and whether it needs to be public.",
        "defenses": ["Restrict admin interfaces to internal networks/VPN", "Use strong authentication", "Patch the application"],
    },
    20: {
        "name": "FTP-Data", "exposure": "High",
        "function": "File Transfer Protocol data transfer channel.",
        "benefit": "Used in active-mode FTP file transfers.",
        "threats": ["Cleartext data transfer", "Unintended data exposure"],
        "considerations": "Active FTP requires inbound connections to port 20; prefer passive FTPS/SFTP.",
        "defenses": ["Migrate to SFTP or FTPS", "Block inbound port 20 at firewall"],
    },
    88: {
        "name": "Kerberos", "exposure": "High",
        "function": "Kerberos network authentication protocol.",
        "benefit": "Centralized, ticket-based identity and authentication services in enterprise environments.",
        "threats": ["AS-REP roasting", "Kerberoasting", "Credential brute-forcing"],
        "considerations": "Authentication services belong strictly on internal corporate networks.",
        "defenses": ["Isolate to internal domain networks", "Enforce strong password policies", "Monitor ticket requests"],
    },
    111: {
        "name": "RPCBind", "exposure": "High",
        "function": "RPCBind / Portmapper: maps RPC service numbers to network ports.",
        "benefit": "Legacy Unix service discovery (e.g. NFS, NIS).",
        "threats": ["Service enumeration", "DDoS amplification reflection", "Past remote code execution flaws"],
        "considerations": "Should never be exposed to the public internet.",
        "defenses": ["Block port 111 at perimeter firewall", "Disable RPC services if unused"],
    },
    161: {
        "name": "SNMP", "exposure": "High",
        "function": "Simple Network Management Protocol: device monitoring and management.",
        "benefit": "Remote hardware, operating system and network monitoring.",
        "threats": ["Default community strings ('public'/'private')", "Information disclosure (network topologies, users)", "Configuration tampering via SNMP write"],
        "considerations": "SNMP should never be public. SNMPv1/v2c send community strings in plaintext.",
        "defenses": ["Use SNMPv3 with encryption and authentication", "Restrict to management network", "Block at external perimeter"],
    },
    389: {
        "name": "LDAP", "exposure": "High",
        "function": "Lightweight Directory Access Protocol: directory query and management.",
        "benefit": "Centralized directory and address book lookups.",
        "threats": ["Cleartext credential transmission without StartTLS", "Anonymous directory binding / enumeration", "LDAP injection"],
        "considerations": "Directory services should reside in internal networks; use LDAPS (636) or StartTLS.",
        "defenses": ["Disable anonymous bind", "Enforce LDAPS/StartTLS", "Isolate behind firewall / VPN"],
    },
    636: {
        "name": "LDAPS", "exposure": "Medium",
        "function": "Lightweight Directory Access Protocol over TLS.",
        "benefit": "Secure, encrypted directory queries and authentication.",
        "threats": ["Brute-force authentication", "Account enumeration if unauthenticated lookups are enabled"],
        "considerations": "Should be accessible only to authenticated internal systems or via VPN.",
        "defenses": ["Restrict access by IP", "Enforce certificate validation", "Keep directory software patched"],
    },
    2049: {
        "name": "NFS", "exposure": "High",
        "function": "Network File System: network file sharing protocol.",
        "benefit": "Seamless network file sharing between Unix/Linux systems.",
        "threats": ["Unrestricted share mounting", "Information disclosure", "Past remote code execution flaws"],
        "considerations": "NFS is intended strictly for local trusted subnets.",
        "defenses": ["Block port 2049 at perimeter firewall", "Export shares only to explicit authorized IPs", "Use NFSv4 with Kerberos"],
    },
    6379: {
        "name": "Redis", "exposure": "High",
        "function": "Redis in-memory key-value data store and cache.",
        "benefit": "High-performance session caching and real-time data storage.",
        "threats": ["Default configuration without authentication", "Direct remote code execution via file write / SSH key injection", "Data extraction"],
        "considerations": "Redis should bind only to 127.0.0.1 or a protected internal subnet.",
        "defenses": ["Bind to localhost only", "Require strong AUTH password", "Enable protected-mode", "Firewall port 6379"],
    },
    8000: {
        "name": "HTTP alternate", "exposure": "Medium",
        "function": "Common alternate HTTP port (often development servers, APIs, or proxy services).",
        "benefit": "Secondary web service, development sandbox, or backend API endpoint.",
        "threats": ["Exposed development/debugging interfaces", "Unpatched application servers", "Cleartext web traffic"],
        "considerations": "Verify whether this service is meant for production exposure.",
        "defenses": ["Restrict access to authorized clients", "Enforce HTTPS", "Keep server and frameworks updated"],
    },
    8081: {
        "name": "HTTP alternate", "exposure": "Medium",
        "function": "Alternate HTTP port for proxies, management interfaces, or secondary web services.",
        "benefit": "Runs secondary web applications alongside primary web ports.",
        "threats": ["Unintended administrative console exposure", "Unencrypted communication", "Default credentials"],
        "considerations": "Ensure administrative interfaces are not accessible without authentication.",
        "defenses": ["Place behind authentication and TLS", "Restrict by IP or VPN", "Disable if unused"],
    },
    8888: {
        "name": "HTTP alternate", "exposure": "Medium",
        "function": "Common alternate HTTP port (often Jupyter Notebooks, web proxies, or dashboard consoles).",
        "benefit": "Interactive data science dashboards or custom web services.",
        "threats": ["Unauthenticated remote code execution (e.g. unprotected Jupyter notebooks)", "Sensitive data exposure"],
        "considerations": "Exposing interactive consoles to the public internet presents high risk.",
        "defenses": ["Enforce token/password authentication", "Require TLS", "Firewall to local network"],
    },
    9090: {
        "name": "Cockpit / Admin Console", "exposure": "Medium",
        "function": "Linux system administration web console (Cockpit) or Prometheus monitoring.",
        "benefit": "Web-based graphical server administration and monitoring.",
        "threats": ["Brute-force attacks against administrative credentials", "Privilege escalation", "Direct OS access upon compromise"],
        "considerations": "Management consoles must not be open to untrusted public networks.",
        "defenses": ["Restrict to VPN / trusted management IPs", "Enforce multi-factor authentication", "Keep Cockpit updated"],
    },
    27017: {
        "name": "MongoDB", "exposure": "High",
        "function": "MongoDB NoSQL document database server.",
        "benefit": "Document database storage for web applications and microservices.",
        "threats": ["Unauthenticated access if bindIp is 0.0.0.0 without auth", "Ransomware extortion / database wiping", "Mass data exfiltration"],
        "considerations": "Databases should never listen on public interfaces.",
        "defenses": ["Bind to 127.0.0.1 or private subnet", "Enable authentication (auth = true)", "Firewall port 27017 at perimeter"],
    },
}

GENERIC = {
    "name": "Unrecognised / uncommon port", "exposure": "Unknown",
    "function": "Not in the built-in reference. Identify the service from the Nmap -sV output.",
    "benefit": "Depends on the service.",
    "threats": ["Unknown services may be forgotten, unmanaged or unpatched"],
    "considerations": "Confirm with the system owner whether this service is intended to be reachable.",
    "defenses": ["Verify business need", "Close or firewall the port if unnecessary", "Keep the service patched"],
}

NOT_DETERMINED = ("Not determined. This scan shows the port is open and identifies the service only. "
                  "Declaring a misconfiguration or vulnerability requires further authorized investigation "
                  "(configuration review, authenticated checks, or approved vulnerability testing).")


def load_open_ports(csv_path):
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return [r for r in rows if r.get("state", "").strip().lower() == "open"]


def analyze_row(row):
    """Return the reference-info dict for one parsed port row (used by report.py)."""
    try:
        port = int(row.get("port", 0))
    except (ValueError, TypeError):
        port = 0
    proto = str(row.get("protocol", "")).lower()
    return PORT_DB.get(port, GENERIC) if proto == "tcp" else GENERIC


def format_entry(row):
    try:
        port = int(row.get("port", 0))
    except (ValueError, TypeError):
        port = 0
    proto = str(row.get("protocol", "")).lower()
    info = PORT_DB.get(port, GENERIC) if proto == "tcp" else GENERIC

    extrainfo = row.get("extrainfo", "").strip()
    product = f"{row.get('product', '')} {row.get('version', '')}".strip()
    if extrainfo:
        product = f"{product} ({extrainfo})" if product else extrainfo

    service_line = row.get("service", "") or "unknown"
    if product:
        service_line += f" ({product})"

    ip = row.get("ip", "unknown")
    lines = [
        f"### {ip} - {port}/{proto} ({info['name']})",
        "",
        f"- **OPEN PORT:** {port}/{proto} is open",
        f"- **SERVICE:** {service_line}",
        f"- **Version:** {product if product else 'not identified'}",
        f"- **Function:** {info['function']}",
        f"- **Legitimate benefit/use:** {info['benefit']}",
        "- **Potential security threats:**",
    ]
    lines += [f"  - {t}" for t in info["threats"]]
    lines += [
        f"- **EXPOSURE (preliminary rating if publicly reachable):** {info['exposure']}",
        f"- **Security considerations:** {info['considerations']}",
        f"- **MISCONFIGURATION / VULNERABILITY status:** {NOT_DETERMINED}",
    ]
    if product:
        lines.append(f"- **Version note:** Compare `{product}` against vendor security advisories to check for known issues.")
    lines.append("- **Recommended defensive measures:**")
    lines += [f"  - {d}" for d in info["defenses"]]
    lines.append("")
    return "\n".join(lines)


def build_report(open_rows, source):
    out = ["# Open Port Analysis", "",
           f"Source data: `{source}`", "",
           "> An open port is not automatically a vulnerability. Ratings below are preliminary",
           "> exposure indicators based on the port type, not confirmed findings.", ""]
    if not open_rows:
        out.append("No open ports were found in the scan results.")
        return "\n".join(out) + "\n"

    out += ["## Summary", "",
            "| Host | Port | Service | Product / Version | Exposure |",
            "|---|---|---|---|---|"]
    for r in open_rows:
        try:
            port_num = int(r["port"])
        except (ValueError, TypeError):
            port_num = 0
        info = PORT_DB.get(port_num, GENERIC) if r["protocol"] == "tcp" else GENERIC
        out.append(f"| {r['ip']} | {r['port']}/{r['protocol']} | {r['service']} | "
                   f"{(r['product'] + ' ' + r['version']).strip()} | {info['exposure']} |")
    out += ["", "## Detailed Analysis", ""]
    out += [format_entry(r) for r in open_rows]
    return "\n".join(out) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Analyze open ports from scan_results.csv.")
    parser.add_argument("--input", default="results/scan_results.csv", help="CSV from parse_nmap.py")
    parser.add_argument("--output", default="results/port_analysis.md", help="Markdown file to write")
    args = parser.parse_args()

    csv_path = Path(args.input)
    if not csv_path.is_file():
        sys.exit(f"Error: {csv_path} not found. Run parse_nmap.py first.")

    open_rows = load_open_ports(csv_path)
    report = build_report(open_rows, csv_path)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")

    print(report)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()