#!/usr/bin/env python3
"""
app.py - Website Port Security Analyzer (end-to-end pipeline).

    python3 app.py
    python3 app.py --url http://192.168.56.101 --authorized
    python3 app.py --url http://192.168.56.101 --full

Pipeline: validate URL -> resolve IP -> Nmap (-sV) -> scripts/parse_nmap.py
          -> scripts/analyze_ports.py -> Markdown report -> HTML dashboard.

Scope: DNS resolution, port discovery, service/version detection, analysis and
reporting only. Use ONLY on systems you own or have written permission to test.
"""

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import report  # noqa: E402
import scanner  # noqa: E402
from scanner import ScanError  # noqa: E402

RESULTS = ROOT / "results"
CSV_PATH = RESULTS / "scan_results.csv"
JSON_PATH = RESULTS / "scan_results.json"
ANALYSIS_PATH = RESULTS / "port_analysis.md"
DASHBOARD_PATH = RESULTS / "dashboard.html"

BAR = "=" * 40


def banner(title):
    print(BAR)
    print(title.center(40).rstrip())
    print(BAR)


def step(msg):
    print(f"[+] {msg}", flush=True)


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def run_script(name, args):
    """Run one of the existing project scripts with the current Python interpreter."""
    cmd = [sys.executable, str(SCRIPTS / name), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    except OSError as exc:
        raise ScanError(f"Could not run {name}: {exc}")
    if proc.returncode != 0:
        raise ScanError(f"{name} failed:\n{(proc.stderr or proc.stdout).strip()}")
    return proc.stdout


def confirm_authorization(hostname, ip):
    print()
    kind = "PRIVATE/LAB" if scanner.is_private(ip) else "PUBLIC"
    print(f"Target {hostname} ({ip}) is a {kind} address.")
    print("Only scan systems you own or have explicit written permission to test.")
    answer = input("Do you have authorization to scan this target? (yes/no): ").strip().lower()
    if answer not in ("yes", "y"):
        raise ScanError("Authorization not confirmed. Scan cancelled.")


def pipeline(args):
    banner("WEBSITE PORT SECURITY ANALYZER")
    print()

    raw_url = args.url or input("Enter target URL: ")
    url, hostname = scanner.validate_url(raw_url)
    name = scanner.safe_name(hostname)

    step("Resolving target...")
    ip = scanner.resolve_host(hostname)
    step(f"Target IP: {ip}")

    if not args.authorized:
        confirm_authorization(hostname, ip)

    nmap_version = scanner.check_nmap()
    step(f"Using {nmap_version}")

    step("Running Nmap...")
    step("Detecting services... (this can take a few minutes; Ctrl+C to cancel)")
    started = datetime.now()
    xml_path, nmap_cmd = scanner.run_nmap(ip, ROOT / "scans" / "raw" / name, full_scan=args.full)
    nmap_cmd = nmap_cmd.replace(str(ROOT) + "/", "")  # show relative paths in the report
    step(f"Nmap finished. XML saved: {rel(xml_path)}")

    # Remove old outputs so a failed step can never be mistaken for fresh results.
    for old in (CSV_PATH, JSON_PATH, ANALYSIS_PATH):
        old.unlink(missing_ok=True)

    step("Parsing Nmap XML...")
    run_script("parse_nmap.py", [str(xml_path), "--outdir", str(RESULTS)])
    if not CSV_PATH.is_file() or not JSON_PATH.is_file():
        raise ScanError("Parser output is missing (results/scan_results.csv or .json was not created).")

    rows = report.load_rows(CSV_PATH)
    if not rows:
        print("[!] The scan returned no port data (target may be filtered or down). "
              "Reports will show zero ports.")

    step("Analyzing open ports...")
    run_script("analyze_ports.py", ["--input", str(CSV_PATH), "--output", str(ANALYSIS_PATH)])
    if not ANALYSIS_PATH.is_file():
        raise ScanError("Analyzer output is missing (results/port_analysis.md was not created).")

    ctx = report.build_context(
        target={"url": url, "hostname": hostname, "ip": ip, "safe_name": name},
        rows=rows, xml_path=xml_path, nmap_version=nmap_version, nmap_cmd=nmap_cmd,
        timestamp=started.strftime("%Y-%m-%d %H:%M:%S"),
    )

    step("Generating security report...")
    report_path = ROOT / "reports" / f"{name}_report.md"
    report.write_markdown(ctx, report_path)

    step("Generating dashboard...")
    report.write_dashboard(ctx, DASHBOARD_PATH)

    print()
    banner("SCAN COMPLETE")
    c = ctx["counts"]
    print()
    print(f"Open Ports   : {c['open']}")
    print(f"High Risk    : {c['high']}")
    print(f"Medium Risk  : {c['medium']}")
    print(f"Low Risk     : {c['low']}")
    print(f"Unknown      : {c['unknown']}")
    if c["open"] == 0:
        print("\nNo open ports were found among the ports scanned.")
    print(f"\nReport:\n{rel(report_path)}")
    print(f"\nDashboard:\n{rel(DASHBOARD_PATH)}")


def main():
    parser = argparse.ArgumentParser(description="Automated Nmap scan, analysis, report and dashboard.")
    parser.add_argument("--url", help="Target URL or hostname (prompted if omitted)")
    parser.add_argument("--full", action="store_true", help="Scan all 65535 TCP ports (-p-). Slower; authorized lab targets only.")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirm you are authorized to scan this target (skips the yes/no prompt)")
    args = parser.parse_args()

    try:
        pipeline(args)
    except ScanError as exc:
        print(f"\n[!] {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Scan cancelled; partial files may exist in scans/raw/.", file=sys.stderr)
        sys.exit(130)
    except EOFError:
        print("\n[!] No input available.", file=sys.stderr)
        sys.exit(1)
    except PermissionError as exc:
        print(f"\n[!] Permission error: {exc}. Check ownership of scans/, results/ and reports/ "
              "(files created earlier with sudo may be root-owned).", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"\n[!] File error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()