#!/usr/bin/env python3
"""
parse_nmap.py - Convert an Nmap XML file into CSV and JSON.

This script does NOT scan anything. It only reads an XML file that Nmap
already produced (for example: nmap -sV TARGET -oA scans/raw/target_scan).

Usage:
    python3 scripts/parse_nmap.py scans/raw/target_scan.xml
    python3 scripts/parse_nmap.py scans/raw/target_scan.xml --outdir results
"""

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

FIELDS = ["ip", "hostname", "port", "protocol", "state", "service", "product", "version"]


def parse_nmap_xml(xml_path):
    """Return a list of dicts, one per port found in the Nmap XML file."""
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"'{xml_path}' is not valid XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise ValueError(f"'{xml_path}' does not look like an Nmap XML file.")

    rows = []
    for host in root.findall("host"):
        # Skip hosts Nmap reported as down
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # IP address (prefer IPv4/IPv6 over MAC)
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break

        # Hostname (may be absent)
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""

        for port in host.findall("ports/port"):
            state_el = port.find("state")
            service_el = port.find("service")
            service = service_el.attrib if service_el is not None else {}

            rows.append({
                "ip": ip,
                "hostname": hostname,
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", ""),
                "state": state_el.get("state", "") if state_el is not None else "",
                "service": service.get("name", ""),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
            })
    return rows


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_json(rows, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
        f.write("\n")


def print_summary(rows, source):
    print("=" * 60)
    print(f"Nmap results parsed from: {source}")
    print("=" * 60)

    if not rows:
        print("No port entries found (host down, or no ports reported).")
        return

    hosts = sorted({r["ip"] for r in rows})
    states = {}
    for r in rows:
        states[r["state"]] = states.get(r["state"], 0) + 1

    print(f"Hosts with port data : {len(hosts)} ({', '.join(hosts)})")
    print("Ports by state       : " + ", ".join(f"{k}={v}" for k, v in sorted(states.items())))
    print()
    print(f"{'IP':<16}{'PORT':<10}{'STATE':<10}{'SERVICE':<14}PRODUCT / VERSION")
    print("-" * 60)
    for r in rows:
        port = f"{r['port']}/{r['protocol']}"
        detail = f"{r['product']} {r['version']}".strip()
        print(f"{r['ip']:<16}{port:<10}{r['state']:<10}{r['service']:<14}{detail}")


def main():
    parser = argparse.ArgumentParser(description="Convert Nmap XML to CSV and JSON.")
    parser.add_argument("xml_file", help="Path to the Nmap XML file (e.g. scans/raw/target_scan.xml)")
    parser.add_argument("--outdir", default="results", help="Output folder (default: results)")
    args = parser.parse_args()

    xml_path = Path(args.xml_file)
    if not xml_path.is_file():
        sys.exit(f"Error: file not found: {xml_path}")

    try:
        rows = parse_nmap_xml(xml_path)
    except ValueError as exc:
        sys.exit(f"Error: {exc}")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    write_csv(rows, outdir / "scan_results.csv")
    write_json(rows, outdir / "scan_results.json")

    print_summary(rows, xml_path)
    print()
    print(f"Saved: {outdir / 'scan_results.csv'}")
    print(f"Saved: {outdir / 'scan_results.json'}")


if __name__ == "__main__":
    main()