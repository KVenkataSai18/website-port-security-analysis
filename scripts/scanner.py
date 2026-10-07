#!/usr/bin/env python3
"""
scanner.py - Target handling and Nmap execution for app.py.

Does only: URL validation, hostname extraction, DNS resolution, and running
Nmap with service/version detection. No exploitation, brute force, or
evasion options are used.
"""

import ipaddress
import re
import shutil
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse


class ScanError(Exception):
    """A user-facing error (bad input, missing tool, scan failure)."""


HOST_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)


def validate_url(raw):
    """Return (normalized_url, hostname). Accepts 'example.com' or a full http(s) URL."""
    raw = (raw or "").strip()
    if not raw:
        raise ScanError("No URL entered.")
    if "://" not in raw:
        raw = "http://" + raw

    try:
        parsed = urlparse(raw)
        host = parsed.hostname
        _ = parsed.port  # raises ValueError on a bad port
    except ValueError:
        raise ScanError(f"Invalid URL: {raw}")

    if parsed.scheme not in ("http", "https"):
        raise ScanError("Only http:// and https:// URLs are supported.")
    if not host:
        raise ScanError(f"Could not find a hostname in: {raw}")

    host = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            raise ScanError("IPv6 targets are not supported by this tool.")
    except ValueError:
        if not HOST_RE.match(host):
            raise ScanError(f"'{host}' is not a valid hostname.")
    return raw, host


def safe_name(hostname):
    """example.com -> example_com (safe for file names)."""
    return re.sub(r"[^a-z0-9]+", "_", hostname.lower()).strip("_") or "target"


def resolve_host(hostname):
    """Resolve a hostname to an IPv4 address."""
    try:
        socket.inet_aton(hostname)
        return hostname  # already an IPv4 address
    except OSError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScanError(f"DNS resolution failed for '{hostname}': {exc.strerror or exc}")
    if not infos:
        raise ScanError(f"No IPv4 address found for '{hostname}'.")
    return infos[0][4][0]


def is_private(ip):
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local


def check_nmap():
    """Return the Nmap version line, or raise ScanError if Nmap is missing."""
    if shutil.which("nmap") is None:
        raise ScanError("Nmap is not installed or not in PATH. Install it with: sudo apt install nmap")
    try:
        out = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanError(f"Could not run Nmap: {exc}")
    first = out.stdout.strip().splitlines()[0] if out.stdout.strip() else "Nmap (version unknown)"
    return first


def run_nmap(ip, out_base, full_scan=False):
    """
    Run: nmap -sV -Pn --host-timeout 30m [-p-] -oA <out_base> <ip>
    Returns (xml_path, command_string).

      -sV            service/version detection
      -Pn            skip host discovery (many web servers block ping)
      --host-timeout give up on a host after 30 minutes
      -oA            write .nmap, .gnmap and .xml files
    """
    out_base = Path(out_base)
    out_base.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["nmap", "-sV", "-Pn", "--host-timeout", "30m"]
    if full_scan:
        cmd.append("-p-")
    cmd += ["-oA", str(out_base), ip]
    cmd_str = " ".join(cmd)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        raise ScanError("Nmap is not installed or not in PATH.")
    except PermissionError:
        raise ScanError("Permission denied while starting Nmap or writing scan files.")

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        low = err.lower()
        if "requires root" in low or "operation not permitted" in low or "permission denied" in low:
            raise ScanError("Nmap needs more privileges for this scan. Check file permissions "
                            "on scans/raw/, or try running with sudo.\n" + err)
        raise ScanError(f"Nmap failed (exit code {proc.returncode}):\n{err}")

    xml_path = out_base.with_suffix(".xml")
    if not xml_path.is_file() or xml_path.stat().st_size == 0:
        raise ScanError(f"Nmap finished but did not produce {xml_path}.")
    return xml_path, cmd_str