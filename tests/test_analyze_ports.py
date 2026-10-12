import pytest
from scripts.analyze_ports import (
    PORT_DB,
    GENERIC,
    analyze_row,
    format_entry,
    build_report,
    load_open_ports,
)


class TestAnalyzePorts:
    def test_known_ports_in_db(self):
        # Verify critical web, admin and database ports exist
        for p in [21, 22, 25, 53, 80, 443, 3306, 3389, 5432, 6379, 27017]:
            assert p in PORT_DB
            assert "name" in PORT_DB[p]
            assert "exposure" in PORT_DB[p]
            assert "function" in PORT_DB[p]
            assert "benefit" in PORT_DB[p]
            assert "threats" in PORT_DB[p]
            assert "defenses" in PORT_DB[p]

    def test_analyze_row_known_tcp(self):
        row = {"port": "22", "protocol": "tcp", "state": "open"}
        info = analyze_row(row)
        assert info["name"] == "SSH"
        assert info["exposure"] == "Medium"

    def test_analyze_row_unknown_port(self):
        row = {"port": "9999", "protocol": "tcp", "state": "open"}
        info = analyze_row(row)
        assert info == GENERIC
        assert info["exposure"] == "Unknown"

    def test_analyze_row_non_tcp(self):
        row = {"port": "53", "protocol": "udp", "state": "open"}
        info = analyze_row(row)
        assert info == GENERIC

    def test_format_entry(self):
        row = {
            "ip": "192.0.2.10",
            "hostname": "target.example",
            "port": "80",
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "product": "nginx",
            "version": "1.18.0",
            "extrainfo": "Ubuntu",
        }
        entry = format_entry(row)
        assert "192.0.2.10 - 80/tcp (HTTP)" in entry
        assert "nginx 1.18.0 (Ubuntu)" in entry
        assert "Hypertext Transfer Protocol" in entry
        assert "Medium" in entry

    def test_build_report_empty(self):
        report = build_report([], "source.csv")
        assert "No open ports were found" in report

    def test_build_report_with_open_ports(self):
        open_rows = [
            {"ip": "192.0.2.10", "port": "443", "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.18", "extrainfo": ""},
        ]
        report = build_report(open_rows, "source.csv")
        assert "# Open Port Analysis" in report
        assert "443/tcp" in report
        assert "Low" in report
