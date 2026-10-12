import pytest
from pathlib import Path
from scripts.report import (
    build_context,
    write_markdown,
    write_dashboard,
    assessment_text,
    recommendations,
    read_xml_extras,
)


class TestReport:
    SAMPLE_XML = Path(__file__).resolve().parent.parent / "samples" / "sample_nmap.xml"

    def test_assessment_text_zero_open(self):
        text = assessment_text({"open": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0})
        assert "No open ports were found" in text

    def test_assessment_text_high_exposure(self):
        text = assessment_text({"open": 3, "high": 1, "medium": 1, "low": 1, "unknown": 0})
        assert "3 open port(s)" in text
        assert "High-exposure services" in text

    def test_recommendations_robustness(self):
        open_ports = [
            {"port": 80, "protocol": "tcp", "name": "HTTP", "risk": "Medium", "defenses": ["Use HTTPS"]},
            {"port": 443, "protocol": "tcp", "name": "HTTPS", "risk": "Low", "defenses": ["Modern TLS"]},
            {"port": 3306, "protocol": "tcp", "name": "MySQL", "risk": "High", "defenses": ["Bind localhost"]},
            {"port": 9999, "protocol": "tcp", "name": "Custom", "risk": "NonStandard", "defenses": ["Review"]},
        ]
        recs = recommendations(open_ports)
        assert len(recs["per_port"]) == 4
        # High risk should come first
        assert recs["per_port"][0]["title"].startswith("Port 3306")
        assert len(recs["general"]) > 0

    def test_build_context_and_output(self, tmp_path):
        target = {"url": "http://192.0.2.10", "hostname": "target.example", "ip": "192.0.2.10", "safe_name": "target"}
        rows = [
            {"ip": "192.0.2.10", "port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "nginx", "version": "1.18.0", "extrainfo": ""},
            {"ip": "192.0.2.10", "port": 443, "protocol": "tcp", "state": "open", "service": "http", "product": "nginx", "version": "1.18.0", "extrainfo": ""},
        ]
        ctx = build_context(
            target=target,
            rows=rows,
            xml_path=self.SAMPLE_XML,
            nmap_version="Nmap 7.94",
            nmap_cmd="nmap -sV TARGET",
            timestamp="2026-10-12 12:00:00",
        )
        assert ctx["counts"]["open"] == 2
        assert ctx["counts"]["medium"] == 1
        assert ctx["counts"]["low"] == 1

        md_path = tmp_path / "report.md"
        dash_path = tmp_path / "dashboard.html"

        write_markdown(ctx, md_path)
        write_dashboard(ctx, dash_path)

        assert md_path.is_file()
        assert dash_path.is_file()

        md_content = md_path.read_text(encoding="utf-8")
        assert "# Website Port Security Analysis Report" in md_content
        assert "Port 80/tcp" in md_content
        assert "Port 443/tcp" in md_content

        dash_content = dash_path.read_text(encoding="utf-8")
        assert "<title>Port Security Dashboard</title>" in dash_content
        assert "target.example" in dash_content
