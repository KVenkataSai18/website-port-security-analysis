import pytest
from pathlib import Path
from scripts.parse_nmap import parse_nmap_xml, write_csv, write_json, FIELDS


class TestParseNmap:
    SAMPLE_XML = Path(__file__).resolve().parent.parent / "samples" / "sample_nmap.xml"

    def test_parse_sample_xml(self):
        assert self.SAMPLE_XML.is_file()
        rows = parse_nmap_xml(self.SAMPLE_XML)
        assert len(rows) == 6

        # Check port numbers and states
        ports = {r["port"]: r for r in rows}
        assert 22 in ports
        assert ports[22]["state"] == "open"
        assert ports[22]["service"] == "ssh"
        assert ports[22]["product"] == "OpenSSH"
        assert ports[22]["version"] == "8.9p1"

        assert 80 in ports
        assert ports[80]["state"] == "open"
        assert ports[80]["service"] == "http"

        assert 443 in ports
        assert ports[443]["state"] == "open"

        assert 3306 in ports
        assert ports[3306]["state"] == "open"
        assert ports[3306]["service"] == "mysql"

        assert 8080 in ports
        assert ports[8080]["state"] == "filtered"

        assert 9999 in ports
        assert ports[9999]["state"] == "open"

    def test_parse_invalid_xml(self, tmp_path):
        bad_xml = tmp_path / "bad.xml"
        bad_xml.write_text("<not-xml>", encoding="utf-8")
        with pytest.raises(ValueError, match="not valid XML"):
            parse_nmap_xml(bad_xml)

    def test_parse_non_nmap_xml(self, tmp_path):
        other_xml = tmp_path / "other.xml"
        other_xml.write_text("<root><child>data</child></root>", encoding="utf-8")
        with pytest.raises(ValueError, match="does not look like an Nmap XML file"):
            parse_nmap_xml(other_xml)

    def test_write_csv_and_json(self, tmp_path):
        rows = parse_nmap_xml(self.SAMPLE_XML)
        csv_file = tmp_path / "test.csv"
        json_file = tmp_path / "test.json"

        write_csv(rows, csv_file)
        write_json(rows, json_file)

        assert csv_file.is_file()
        assert json_file.is_file()
        assert csv_file.stat().st_size > 0
        assert json_file.stat().st_size > 0

        # Verify header in CSV
        lines = csv_file.read_text(encoding="utf-8").splitlines()
        assert lines[0] == ",".join(FIELDS)
        assert len(lines) == len(rows) + 1
