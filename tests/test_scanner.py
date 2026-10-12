import pytest
from unittest.mock import patch, MagicMock
import subprocess
from scripts.scanner import (
    validate_url,
    safe_name,
    resolve_host,
    is_private,
    check_nmap,
    ScanError,
)


class TestScanner:
    def test_validate_url_plain_hostname(self):
        raw, host = validate_url("example.com")
        assert raw == "http://example.com"
        assert host == "example.com"

    def test_validate_url_with_scheme(self):
        raw, host = validate_url("https://sub.domain.org")
        assert raw == "https://sub.domain.org"
        assert host == "sub.domain.org"

    def test_validate_url_ipv4_address(self):
        raw, host = validate_url("http://192.168.1.100")
        assert host == "192.168.1.100"

    def test_validate_url_ipv6_rejected(self):
        with pytest.raises(ScanError, match="IPv6 targets are not supported"):
            validate_url("http://[2001:db8::1]")

    def test_validate_url_invalid_scheme(self):
        with pytest.raises(ScanError, match="Only http:// and https:// URLs are supported"):
            validate_url("ftp://example.com")

    def test_validate_url_empty(self):
        with pytest.raises(ScanError, match="No URL entered"):
            validate_url("")

    def test_safe_name(self):
        assert safe_name("example.com") == "example_com"
        assert safe_name("sub-domain.test.org") == "sub_domain_test_org"
        assert safe_name("192.168.1.1") == "192_168_1_1"
        assert safe_name("$$$") == "target"

    def test_is_private_ip(self):
        assert is_private("127.0.0.1") is True
        assert is_private("192.168.1.50") is True
        assert is_private("10.0.0.5") is True
        assert is_private("172.16.0.1") is True
        assert is_private("8.8.8.8") is False
        assert is_private("93.184.216.34") is False

    @patch("socket.getaddrinfo")
    def test_resolve_host_domain(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
        ip = resolve_host("example.com")
        assert ip == "93.184.216.34"

    def test_resolve_host_ip_literal(self):
        ip = resolve_host("192.168.1.1")
        assert ip == "192.168.1.1"

    @patch("shutil.which", return_value="/usr/bin/nmap")
    @patch("subprocess.run")
    def test_check_nmap_present(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(stdout="Nmap version 7.94SVN\n", returncode=0)
        ver = check_nmap()
        assert "Nmap version 7.94" in ver

    @patch("shutil.which", return_value=None)
    def test_check_nmap_missing(self, mock_which):
        with pytest.raises(ScanError, match="Nmap is not installed"):
            check_nmap()
