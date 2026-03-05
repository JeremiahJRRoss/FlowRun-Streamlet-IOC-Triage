# tests/test_tools.py
# ─────────────────────────────────────────────────────────────────────────────
# Tool tests using httpx mock responses.
# Tests the integration layer (URL building, response parsing).
# ─────────────────────────────────────────────────────────────────────────────

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.integrations.virustotal import build_vt_url, parse_vt_response
from agent.integrations.abuseipdb import build_abuseipdb_url, parse_abuseipdb_response
from agent.integrations.otx import build_otx_url, parse_otx_response
from agent.integrations.urlscan import parse_urlscan_response
from agent.integrations.nvd import build_nvd_url, parse_nvd_response


class TestVirusTotalIntegration:
    """VirusTotal URL routing and response parsing."""

    def test_ip_url(self):
        url = build_vt_url("https://www.virustotal.com/api/v3", "8.8.8.8")
        assert "/ip_addresses/8.8.8.8" in url

    def test_domain_url(self):
        url = build_vt_url("https://www.virustotal.com/api/v3", "example.com")
        assert "/domains/example.com" in url

    def test_url_url(self):
        url = build_vt_url("https://www.virustotal.com/api/v3", "https://evil.com/phish")
        assert "/urls/" in url

    def test_hash_url(self):
        md5 = "44d88612fea8a8f36de82e1278abb02f"
        url = build_vt_url("https://www.virustotal.com/api/v3", md5)
        assert f"/files/{md5}" in url

    def test_parse_response(self):
        raw = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 5, "suspicious": 2, "harmless": 80, "undetected": 13
        }}}}
        result = parse_vt_response(raw)
        assert "data" in result


class TestAbuseIPDBIntegration:
    """AbuseIPDB URL building and response parsing."""

    def test_build_url(self):
        url, params = build_abuseipdb_url(
            "https://api.abuseipdb.com/api/v2/check", "203.0.113.42"
        )
        assert params["ipAddress"] == "203.0.113.42"
        assert params["maxAgeInDays"] == 90

    def test_parse_response(self):
        raw = {"data": {"abuseConfidenceScore": 85, "totalReports": 42}}
        result = parse_abuseipdb_response(raw)
        assert result["data"]["abuseConfidenceScore"] == 85


class TestOTXIntegration:
    """OTX URL routing for different IOC types."""

    def test_ipv4_url(self):
        url = build_otx_url("https://otx.alienvault.com/api/v1/indicators", "8.8.8.8")
        assert "/IPv4/8.8.8.8/general" in url

    def test_domain_url(self):
        url = build_otx_url("https://otx.alienvault.com/api/v1/indicators", "example.com")
        assert "/domain/example.com/general" in url

    def test_cve_url(self):
        url = build_otx_url("https://otx.alienvault.com/api/v1/indicators", "CVE-2021-44228")
        assert "/cve/CVE-2021-44228/general" in url

    def test_hash_url(self):
        h = "44d88612fea8a8f36de82e1278abb02f"
        url = build_otx_url("https://otx.alienvault.com/api/v1/indicators", h)
        assert f"/file/{h}/general" in url

    def test_parse_response(self):
        raw = {"pulse_info": {"pulses": [{"name": "Test Pulse"}]}}
        result = parse_otx_response(raw)
        assert len(result["pulse_info"]["pulses"]) == 1


class TestURLScanIntegration:
    """urlscan.io response parsing."""

    def test_parse_malicious(self):
        raw = {
            "verdicts": {"overall": {"score": 100, "malicious": True}},
            "page": {"domain": "evil.com"},
        }
        result = parse_urlscan_response(raw)
        assert result["verdicts"]["overall"]["malicious"] is True

    def test_parse_clean(self):
        raw = {
            "verdicts": {"overall": {"score": 0, "malicious": False}},
            "page": {"domain": "google.com"},
        }
        result = parse_urlscan_response(raw)
        assert result["verdicts"]["overall"]["score"] == 0


class TestNVDIntegration:
    """NIST NVD URL building and response parsing."""

    def test_build_url(self):
        url, params = build_nvd_url(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "CVE-2021-44228",
        )
        assert params["cveId"] == "CVE-2021-44228"

    def test_parse_response(self):
        raw = {"vulnerabilities": [{"cve": {
            "id": "CVE-2021-44228",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]},
            "descriptions": [{"value": "Log4Shell vulnerability"}],
        }}]}
        result = parse_nvd_response(raw)
        assert len(result["vulnerabilities"]) == 1


class TestOSVIntegration:
    """OSV.dev request building and response parsing."""

    def test_build_query_npm(self):
        from agent.integrations.osv import build_osv_query
        body = build_osv_query("npm", "postmark-mcp")
        assert body["package"]["name"] == "postmark-mcp"
        assert body["package"]["ecosystem"] == "npm"

    def test_build_query_pypi(self):
        from agent.integrations.osv import build_osv_query
        body = build_osv_query("pypi", "requessts")
        assert body["package"]["ecosystem"] == "PyPI"

    def test_parse_response(self):
        from agent.integrations.osv import parse_osv_response
        raw = {"vulns": [{"id": "MAL-2024-1234", "summary": "Malicious package"}]}
        result = parse_osv_response(raw)
        assert len(result["vulns"]) == 1

    def test_parse_package_ioc(self):
        from agent.integrations.osv import parse_package_ioc
        eco, name = parse_package_ioc("npm:postmark-mcp")
        assert eco == "npm"
        assert name == "postmark-mcp"


class TestRegistryIntegration:
    """Package registry URL building and response parsing."""

    def test_build_npm_url(self):
        from agent.integrations.registry import build_registry_url
        url = build_registry_url("npm", "postmark-mcp")
        assert url == "https://registry.npmjs.org/postmark-mcp"

    def test_build_pypi_url(self):
        from agent.integrations.registry import build_registry_url
        url = build_registry_url("pypi", "requests")
        assert url == "https://pypi.org/pypi/requests/json"

    def test_unsupported_ecosystem(self):
        from agent.integrations.registry import build_registry_url
        import pytest
        with pytest.raises(ValueError, match="not supported"):
            build_registry_url("cargo", "serde")

    def test_parse_npm_response(self):
        from agent.integrations.registry import parse_registry_response
        raw = {
            "name": "test-pkg",
            "dist-tags": {"latest": "1.0.0"},
            "time": {"created": "2024-01-01T00:00:00Z", "modified": "2024-06-01T00:00:00Z"},
            "maintainers": [{"name": "alice"}],
            "description": "A test package",
            "versions": {"1.0.0": {"scripts": {"postinstall": "node evil.js"}}},
        }
        result = parse_registry_response("npm", raw)
        assert result["name"] == "test-pkg"
        assert result["has_install_scripts"] is True
        assert len(result["maintainers"]) == 1

    def test_parse_pypi_response(self):
        from agent.integrations.registry import parse_registry_response
        raw = {
            "info": {
                "name": "requests",
                "version": "2.31.0",
                "author": "Kenneth Reitz",
                "summary": "HTTP library",
                "project_urls": {"Source": "https://github.com/psf/requests"},
            },
            "releases": {"2.31.0": [{"upload_time_iso_8601": "2023-05-22T00:00:00Z"}]},
        }
        result = parse_registry_response("pypi", raw)
        assert result["name"] == "requests"
        assert result["repository"] == "https://github.com/psf/requests"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
