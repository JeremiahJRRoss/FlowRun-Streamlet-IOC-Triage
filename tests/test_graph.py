# tests/test_graph.py
# ─────────────────────────────────────────────────────────────────────────────
# Integration tests for the LangGraph StateGraph.
# Replaces entire module-level tool objects to avoid Pydantic v2 setattr issues.
# ─────────────────────────────────────────────────────────────────────────────

import asyncio
import pytest
import sys
import os
from unittest.mock import AsyncMock, patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Mock data ─────────────────────────────────────────────────────────────────

MOCK_VT_CLEAN = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 10
}}}}

MOCK_VT_MALICIOUS = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 75, "suspicious": 10, "harmless": 10, "undetected": 5
}}}}

MOCK_ABUSEIPDB_CLEAN = {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US"}}
MOCK_ABUSEIPDB_MALICIOUS = {"data": {"abuseConfidenceScore": 100, "totalReports": 500, "countryCode": "RU"}}

MOCK_OTX_CLEAN = {"pulse_info": {"pulses": []}}
MOCK_OTX_MALICIOUS = {"pulse_info": {"pulses": [{"name": f"APT{i}"} for i in range(5)]}}

MOCK_URLSCAN_CLEAN = {"verdicts": {"overall": {"score": 0, "malicious": False}}}
MOCK_NVD_EMPTY = {"vulnerabilities": []}


def _make_mock_tool(return_value=None, side_effect=None):
    """Create a mock object that looks like a LangChain tool."""
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=return_value, side_effect=side_effect)
    mock.name = "mock_tool"
    return mock


def _mock_llm():
    """Return a mock LLM that produces a simple report string."""
    mock_response = MagicMock()
    mock_response.content = "This IOC shows clean signals across all sources."
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=mock_response)
    return mock


class TestGraphCleanIP:
    """AC-02: 8.8.8.8 (Google DNS) should return CLEAN or LOW."""

    @patch("agent.graph.get_llm")
    @patch("agent.graph.nvd_tool", _make_mock_tool(MOCK_NVD_EMPTY))
    @patch("agent.graph.urlscan_tool", _make_mock_tool(MOCK_URLSCAN_CLEAN))
    @patch("agent.graph.otx_tool", _make_mock_tool(MOCK_OTX_CLEAN))
    @patch("agent.graph.abuseipdb_tool", _make_mock_tool(MOCK_ABUSEIPDB_CLEAN))
    @patch("agent.graph.vt_tool", _make_mock_tool(MOCK_VT_CLEAN))
    def test_clean_ip_returns_clean_or_low(self, mock_get_llm):
        mock_get_llm.return_value = _mock_llm()
        from agent.graph import build_graph
        graph = build_graph()
        result = asyncio.run(graph.ainvoke({"ioc_raw": "8.8.8.8"}))

        assert result["ioc_type"] == "ip"
        assert result["severity_band"] in ("CLEAN", "LOW")
        assert result["composite_score"] < 0.31
        assert result["report_text"]


class TestGraphMaliciousIP:
    """AC-01: Known-malicious IP should return HIGH or CRITICAL."""

    @patch("agent.graph.escalation_gate", new_callable=AsyncMock, return_value={})
    @patch("agent.graph.get_llm")
    @patch("agent.graph.nvd_tool", _make_mock_tool(MOCK_NVD_EMPTY))
    @patch("agent.graph.urlscan_tool", _make_mock_tool(MOCK_URLSCAN_CLEAN))
    @patch("agent.graph.otx_tool", _make_mock_tool(MOCK_OTX_MALICIOUS))
    @patch("agent.graph.abuseipdb_tool", _make_mock_tool(MOCK_ABUSEIPDB_MALICIOUS))
    @patch("agent.graph.vt_tool", _make_mock_tool(MOCK_VT_MALICIOUS))
    def test_malicious_ip_returns_high_or_critical(self, mock_get_llm, mock_escalation):
        mock_get_llm.return_value = _mock_llm()
        from agent.graph import build_graph
        graph = build_graph()
        result = asyncio.run(graph.ainvoke({"ioc_raw": "203.0.113.42"}))

        assert result["ioc_type"] == "ip"
        assert result["severity_band"] in ("HIGH", "CRITICAL")
        assert result["composite_score"] > 0.55


class TestGraphUnknownIOC:
    """AC-03: Unrecognisable input routes to error_node."""

    @patch("agent.graph.get_llm")
    def test_unknown_ioc_routes_to_error(self, mock_get_llm):
        mock_get_llm.return_value = _mock_llm()
        from agent.graph import build_graph
        graph = build_graph()
        result = asyncio.run(graph.ainvoke({"ioc_raw": "not_a_valid_ioc_at_all!!!"}))

        assert result["ioc_type"] == "unknown"
        report = result.get("report_text", "").lower()
        assert "error" in report or "unable" in report or "classify" in report


class TestGraphAPIFailure:
    """AC-05: Single API failure should not abort triage."""

    @patch("agent.graph.get_llm")
    @patch("agent.graph.nvd_tool", _make_mock_tool(MOCK_NVD_EMPTY))
    @patch("agent.graph.urlscan_tool", _make_mock_tool(MOCK_URLSCAN_CLEAN))
    @patch("agent.graph.otx_tool", _make_mock_tool(MOCK_OTX_CLEAN))
    @patch("agent.graph.abuseipdb_tool", _make_mock_tool(MOCK_ABUSEIPDB_CLEAN))
    @patch("agent.graph.vt_tool", _make_mock_tool(side_effect=Exception("VT 500 error")))
    def test_vt_failure_still_completes(self, mock_get_llm):
        mock_get_llm.return_value = _mock_llm()
        from agent.graph import build_graph
        graph = build_graph()
        result = asyncio.run(graph.ainvoke({"ioc_raw": "8.8.8.8"}))

        assert result["ioc_type"] == "ip"
        assert result["report_text"]
        assert any("virustotal" in e for e in result["intel_errors"])


class TestGraphCVE:
    """Test CVE IOC type uses NVD and CVE weights — VT is not queried."""

    @patch("agent.graph.get_llm")
    @patch("agent.graph.nvd_tool", _make_mock_tool({
        "vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8}}
        ]}, "descriptions": [{"value": "Critical vuln"}]}}]
    }))
    @patch("agent.graph.otx_tool", _make_mock_tool(MOCK_OTX_CLEAN))
    def test_cve_uses_nvd(self, mock_get_llm):
        mock_get_llm.return_value = _mock_llm()
        from agent.graph import build_graph
        graph = build_graph()
        result = asyncio.run(graph.ainvoke({"ioc_raw": "CVE-2021-44228"}))

        assert result["ioc_type"] == "cve"
        assert "nvd" in result.get("active_weights", {})
        assert "virustotal" not in result.get("active_weights", {})
        assert result["report_text"]


class TestMergeUrlDomainResults:
    """Test the URL→domain result merge logic."""

    def test_domain_result_wins_when_worse(self):
        from agent.graph import _merge_url_domain_results
        from agent.scoring import normalise_virustotal

        # URL result: clean (0 malicious)
        url_result = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 10
        }}}}
        # Domain result: bad (20 malicious)
        domain_result = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 20, "suspicious": 0, "harmless": 60, "undetected": 20
        }}}}
        raw_intel = {
            "virustotal": url_result,
            "virustotal_domain": domain_result,
        }
        _merge_url_domain_results(raw_intel, "virustotal", normalise_virustotal)

        # Domain result should win (worse signal)
        assert raw_intel["virustotal"] is domain_result
        assert "virustotal_domain" not in raw_intel

    def test_url_result_wins_when_worse(self):
        from agent.graph import _merge_url_domain_results
        from agent.scoring import normalise_virustotal

        # URL result: bad
        url_result = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 50, "suspicious": 5, "harmless": 30, "undetected": 15
        }}}}
        # Domain result: clean
        domain_result = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 10
        }}}}
        raw_intel = {
            "virustotal": url_result,
            "virustotal_domain": domain_result,
        }
        _merge_url_domain_results(raw_intel, "virustotal", normalise_virustotal)

        # URL result should win (worse signal)
        assert raw_intel["virustotal"] is url_result
        assert "virustotal_domain" not in raw_intel

    def test_only_domain_result_promotes(self):
        from agent.graph import _merge_url_domain_results
        from agent.scoring import normalise_virustotal

        domain_result = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 10, "suspicious": 0, "harmless": 80, "undetected": 10
        }}}}
        raw_intel = {"virustotal_domain": domain_result}
        _merge_url_domain_results(raw_intel, "virustotal", normalise_virustotal)

        assert raw_intel["virustotal"] is domain_result
        assert "virustotal_domain" not in raw_intel

    def test_no_results_no_crash(self):
        from agent.graph import _merge_url_domain_results
        from agent.scoring import normalise_virustotal

        raw_intel = {}
        _merge_url_domain_results(raw_intel, "virustotal", normalise_virustotal)
        assert "virustotal" not in raw_intel


class TestGraphURL:
    """Test URL IOC fires both URL-level and domain-level queries."""

    @patch("agent.graph.get_llm")
    @patch("agent.graph.urlscan_tool", _make_mock_tool(MOCK_URLSCAN_CLEAN))
    @patch("agent.graph.otx_tool", _make_mock_tool(MOCK_OTX_CLEAN))
    @patch("agent.graph.vt_tool", _make_mock_tool(MOCK_VT_CLEAN))
    def test_url_triage_completes(self, mock_get_llm):
        mock_get_llm.return_value = _mock_llm()
        from agent.graph import build_graph
        graph = build_graph()
        result = asyncio.run(graph.ainvoke({"ioc_raw": "https://example.com/test"}))

        assert result["ioc_type"] == "url"
        assert result["report_text"]
        assert result["severity_band"] in ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class TestGraphPackage:
    """Test package IOC type uses OSV + Registry."""

    @patch("agent.graph.get_llm")
    @patch("agent.graph.registry_tool", _make_mock_tool({
        "source": "npm", "name": "evil-pkg", "latest_version": "1.0.0",
        "created": "2018-01-01T00:00:00Z", "has_install_scripts": False,
        "maintainer_count": 5,
    }))
    @patch("agent.graph.osv_tool", _make_mock_tool({"vulns": []}))
    def test_clean_package(self, mock_get_llm):
        mock_get_llm.return_value = _mock_llm()
        from agent.graph import build_graph
        graph = build_graph()
        result = asyncio.run(graph.ainvoke({"ioc_raw": "npm:lodash"}))

        assert result["ioc_type"] == "package"
        assert result["severity_band"] in ("CLEAN", "LOW")
        assert "virustotal" not in result.get("active_weights", {})

    @patch("agent.graph.escalation_gate", new_callable=AsyncMock, return_value={})
    @patch("agent.graph.get_llm")
    @patch("agent.graph.registry_tool", _make_mock_tool({
        "source": "npm", "name": "evil-pkg", "latest_version": "1.0.0",
        "created": "2024-12-01T00:00:00Z", "has_install_scripts": True,
        "maintainer_count": 1,
    }))
    @patch("agent.graph.osv_tool", _make_mock_tool({
        "vulns": [{"id": "MAL-2024-9999", "summary": "Malicious npm package"}]
    }))
    def test_malicious_package(self, mock_get_llm, mock_escalation):
        mock_get_llm.return_value = _mock_llm()
        from agent.graph import build_graph
        graph = build_graph()
        result = asyncio.run(graph.ainvoke({"ioc_raw": "npm:evil-pkg"}))

        assert result["ioc_type"] == "package"
        assert result["severity_band"] in ("HIGH", "CRITICAL")
        assert "osv" in result.get("active_weights", {})


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestGraphPackageMulti:
    """Test bare package name triggers multi-ecosystem scan."""

    @patch("agent.graph.get_llm")
    @patch("agent.graph.osv_multi_tool", _make_mock_tool({
        "package_name": "traceroute",
        "ecosystems_scanned": ["npm", "PyPI", "crates.io", "Go"],
        "ecosystems_with_hits": [],
        "total_vulns": 0,
        "has_malware": False,
        "results": {
            "npm": {"vulns": []},
            "PyPI": {"vulns": []},
            "crates.io": {"vulns": []},
            "Go": {"vulns": []},
        },
    }))
    def test_bare_package_clean(self, mock_get_llm):
        mock_get_llm.return_value = _mock_llm()
        from agent.graph import build_graph
        graph = build_graph()
        result = asyncio.run(graph.ainvoke({"ioc_raw": "traceroute"}))

        assert result["ioc_type"] == "package_multi"
        assert result["severity_band"] in ("CLEAN", "LOW")
        assert "osv_multi" in result.get("active_weights", {})
        assert result["report_text"]

    @patch("agent.graph.escalation_gate", new_callable=AsyncMock, return_value={})
    @patch("agent.graph.get_llm")
    @patch("agent.graph.osv_multi_tool", _make_mock_tool({
        "package_name": "evil-thing",
        "ecosystems_scanned": ["npm", "PyPI"],
        "ecosystems_with_hits": ["PyPI"],
        "total_vulns": 1,
        "has_malware": True,
        "results": {
            "npm": {"vulns": []},
            "PyPI": {"vulns": [{"id": "MAL-2024-5678", "summary": "Malware"}]},
        },
    }))
    def test_bare_package_malware(self, mock_get_llm, mock_escalation):
        mock_get_llm.return_value = _mock_llm()
        from agent.graph import build_graph
        graph = build_graph()
        result = asyncio.run(graph.ainvoke({"ioc_raw": "evil-thing"}))

        assert result["ioc_type"] == "package_multi"
        assert result["severity_band"] in ("HIGH", "CRITICAL")
        assert result["report_text"]
