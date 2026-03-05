# tests/test_scoring.py
# ─────────────────────────────────────────────────────────────────────────────
# Tests for the scoring module: weight redistribution, normalisers,
# composite score calculation, and severity band mapping.
# ─────────────────────────────────────────────────────────────────────────────

import pytest
import sys
import os
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.scoring import (
    BASE_WEIGHTS,
    CVE_WEIGHTS,
    PACKAGE_WEIGHTS,
    PACKAGE_MULTI_WEIGHTS,
    redistribute_weights,
    compute_composite,
    score_to_severity,
    normalise_virustotal,
    normalise_abuseipdb,
    normalise_otx,
    normalise_urlscan,
    normalise_nvd,
    normalise_osv,
    normalise_osv_multi,
    normalise_registry,
    detect_conflicts,
    extract_vt_detections,
    extract_otx_campaigns,
    extract_nvd_details,
    extract_osv_details,
    generate_tldr,
)


class TestWeightSums:
    """Both weight dicts must sum to exactly 1.00."""

    def test_base_weights_sum(self):
        assert math.isclose(sum(BASE_WEIGHTS.values()), 1.0, abs_tol=1e-9)

    def test_cve_weights_sum(self):
        assert math.isclose(sum(CVE_WEIGHTS.values()), 1.0, abs_tol=1e-9)

    def test_base_weights_sources(self):
        assert set(BASE_WEIGHTS.keys()) == {"virustotal", "abuseipdb", "otx", "urlscan"}

    def test_cve_weights_sources(self):
        assert set(CVE_WEIGHTS.keys()) == {"otx", "nvd"}

    def test_package_weights_sum(self):
        assert math.isclose(sum(PACKAGE_WEIGHTS.values()), 1.0, abs_tol=1e-9)

    def test_package_weights_sources(self):
        assert set(PACKAGE_WEIGHTS.keys()) == {"osv", "registry"}


class TestWeightRedistribution:
    """Weights must be redistributed proportionally when sources are missing."""

    def test_all_sources_available(self):
        result = redistribute_weights(BASE_WEIGHTS, ["virustotal", "abuseipdb", "otx", "urlscan"])
        assert math.isclose(sum(result.values()), 1.0, abs_tol=1e-9)
        assert math.isclose(result["virustotal"], 0.40, abs_tol=1e-9)

    def test_one_source_missing(self):
        # Remove abuseipdb (0.30) → remaining sum=0.70
        result = redistribute_weights(BASE_WEIGHTS, ["virustotal", "otx", "urlscan"])
        assert math.isclose(sum(result.values()), 1.0, abs_tol=1e-9)
        assert math.isclose(result["virustotal"], 0.40 / 0.70, abs_tol=1e-9)

    def test_two_sources_missing(self):
        result = redistribute_weights(BASE_WEIGHTS, ["virustotal", "otx"])
        assert math.isclose(sum(result.values()), 1.0, abs_tol=1e-9)

    def test_cve_redistribution(self):
        # If NVD is down, only OTX remains — gets full weight
        result = redistribute_weights(CVE_WEIGHTS, ["otx"])
        assert math.isclose(sum(result.values()), 1.0, abs_tol=1e-9)
        assert "nvd" not in result
        assert math.isclose(result["otx"], 1.0, abs_tol=1e-9)

    def test_empty_sources(self):
        result = redistribute_weights(BASE_WEIGHTS, [])
        assert result == {}


class TestNormalisers:
    """Per-source normalisation functions."""

    def test_virustotal_malicious(self):
        # 10 malicious + 2 suspicious = 11 effective → 0.60 tier
        raw = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 10, "suspicious": 2, "harmless": 80, "undetected": 8
        }}}}
        score = normalise_virustotal(raw)
        assert score == 0.60

    def test_virustotal_clean(self):
        raw = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 10
        }}}}
        assert normalise_virustotal(raw) == 0.0

    def test_virustotal_empty(self):
        assert normalise_virustotal({}) == 0.0

    def test_virustotal_low_detections(self):
        # 1 malicious → 0.20 tier (noise/FP range)
        raw = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 1, "suspicious": 0, "harmless": 89, "undetected": 10
        }}}}
        assert normalise_virustotal(raw) == 0.20

    def test_virustotal_moderate_detections(self):
        # 4 malicious + 1 suspicious = 4.5 → 0.40 tier
        raw = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 4, "suspicious": 1, "harmless": 80, "undetected": 15
        }}}}
        assert normalise_virustotal(raw) == 0.40

    def test_virustotal_high_detections(self):
        # 25 malicious → 0.80 tier
        raw = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 25, "suspicious": 0, "harmless": 60, "undetected": 15
        }}}}
        assert normalise_virustotal(raw) == 0.80

    def test_virustotal_confirmed_malicious(self):
        # 50 malicious → 1.00 tier
        raw = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 50, "suspicious": 5, "harmless": 30, "undetected": 15
        }}}}
        assert normalise_virustotal(raw) == 1.00

    def test_abuseipdb_high_score(self):
        raw = {"data": {"abuseConfidenceScore": 95}}
        assert math.isclose(normalise_abuseipdb(raw), 0.95, abs_tol=1e-6)

    def test_abuseipdb_zero(self):
        raw = {"data": {"abuseConfidenceScore": 0}}
        assert normalise_abuseipdb(raw) == 0.0

    def test_otx_no_pulses(self):
        raw = {"pulse_info": {"pulses": []}}
        assert normalise_otx(raw) == 0.0

    def test_otx_one_pulse(self):
        raw = {"pulse_info": {"pulses": [{"name": "test"}]}}
        assert normalise_otx(raw) == 0.5

    def test_otx_five_pulses(self):
        raw = {"pulse_info": {"pulses": [{"name": f"p{i}"} for i in range(5)]}}
        assert math.isclose(normalise_otx(raw), 0.8, abs_tol=1e-6)

    def test_urlscan_malicious(self):
        raw = {"verdicts": {"overall": {"score": 100, "malicious": True}}}
        assert normalise_urlscan(raw) == 1.0

    def test_urlscan_clean(self):
        raw = {"verdicts": {"overall": {"score": 0, "malicious": False}}}
        assert normalise_urlscan(raw) == 0.0

    def test_nvd_high_cvss(self):
        raw = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8}}
        ]}}}]}
        assert math.isclose(normalise_nvd(raw), 0.98, abs_tol=1e-6)

    def test_nvd_no_vulns(self):
        raw = {"vulnerabilities": []}
        assert normalise_nvd(raw) == 0.0


class TestSeverityMapping:
    """Five distinct severity tiers."""

    def test_clean(self):
        assert score_to_severity(0.00) == "CLEAN"
        assert score_to_severity(0.05) == "CLEAN"
        assert score_to_severity(0.10) == "CLEAN"

    def test_low(self):
        assert score_to_severity(0.11) == "LOW"
        assert score_to_severity(0.20) == "LOW"
        assert score_to_severity(0.30) == "LOW"

    def test_medium(self):
        assert score_to_severity(0.31) == "MEDIUM"
        assert score_to_severity(0.45) == "MEDIUM"
        assert score_to_severity(0.55) == "MEDIUM"

    def test_high(self):
        assert score_to_severity(0.56) == "HIGH"
        assert score_to_severity(0.65) == "HIGH"
        assert score_to_severity(0.75) == "HIGH"

    def test_critical(self):
        assert score_to_severity(0.76) == "CRITICAL"
        assert score_to_severity(0.90) == "CRITICAL"
        assert score_to_severity(1.00) == "CRITICAL"


class TestCompositeScore:
    """End-to-end composite score computation."""

    def test_all_clean_ip(self):
        raw_intel = {
            "virustotal": {"data": {"attributes": {"last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 10
            }}}},
            "abuseipdb": {"data": {"abuseConfidenceScore": 0}},
            "otx": {"pulse_info": {"pulses": []}},
        }
        composite, breakdown, weights = compute_composite(raw_intel, [], "ip")
        assert composite < 0.11  # Should be CLEAN or LOW
        assert math.isclose(sum(weights.values()), 1.0, abs_tol=1e-9)

    def test_highly_malicious_ip(self):
        raw_intel = {
            "virustotal": {"data": {"attributes": {"last_analysis_stats": {
                "malicious": 80, "suspicious": 10, "harmless": 5, "undetected": 5
            }}}},
            "abuseipdb": {"data": {"abuseConfidenceScore": 100}},
            "otx": {"pulse_info": {"pulses": [{"name": f"p{i}"} for i in range(10)]}},
        }
        composite, breakdown, weights = compute_composite(raw_intel, [], "ip")
        assert composite > 0.75  # Should be CRITICAL

    def test_cve_weights_used(self):
        raw_intel = {
            "otx": {"pulse_info": {"pulses": []}},
            "nvd": {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8}}
            ]}}}]},
        }
        composite, breakdown, weights = compute_composite(raw_intel, [], "cve")
        assert "nvd" in weights
        assert "otx" in weights
        assert "virustotal" not in weights
        assert "abuseipdb" not in weights
        # NVD 9.8/10 = 0.98, OTX 0 pulses = 0.0
        # composite = 0.98 * 0.6 + 0.0 * 0.4 = 0.588
        assert composite > 0.55

    def test_no_sources_defaults_low(self):
        composite, breakdown, weights = compute_composite({}, ["all failed"], "ip")
        assert 0.10 < composite < 0.31  # LOW range


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestConflictDetection:
    """Test conflicting signal detection."""

    def test_no_conflicts_when_all_clean(self):
        breakdown = {"virustotal": 0.0, "otx": 0.0, "abuseipdb": 0.0}
        assert detect_conflicts(breakdown) == []

    def test_no_conflicts_when_all_bad(self):
        breakdown = {"virustotal": 0.8, "otx": 0.6}
        assert detect_conflicts(breakdown) == []

    def test_conflict_detected(self):
        breakdown = {"virustotal": 0.0, "otx": 0.6}
        conflicts = detect_conflicts(breakdown)
        assert len(conflicts) == 1
        assert "VirusTotal" in conflicts[0]
        assert "OTX" in conflicts[0]

    def test_multiple_conflicts(self):
        breakdown = {"virustotal": 0.0, "otx": 0.6, "abuseipdb": 0.8}
        conflicts = detect_conflicts(breakdown)
        assert len(conflicts) == 2

    def test_single_source_no_conflict(self):
        assert detect_conflicts({"virustotal": 0.5}) == []

    def test_borderline_no_conflict(self):
        # 0.25 is not clean enough (<= 0.20) and 0.45 is not bad enough (>= 0.50)
        assert detect_conflicts({"virustotal": 0.25, "otx": 0.45}) == []


class TestVTDetectionExtraction:
    """Test VirusTotal per-engine detection name extraction."""

    def test_extracts_malicious_names(self):
        raw = {"data": {"attributes": {"last_analysis_results": {
            "Kaspersky": {"category": "malicious", "result": "Trojan.Win32.Agent"},
            "CrowdStrike": {"category": "malicious", "result": "Win/malicious_confidence_90%"},
            "McAfee": {"category": "undetected", "result": None},
        }}}}
        names = extract_vt_detections(raw)
        assert len(names) == 2
        assert "Kaspersky: Trojan.Win32.Agent" in names

    def test_extracts_suspicious(self):
        raw = {"data": {"attributes": {"last_analysis_results": {
            "EngineA": {"category": "suspicious", "result": "PUP.Generic"},
        }}}}
        names = extract_vt_detections(raw)
        assert len(names) == 1

    def test_empty_when_clean(self):
        raw = {"data": {"attributes": {"last_analysis_results": {
            "EngineA": {"category": "undetected", "result": None},
        }}}}
        assert extract_vt_detections(raw) == []

    def test_limits_results(self):
        results = {}
        for i in range(20):
            results[f"Engine{i}"] = {"category": "malicious", "result": f"Malware.{i}"}
        raw = {"data": {"attributes": {"last_analysis_results": results}}}
        names = extract_vt_detections(raw, max_names=5)
        assert len(names) == 5

    def test_deduplicates_result_names(self):
        raw = {"data": {"attributes": {"last_analysis_results": {
            "EngineA": {"category": "malicious", "result": "Trojan.Generic"},
            "EngineB": {"category": "malicious", "result": "Trojan.Generic"},
            "EngineC": {"category": "malicious", "result": "Worm.Different"},
        }}}}
        names = extract_vt_detections(raw)
        # Should have 2 unique results, not 3
        assert len(names) == 2


class TestOTXCampaignExtraction:
    """Test OTX adversary and campaign extraction."""

    def test_extracts_adversaries(self):
        raw = {"pulse_info": {"pulses": [
            {"name": "APT28 Campaign", "adversary": "APT28", "tags": ["phishing"]},
            {"name": "Other Pulse", "adversary": "", "tags": ["malware"]},
        ]}}
        result = extract_otx_campaigns(raw)
        assert result["adversaries"] == ["APT28"]
        assert "phishing" in result["tags"]
        assert "malware" in result["tags"]
        assert len(result["pulse_names"]) == 2

    def test_empty_pulses(self):
        raw = {"pulse_info": {"pulses": []}}
        result = extract_otx_campaigns(raw)
        assert result["adversaries"] == []
        assert result["tags"] == []
        assert result["pulse_names"] == []


class TestNVDDetailExtraction:
    """Test NVD CVSS severity and attack vector extraction."""

    def test_extracts_v31(self):
        raw = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "attackVector": "NETWORK"}}
        ]}, "descriptions": [{"value": "Bad vuln", "lang": "en"}]}}]}
        result = extract_nvd_details(raw)
        assert result["base_score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert result["vector"] == "NETWORK"
        assert "Bad vuln" in result["description"]

    def test_awaiting_analysis(self):
        raw = {"vulnerabilities": [{"cve": {"metrics": {},
            "descriptions": [{"value": "Awaiting analysis", "lang": "en"}]}}]}
        result = extract_nvd_details(raw)
        assert result["severity"] == "N/A"
        assert result["base_score"] == 0.0

    def test_no_vulnerabilities(self):
        raw = {"vulnerabilities": []}
        result = extract_nvd_details(raw)
        assert result["severity"] == "N/A"


class TestTLDR:
    """Test TL;DR summary generation."""

    def test_clean_ip(self):
        tldr = generate_tldr("8.8.8.8", "ip", "CLEAN", 0.05, {"virustotal": 0.0, "otx": 0.0}, {}, [])
        assert "Clean" in tldr
        assert "IP" in tldr

    def test_malicious_hash(self):
        raw_intel = {"virustotal": {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 50, "suspicious": 5, "harmless": 30, "undetected": 15
        }}}}}
        tldr = generate_tldr(
            "abc123", "hash_md5", "CRITICAL", 0.95,
            {"virustotal": 1.0}, raw_intel, [],
        )
        assert "malicious" in tldr.lower() or "Confirmed" in tldr
        assert "50/" in tldr

    def test_partial_data_noted(self):
        tldr = generate_tldr(
            "1.2.3.4", "ip", "LOW", 0.2,
            {"otx": 0.0}, {}, ["virustotal: error"],
        )
        assert "1 of 2" in tldr

    def test_cve_with_cvss(self):
        raw_intel = {"nvd": {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "attackVector": "NETWORK"}}
        ]}, "descriptions": [{"value": "test"}]}}]}}
        tldr = generate_tldr(
            "CVE-2021-44228", "cve", "CRITICAL", 0.95,
            {"nvd": 0.98}, raw_intel, [],
        )
        assert "CVSS" in tldr or "9.8" in tldr


class TestOSVNormaliser:
    """OSV.dev normaliser tests."""

    def test_malware_advisory(self):
        raw = {"vulns": [{"id": "MAL-2024-1234", "summary": "Malicious package"}]}
        assert normalise_osv(raw) == 1.0

    def test_critical_severity(self):
        raw = {"vulns": [{"id": "GHSA-1234", "database_specific": {"severity": "CRITICAL"}}]}
        assert normalise_osv(raw) == 0.90

    def test_high_severity(self):
        raw = {"vulns": [{"id": "GHSA-5678", "database_specific": {"severity": "HIGH"}}]}
        assert normalise_osv(raw) == 0.70

    def test_no_vulns(self):
        raw = {"vulns": []}
        assert normalise_osv(raw) == 0.0

    def test_empty_response(self):
        assert normalise_osv({}) == 0.0

    def test_vuln_without_severity(self):
        raw = {"vulns": [{"id": "GHSA-9999", "summary": "Some vuln"}]}
        assert normalise_osv(raw) == 0.50


class TestRegistryNormaliser:
    """Package registry normaliser tests."""

    def test_install_scripts_flagged(self):
        raw = {"source": "npm", "has_install_scripts": True, "created": "2020-01-01T00:00:00Z"}
        score = normalise_registry(raw)
        assert score >= 0.40

    def test_clean_established_package(self):
        raw = {"ecosystem": "npm", "has_install_scripts": False, "created": "2018-01-01T00:00:00Z",
               "maintainers": ["alice", "bob", "carol", "dave", "eve"],
               "repository": "https://github.com/example/pkg"}
        assert normalise_registry(raw) == 0.0

    def test_new_package_flagged(self):
        from datetime import datetime, timezone, timedelta
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        raw = {"ecosystem": "npm", "has_install_scripts": False, "created": yesterday,
               "maintainers": ["newuser"], "repository": "https://github.com/x/y"}
        score = normalise_registry(raw)
        assert score >= 0.30  # new + single maintainer

    def test_unsupported_ecosystem(self):
        raw = {"_unsupported": True}
        assert normalise_registry(raw) == 0.0

    def test_pypi_no_source_repo(self):
        raw = {"ecosystem": "pypi", "repository": None, "created": "2020-01-01T00:00:00Z",
               "maintainers": ["someone"]}
        score = normalise_registry(raw)
        assert score >= 0.10


class TestOSVDetailExtraction:
    """Test OSV detail extraction."""

    def test_malware_detected(self):
        raw = {"vulns": [{"id": "MAL-2024-1234", "summary": "Trojan", "database_specific": {}}]}
        result = extract_osv_details(raw)
        assert result["is_malware"] is True
        assert result["vuln_count"] == 1

    def test_multiple_advisories(self):
        raw = {"vulns": [
            {"id": "GHSA-1", "summary": "XSS", "database_specific": {"severity": "HIGH"}},
            {"id": "GHSA-2", "summary": "RCE", "database_specific": {"severity": "CRITICAL"}},
        ]}
        result = extract_osv_details(raw)
        assert result["vuln_count"] == 2
        assert result["max_severity"] == "CRITICAL"


class TestPackageComposite:
    """Test package IOC type composite scoring."""

    def test_malware_package_critical(self):
        raw_intel = {
            "osv": {"vulns": [{"id": "MAL-2024-1234", "summary": "Malicious"}]},
            "registry": {"source": "npm", "has_install_scripts": True,
                         "created": "2024-12-01T00:00:00Z", "maintainer_count": 1},
        }
        composite, breakdown, weights = compute_composite(raw_intel, [], "package")
        assert composite > 0.75  # Should be CRITICAL
        assert "osv" in weights
        assert "registry" in weights

    def test_clean_package(self):
        raw_intel = {
            "osv": {"vulns": []},
            "registry": {"source": "npm", "has_install_scripts": False,
                         "created": "2018-01-01T00:00:00Z", "maintainer_count": 10},
        }
        composite, breakdown, weights = compute_composite(raw_intel, [], "package")
        assert composite < 0.11  # Should be CLEAN


class TestOSVMultiNormaliser:
    """Test multi-ecosystem OSV scan normalisation."""

    def test_malware_in_any_ecosystem(self):
        raw = {
            "has_malware": True,
            "results": {
                "npm": {"vulns": []},
                "PyPI": {"vulns": [{"id": "MAL-2024-5678"}]},
            },
        }
        assert normalise_osv_multi(raw) == 1.00

    def test_vuln_in_one_ecosystem(self):
        raw = {
            "has_malware": False,
            "results": {
                "npm": {"vulns": []},
                "PyPI": {"vulns": [{"id": "PYSEC-2024-123", "database_specific": {"severity": "HIGH"}}]},
                "Go": {"vulns": []},
            },
        }
        score = normalise_osv_multi(raw)
        assert score >= 0.50

    def test_clean_across_all(self):
        raw = {
            "has_malware": False,
            "results": {
                "npm": {"vulns": []},
                "PyPI": {"vulns": []},
                "Go": {"vulns": []},
            },
        }
        assert normalise_osv_multi(raw) == 0.0

    def test_empty_results(self):
        raw = {"has_malware": False, "results": {}}
        assert normalise_osv_multi(raw) == 0.0


class TestPackageMultiWeights:
    """PACKAGE_MULTI_WEIGHTS must sum to 1.00."""

    def test_package_multi_weights_sum(self):
        assert math.isclose(sum(PACKAGE_MULTI_WEIGHTS.values()), 1.0, abs_tol=1e-9)

    def test_package_multi_weights_sources(self):
        assert set(PACKAGE_MULTI_WEIGHTS.keys()) == {"osv_multi"}


class TestPackageMultiComposite:
    """Test composite scoring for package_multi type."""

    def test_malware_multi_critical(self):
        raw_intel = {
            "osv_multi": {
                "has_malware": True,
                "package_name": "evil-pkg",
                "ecosystems_scanned": ["npm", "PyPI"],
                "ecosystems_with_hits": ["PyPI"],
                "total_vulns": 1,
                "results": {
                    "npm": {"vulns": []},
                    "PyPI": {"vulns": [{"id": "MAL-2024-9999"}]},
                },
            },
        }
        composite, breakdown, weights = compute_composite(raw_intel, [], "package_multi")
        assert composite >= 0.76  # CRITICAL
        assert "osv_multi" in weights

    def test_clean_multi(self):
        raw_intel = {
            "osv_multi": {
                "has_malware": False,
                "package_name": "safe-pkg",
                "ecosystems_scanned": ["npm", "PyPI", "Go"],
                "ecosystems_with_hits": [],
                "total_vulns": 0,
                "results": {
                    "npm": {"vulns": []},
                    "PyPI": {"vulns": []},
                    "Go": {"vulns": []},
                },
            },
        }
        composite, breakdown, weights = compute_composite(raw_intel, [], "package_multi")
        assert composite <= 0.10  # CLEAN
