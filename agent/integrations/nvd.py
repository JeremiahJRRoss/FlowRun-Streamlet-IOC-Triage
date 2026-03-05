# agent/integrations/nvd.py
# ─────────────────────────────────────────────────────────────────────────────
# Raw HTTP client helpers and response normaliser for NIST NVD API.
# Endpoint: GET /rest/json/cves/2.0?cveId={cve}
# No API key required (unauthenticated, rate-limited: 5 req/30s).
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations


def build_nvd_url(base_url: str, cve_id: str) -> tuple[str, dict]:
    """Return (url, query_params) for NVD CVE lookup."""
    params = {"cveId": cve_id.upper()}
    return base_url, params


def parse_nvd_response(raw: dict) -> dict:
    """
    Normalise NVD response.
    Key fields: vulnerabilities[0].cve.metrics.cvssMetricV31,
    vulnerabilities[0].cve.descriptions, vulnerabilities[0].cve.weaknesses
    """
    return raw
