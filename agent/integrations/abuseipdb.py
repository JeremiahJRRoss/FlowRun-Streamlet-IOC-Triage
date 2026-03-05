# agent/integrations/abuseipdb.py
# ─────────────────────────────────────────────────────────────────────────────
# Raw HTTP client helpers and response normaliser for AbuseIPDB API v2.
# Endpoint: GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations


def build_abuseipdb_url(base_url: str, ip: str) -> tuple[str, dict]:
    """Return (url, query_params) for AbuseIPDB check endpoint."""
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": "true",
    }
    return base_url, params


def parse_abuseipdb_response(raw: dict) -> dict:
    """
    Normalise AbuseIPDB response.
    Key fields: data.abuseConfidenceScore, data.totalReports,
    data.countryCode, data.usageType
    """
    return raw
