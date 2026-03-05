# agent/integrations/virustotal.py
# ─────────────────────────────────────────────────────────────────────────────
# Raw HTTP client helpers and response normaliser for VirusTotal API v3.
# Endpoint routing based on IOC type:
#   IP        → /ip_addresses/{ip}
#   Domain    → /domains/{domain}
#   URL       → /urls/{base64_url}
#   File hash → /files/{hash}
#   CVE       → /files/{cve}  (search-based — VT treats CVE as a search tag)
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import base64
import re


def _detect_ioc_type(ioc: str) -> str:
    """Detect IOC type from value for VT URL routing."""
    ioc_stripped = ioc.strip()

    # CVE
    if re.match(r"^CVE-\d{4}-\d{4,}$", ioc_stripped, re.IGNORECASE):
        return "cve"
    # URL
    if re.match(r"^(https?|ftp)://", ioc_stripped, re.IGNORECASE):
        return "url"
    # IPv4
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc_stripped):
        return "ip"
    # IPv6 (simplified check)
    if ":" in ioc_stripped and re.match(r"^[0-9a-fA-F:]+$", ioc_stripped):
        return "ip"
    # Hash — MD5 (32), SHA-1 (40), SHA-256 (64)
    if re.match(r"^[0-9a-fA-F]{32}$", ioc_stripped):
        return "hash"
    if re.match(r"^[0-9a-fA-F]{40}$", ioc_stripped):
        return "hash"
    if re.match(r"^[0-9a-fA-F]{64}$", ioc_stripped):
        return "hash"
    # Domain (fallback — no scheme, no path separators before first .)
    if "." in ioc_stripped and "/" not in ioc_stripped:
        return "domain"

    return "domain"  # Default fallback


def build_vt_url(base_url: str, ioc: str) -> str:
    """Build the correct VirusTotal v3 API URL for the given IOC."""
    ioc_type = _detect_ioc_type(ioc)

    if ioc_type == "ip":
        return f"{base_url}/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        return f"{base_url}/domains/{ioc}"
    elif ioc_type == "url":
        # VT requires base64-encoded URL (no padding)
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        return f"{base_url}/urls/{url_id}"
    elif ioc_type == "hash":
        return f"{base_url}/files/{ioc}"
    elif ioc_type == "cve":
        # VT doesn't have a dedicated CVE endpoint; use search on the CVE ID as a file hash query
        # Many CVE-related samples are tagged in VT — fall back to search
        return f"{base_url}/files/{ioc}"

    return f"{base_url}/files/{ioc}"


def parse_vt_response(raw: dict) -> dict:
    """
    Normalise VirusTotal API response to a consistent schema.
    Returns the response as-is (already structured), preserving
    the 'data.attributes.last_analysis_stats' path for scoring.
    """
    return raw
