# agent/integrations/otx.py
# ─────────────────────────────────────────────────────────────────────────────
# Raw HTTP client helpers and response normaliser for AlienVault OTX API v1.
# Endpoint: GET /api/v1/indicators/{type}/{ioc}/general
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import re


def _detect_otx_type(ioc: str) -> str:
    """Map an IOC value to the OTX indicator type path segment."""
    ioc = ioc.strip()

    # CVE
    if re.match(r"^CVE-\d{4}-\d{4,}$", ioc, re.IGNORECASE):
        return "cve"
    # URL
    if re.match(r"^(https?|ftp)://", ioc, re.IGNORECASE):
        return "url"
    # IPv4
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
        return "IPv4"
    # IPv6
    if ":" in ioc and re.match(r"^[0-9a-fA-F:]+$", ioc):
        return "IPv6"
    # File hashes
    if re.match(r"^[0-9a-fA-F]{32}$", ioc):
        return "file"
    if re.match(r"^[0-9a-fA-F]{40}$", ioc):
        return "file"
    if re.match(r"^[0-9a-fA-F]{64}$", ioc):
        return "file"
    # Domain
    if "." in ioc and "/" not in ioc:
        return "domain"

    return "domain"


def build_otx_url(base_url: str, ioc: str) -> str:
    """Build the correct OTX indicator URL for the given IOC."""
    otx_type = _detect_otx_type(ioc)

    if otx_type == "cve":
        return f"{base_url}/cve/{ioc}/general"
    elif otx_type == "url":
        return f"{base_url}/url/{ioc}/general"
    elif otx_type in ("IPv4", "IPv6"):
        return f"{base_url}/{otx_type}/{ioc}/general"
    elif otx_type == "file":
        return f"{base_url}/file/{ioc}/general"
    else:
        return f"{base_url}/domain/{ioc}/general"


def parse_otx_response(raw: dict) -> dict:
    """
    Normalise OTX response.
    Key fields: pulse_info.pulses[].name, tags, adversary
    """
    return raw
