# agent/tools/nvd.py
# ─────────────────────────────────────────────────────────────────────────────
# LangChain Tool: NIST NVD API — CVE IOC type only
# No API key required (unauthenticated, rate-limited to 5 req/30s).
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

from typing import Any

import httpx

from agent.tools.base import ThreatIntelTool
from agent.integrations.nvd import build_nvd_url, parse_nvd_response


class NVDTool(ThreatIntelTool):
    name: str = "nvd"
    description: str = "Query NIST NVD for CVE vulnerability details and CVSS scores."
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def _fetch(self, client: httpx.AsyncClient, ioc: str) -> dict:
        url, params = build_nvd_url(self.base_url, ioc)
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return parse_nvd_response(resp.json())
