# agent/tools/virustotal.py
# ─────────────────────────────────────────────────────────────────────────────
# LangChain Tool: VirusTotal API v3
# Supports: IP, domain, URL, file hash (MD5/SHA-1/SHA-256), CVE
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import os
from typing import Any

import httpx

from agent.tools.base import ThreatIntelTool
from agent.integrations.virustotal import build_vt_url, parse_vt_response


class VirusTotalTool(ThreatIntelTool):
    name: str = "virustotal"
    description: str = "Query VirusTotal API v3 for IOC reputation data across 90+ engines."
    base_url: str = "https://www.virustotal.com/api/v3"

    async def _fetch(self, client: httpx.AsyncClient, ioc: str) -> dict:
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        url = build_vt_url(self.base_url, ioc)
        headers = {"x-apikey": api_key}
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return parse_vt_response(resp.json())
