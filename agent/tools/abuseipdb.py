# agent/tools/abuseipdb.py
# ─────────────────────────────────────────────────────────────────────────────
# LangChain Tool: AbuseIPDB API v2 — IP addresses only
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import os
from typing import Any

import httpx

from agent.tools.base import ThreatIntelTool
from agent.integrations.abuseipdb import build_abuseipdb_url, parse_abuseipdb_response


class AbuseIPDBTool(ThreatIntelTool):
    name: str = "abuseipdb"
    description: str = "Query AbuseIPDB for IP abuse confidence score, report count, and abuse categories."
    base_url: str = "https://api.abuseipdb.com/api/v2/check"

    async def _fetch(self, client: httpx.AsyncClient, ioc: str) -> dict:
        api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        url, params = build_abuseipdb_url(self.base_url, ioc)
        headers = {"Key": api_key, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, params=params)
        resp.raise_for_status()
        return parse_abuseipdb_response(resp.json())
