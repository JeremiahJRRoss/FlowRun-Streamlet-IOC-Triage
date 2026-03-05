# agent/tools/otx.py
# ─────────────────────────────────────────────────────────────────────────────
# LangChain Tool: AlienVault OTX API v1
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import os
from typing import Any

import httpx

from agent.tools.base import ThreatIntelTool
from agent.integrations.otx import build_otx_url, parse_otx_response


class OTXTool(ThreatIntelTool):
    name: str = "otx"
    description: str = "Query AlienVault OTX for threat intelligence pulses and campaign tags."
    base_url: str = "https://otx.alienvault.com/api/v1/indicators"

    # OTX needs to know the IOC type to build the correct URL path.
    # We store this at invocation time via the ioc parameter format: "type:value"
    # However, to keep the interface clean, the enrichment_node passes just the
    # IOC value — OTX integration module auto-detects the type from the value.

    async def _fetch(self, client: httpx.AsyncClient, ioc: str) -> dict:
        api_key = os.getenv("OTX_API_KEY", "")
        url = build_otx_url(self.base_url, ioc)
        headers = {"X-OTX-API-KEY": api_key}
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return parse_otx_response(resp.json())
