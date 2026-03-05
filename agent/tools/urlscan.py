# agent/tools/urlscan.py
# ─────────────────────────────────────────────────────────────────────────────
# LangChain Tool: urlscan.io API v1 — URL IOC type only
# Two-phase: POST scan submission → poll GET for result (max 30s, 3s interval)
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from agent.tools.base import ThreatIntelTool
from agent.integrations.urlscan import parse_urlscan_response


class URLScanTool(ThreatIntelTool):
    name: str = "urlscan"
    description: str = "Submit URL to urlscan.io for live sandbox analysis and poll for results."
    base_url: str = "https://urlscan.io/api/v1"
    timeout: float = 45.0  # Longer timeout to account for polling

    async def _fetch(self, client: httpx.AsyncClient, url_ioc: str) -> dict:
        api_key = os.getenv("URLSCAN_API_KEY", "")
        headers = {
            "API-Key": api_key,
            "Content-Type": "application/json",
        }

        # Phase 1: Submit scan
        submit_resp = await client.post(
            f"{self.base_url}/scan/",
            headers=headers,
            json={"url": url_ioc, "visibility": "public"},
        )
        submit_resp.raise_for_status()
        uuid = submit_resp.json()["uuid"]

        # Phase 2: Poll for result (max 30s, 3s interval, 10 attempts)
        for _ in range(10):
            await asyncio.sleep(3)
            result_resp = await client.get(
                f"{self.base_url}/result/{uuid}/",
                headers={"API-Key": api_key},
            )
            if result_resp.status_code == 200:
                return parse_urlscan_response(result_resp.json())
            # 404 means not ready yet — keep polling
            if result_resp.status_code != 404:
                result_resp.raise_for_status()

        raise TimeoutError(f"urlscan result not ready for {uuid} after 30s")
