# agent/tools/osv.py
# ─────────────────────────────────────────────────────────────────────────────
# LangChain Tools: OSV.dev (Google Open Source Vulnerability database)
# - OSVTool: Single-ecosystem query for prefixed package IOCs (npm:pkg)
# - OSVMultiTool: Multi-ecosystem scan for bare package names (traceroute)
# No API key required.
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from agent.tools.base import ThreatIntelTool
from agent.integrations.osv import (
    parse_package_ioc,
    build_osv_query,
    build_osv_query_raw,
    parse_osv_response,
    MULTI_SCAN_ECOSYSTEMS,
)


OSV_API_URL = "https://api.osv.dev/v1/query"


class OSVTool(ThreatIntelTool):
    """Query OSV.dev for a single ecosystem:package pair."""
    name: str = "osv"
    description: str = "Query OSV.dev for known vulnerabilities and malicious package advisories."
    base_url: str = OSV_API_URL

    async def _fetch(self, client: httpx.AsyncClient, ioc: str) -> dict:
        ecosystem, package_name = parse_package_ioc(ioc)
        query_body = build_osv_query(ecosystem, package_name)
        resp = await client.post(
            self.base_url,
            json=query_body,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return parse_osv_response(resp.json())


class OSVMultiTool(ThreatIntelTool):
    """
    Scan a bare package name across all major ecosystems in parallel.

    Input: a bare package name like "traceroute" (no ecosystem prefix).
    Queries OSV.dev for that name across npm, PyPI, crates.io, Go, Maven,
    NuGet, RubyGems, Packagist, Pub, and Hex simultaneously.

    Returns: {
        "package_name": "traceroute",
        "ecosystems_scanned": ["npm", "PyPI", ...],
        "results": {
            "npm": {"vulns": [...]},
            "PyPI": {"vulns": [{"id": "MAL-2024-5678", ...}]},
            ...
        },
        "ecosystems_with_hits": ["PyPI"],
        "total_vulns": 1,
        "has_malware": True,
    }
    """
    name: str = "osv_multi"
    description: str = "Scan a package name across all major ecosystems for vulnerabilities."
    base_url: str = OSV_API_URL

    async def _fetch(self, client: httpx.AsyncClient, package_name: str) -> dict:
        # Build one query per ecosystem
        queries: dict[str, dict] = {}
        for eco in MULTI_SCAN_ECOSYSTEMS:
            queries[eco] = build_osv_query_raw(eco, package_name)

        # Fire all queries in parallel
        async def _query_one(eco: str, body: dict) -> tuple[str, dict]:
            try:
                resp = await client.post(
                    self.base_url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                return eco, parse_osv_response(resp.json())
            except Exception:
                return eco, {"vulns": []}

        tasks = [_query_one(eco, body) for eco, body in queries.items()]
        results_list = await asyncio.gather(*tasks)

        # Assemble results
        results: dict[str, dict] = {}
        ecosystems_with_hits: list[str] = []
        total_vulns = 0
        has_malware = False

        for eco, data in results_list:
            vulns = data.get("vulns", [])
            results[eco] = data
            if vulns:
                ecosystems_with_hits.append(eco)
                total_vulns += len(vulns)
                for v in vulns:
                    if v.get("id", "").startswith("MAL-"):
                        has_malware = True

        return {
            "package_name": package_name,
            "ecosystems_scanned": list(queries.keys()),
            "results": results,
            "ecosystems_with_hits": ecosystems_with_hits,
            "total_vulns": total_vulns,
            "has_malware": has_malware,
        }
