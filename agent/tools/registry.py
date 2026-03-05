# agent/tools/registry.py
# ─────────────────────────────────────────────────────────────────────────────
# LangChain Tool: Package registry metadata (npm, PyPI)
# No API key required. Extracts age, maintainers, install scripts, etc.
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

from typing import Any

import httpx

from agent.tools.base import ThreatIntelTool
from agent.integrations.osv import parse_package_ioc
from agent.integrations.registry import build_registry_url, parse_registry_response


class RegistryTool(ThreatIntelTool):
    name: str = "registry"
    description: str = "Query package registry (npm/PyPI) for metadata: age, maintainers, install scripts."
    base_url: str = ""  # URL built dynamically per ecosystem

    async def _fetch(self, client: httpx.AsyncClient, ioc: str) -> dict:
        ecosystem, package_name = parse_package_ioc(ioc)
        try:
            url = build_registry_url(ecosystem, package_name)
        except ValueError:
            # Ecosystem not supported for registry lookup — return empty
            return {"_unsupported": True, "ecosystem": ecosystem, "name": package_name}
        resp = await client.get(url)
        resp.raise_for_status()
        return parse_registry_response(ecosystem, resp.json())
