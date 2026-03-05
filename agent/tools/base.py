# agent/tools/base.py
# ─────────────────────────────────────────────────────────────────────────────
# Abstract base class for all threat intelligence tool wrappers.
# Implements exponential backoff retry: attempt 1 immediately,
# attempt 2 after 1.5s, attempt 3 after 3.0s.
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import asyncio
from typing import Any, Optional, Type

import httpx
from langchain.tools import BaseTool
from pydantic import Field


class ThreatIntelTool(BaseTool):
    """Abstract base for all threat intelligence tool wrappers."""

    base_url: str = ""
    max_retries: int = 3
    retry_base_delay: float = 1.5   # seconds — doubles on each retry
    timeout: float = 15.0

    class Config:
        arbitrary_types_allowed = True

    async def _arun(self, ioc: str, **kwargs: Any) -> dict:
        """Async execution with exponential backoff retry."""
        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    return await self._fetch(client, ioc)
            except (httpx.TimeoutException, httpx.HTTPStatusError) as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    delay = self.retry_base_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
        # All retries exhausted — raise the last exception
        raise last_exc  # type: ignore[misc]

    async def _fetch(self, client: httpx.AsyncClient, ioc: str) -> dict:
        """Subclasses must implement the actual API call logic."""
        raise NotImplementedError("Subclasses must implement _fetch()")

    def _run(self, ioc: str, **kwargs: Any) -> dict:
        """Synchronous fallback for non-async contexts."""
        return asyncio.run(self._arun(ioc))
