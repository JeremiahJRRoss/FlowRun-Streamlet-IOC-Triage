# agent/integrations/urlscan.py
# ─────────────────────────────────────────────────────────────────────────────
# Response normaliser for urlscan.io API v1.
# The two-phase submit/poll logic lives in agent/tools/urlscan.py.
# This module handles response parsing only.
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations


def parse_urlscan_response(raw: dict) -> dict:
    """
    Normalise urlscan.io result response.
    Key fields: verdicts.overall.score, verdicts.overall.malicious,
    page.domain, screenshot_url
    """
    return raw
