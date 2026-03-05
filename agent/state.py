# agent/state.py
# ─────────────────────────────────────────────────────────────────────────────
# AgentState — shared memory for all LangGraph nodes.
# Every node receives the full state and returns a partial dict of updates.
# ─────────────────────────────────────────────────────────────────────────────

from typing import TypedDict, Any


class AgentState(TypedDict):
    # ── INPUT ──────────────────────────────────────────────────
    ioc_raw: str                        # Exact string from user input
    ioc_clean: str                      # Normalised (stripped, lowercased domain/url, uppercased hash/CVE)
    ioc_type: str                       # 'ip' | 'domain' | 'url' | 'hash_md5' |
                                        # 'hash_sha1' | 'hash_sha256' | 'cve' | 'unknown'

    # ── ENRICHMENT ─────────────────────────────────────────────
    raw_intel: dict[str, Any]           # {source_name: parsed_response_dict}
    intel_errors: list[str]             # Non-fatal: ["abuseipdb: TimeoutError: ...", ...]

    # ── SCORING ────────────────────────────────────────────────
    score_breakdown: dict[str, float]   # Per-source normalised 0.0–1.0 scores
    composite_score: float              # Weighted aggregate
    active_weights: dict[str, float]    # Re-normalised if sources unavailable

    # ── VERDICT ────────────────────────────────────────────────
    severity_band: str                  # 'CLEAN'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'
    verdict_justification: str          # Plain-English explanation of verdict
    escalation_required: bool           # True only when severity_band == 'CRITICAL'

    # ── OUTPUT ─────────────────────────────────────────────────
    report_text: str                    # CLI-formatted threat report
    report_html: str                    # HTML-formatted report for Jupyter
    arize_trace_url: str                # Direct URL to trace in Arize UI
