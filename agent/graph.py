# agent/graph.py
# ─────────────────────────────────────────────────────────────────────────────
# LangGraph StateGraph — all nodes, edges, and conditional routing.
# This is the core orchestration module for the IoC Triage agent.
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import asyncio
import json
import re
import sys
from typing import Any
from urllib.parse import urlparse

from langgraph.graph import StateGraph, END

from agent.state import AgentState
from agent.llm import get_llm, CLASSIFIER_SYSTEM
from agent.scoring import (
    compute_composite, score_to_severity,
    normalise_virustotal, normalise_otx, normalise_urlscan,
)
from agent.report import format_cli_report, format_html_report

# Tool imports — instantiated once at module level
from agent.tools.virustotal import VirusTotalTool
from agent.tools.abuseipdb import AbuseIPDBTool
from agent.tools.otx import OTXTool
from agent.tools.urlscan import URLScanTool
from agent.tools.nvd import NVDTool
from agent.tools.osv import OSVTool, OSVMultiTool
from agent.tools.registry import RegistryTool

vt_tool = VirusTotalTool()
abuseipdb_tool = AbuseIPDBTool()
otx_tool = OTXTool()
urlscan_tool = URLScanTool()
nvd_tool = NVDTool()
osv_tool = OSVTool()
osv_multi_tool = OSVMultiTool()
registry_tool = RegistryTool()


# ── Regex pre-classification ──────────────────────────────────────────────────

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{3,}$")
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_URL_RE = re.compile(r"^(https?|ftp)://", re.IGNORECASE)
# Prefixed package: ecosystem:name format (all supported ecosystems)
_PACKAGE_RE = re.compile(
    r"^(npm|pypi|pip|crates|cargo|go|maven|nuget|rubygems|gem|packagist|composer"
    r"|pub|hex|hackage|cran|swifturl|cocoapods"
    r"|rhel|redhat|debian|ubuntu|alpine|rocky|alma|suse|opensuse"
    r"|android|linux|bitnami|curl)"
    r":[\w./@-]+$",
    re.IGNORECASE,
)
# Bare package name: alphanumeric + hyphens/underscores, 2-80 chars, no dots
# (dots would be a domain). Must start with a letter.
# Examples: traceroute, postmark-mcp, my_package, express
_BARE_PACKAGE_RE = re.compile(r"^[a-zA-Z][\w-]{1,79}$")
# Domain: one or more labels separated by dots, ending in a 2-63 char TLD,
# no scheme, no path, no whitespace. Must contain at least one dot.
_DOMAIN_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,63}$"
)


def _regex_classify(ioc: str) -> str | None:
    """Fast regex pre-check. Returns IOC type or None if inconclusive."""
    if _PACKAGE_RE.match(ioc):
        return "package"
    if _CVE_RE.match(ioc):
        return "cve"
    if _URL_RE.match(ioc):
        return "url"
    if _IPV4_RE.match(ioc):
        # Validate octets
        parts = ioc.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return "ip"
    if _IPV6_RE.match(ioc) and ":" in ioc:
        return "ip"
    if _SHA256_RE.match(ioc):
        return "hash_sha256"
    if _SHA1_RE.match(ioc):
        return "hash_sha1"
    if _MD5_RE.match(ioc):
        return "hash_md5"
    # Domain check before bare package — domains have dots
    if _DOMAIN_RE.match(ioc):
        return "domain"
    # Bare package name: no dots, no scheme, no hash pattern — last check
    if _BARE_PACKAGE_RE.match(ioc):
        return "package_multi"
    return None


def _normalise_ioc(ioc: str, ioc_type: str) -> str:
    """Normalise IOC value based on detected type."""
    if ioc_type in ("domain", "url"):
        return ioc.lower()
    if ioc_type.startswith("hash_"):
        return ioc.upper()
    if ioc_type == "cve":
        return ioc.upper()
    if ioc_type == "package":
        # Normalise ecosystem prefix to lowercase, keep package name as-is
        eco, _, name = ioc.partition(":")
        return f"{eco.lower()}:{name}"
    if ioc_type == "package_multi":
        return ioc.lower()
    return ioc


# ── Node Functions ────────────────────────────────────────────────────────────

async def input_node(state: AgentState) -> dict:
    """
    Receive raw IOC string and perform lightweight pre-processing.
    No external calls, no LLM usage — intentionally minimal.
    """
    raw = state.get("ioc_raw", "").strip()
    # Length-limit to prevent injection (max 2048 chars per Architecture doc §13)
    raw = raw[:2048]

    # Attempt regex pre-classification
    pre_type = _regex_classify(raw)
    clean = _normalise_ioc(raw, pre_type) if pre_type else raw

    return {
        "ioc_raw": raw,
        "ioc_clean": clean,
        "ioc_type": pre_type or "pending_llm",
        "raw_intel": {},
        "intel_errors": [],
        "score_breakdown": {},
        "composite_score": 0.0,
        "active_weights": {},
        "severity_band": "",
        "verdict_justification": "",
        "escalation_required": False,
        "report_text": "",
        "report_html": "",
        "arize_trace_url": "",
    }


async def classifier_node(state: AgentState) -> dict:
    """
    Determine IOC type. Uses regex result if available; falls back to
    GPT-5.2 Instant (gpt-5.2-chat-latest, effort=low) for ambiguous cases.
    """
    ioc_type = state.get("ioc_type", "")
    ioc_raw = state.get("ioc_raw", "")

    # If regex already resolved the type, skip LLM call
    if ioc_type and ioc_type != "pending_llm":
        return {"ioc_type": ioc_type, "ioc_clean": state.get("ioc_clean", ioc_raw)}

    # LLM classification
    try:
        llm = get_llm("classifier")
        from langchain_core.messages import SystemMessage, HumanMessage
        from langchain_core.output_parsers import JsonOutputParser

        messages = [
            SystemMessage(content=CLASSIFIER_SYSTEM),
            HumanMessage(content=ioc_raw),
        ]
        parser = JsonOutputParser()
        response = await llm.ainvoke(messages)
        parsed = parser.parse(response.content)

        detected_type = parsed.get("type", "unknown")
        clean_value = parsed.get("clean", ioc_raw)
        confidence = parsed.get("confidence", 0.0)

        # If confidence < 0.6, set type to unknown
        if confidence < 0.6:
            detected_type = "unknown"

        return {"ioc_type": detected_type, "ioc_clean": clean_value}

    except Exception as exc:
        # If LLM call fails, default to unknown → routes to error_node
        print(f"⚠️  Classifier LLM error: {exc}", file=sys.stderr)
        return {"ioc_type": "unknown", "ioc_clean": ioc_raw}


async def enrichment_node(state: AgentState) -> dict:
    """
    Execute all applicable threat intelligence API calls concurrently
    using asyncio.gather(return_exceptions=True).
    This is a single async LangGraph node — NOT multiple parallel graph nodes.

    For URL IOC types, the domain is extracted and queried separately against
    VirusTotal and OTX in addition to the URL-level queries. For each source,
    the response with the stronger threat signal is kept. This catches cases
    where the domain has known-bad reputation even if the specific URL is new.
    """
    ioc_type = state["ioc_type"]
    ioc_clean = state["ioc_clean"]

    # Extract domain from URL (used for dual-query on URL types)
    domain_from_url = None
    if ioc_type == "url":
        try:
            parsed = urlparse(ioc_clean)
            domain_from_url = parsed.hostname or parsed.netloc
            # Strip 'www.' prefix for cleaner domain lookup
            if domain_from_url and domain_from_url.startswith("www."):
                domain_from_url = domain_from_url[4:]
        except Exception:
            pass

    # ── Build task list based on IOC type ──────────────────────────────────
    # Task keys ending in "_domain" are domain-level duplicates for URL types.
    # They'll be merged with the URL-level result before returning.
    tasks: dict[str, Any] = {}

    if ioc_type not in ("cve", "package", "package_multi"):
        tasks["virustotal"] = vt_tool.ainvoke(ioc_clean)

    if ioc_type not in ("package", "package_multi"):
        tasks["otx"] = otx_tool.ainvoke(ioc_clean)

    if ioc_type == "ip":
        tasks["abuseipdb"] = abuseipdb_tool.ainvoke(ioc_clean)

    if ioc_type in ("url", "domain"):
        scan_target = ioc_clean if ioc_type == "url" else f"https://{ioc_clean}"
        tasks["urlscan"] = urlscan_tool.ainvoke(scan_target)

    if ioc_type == "cve":
        tasks["nvd"] = nvd_tool.ainvoke(ioc_clean)

    # Prefixed package IOC: query OSV.dev + package registry
    if ioc_type == "package":
        tasks["osv"] = osv_tool.ainvoke(ioc_clean)
        tasks["registry"] = registry_tool.ainvoke(ioc_clean)

    # Bare package name: multi-ecosystem scan across all major ecosystems
    if ioc_type == "package_multi":
        tasks["osv_multi"] = osv_multi_tool.ainvoke(ioc_clean)

    # For URL types: also query the extracted domain against VT and OTX
    if ioc_type == "url" and domain_from_url:
        tasks["virustotal_domain"] = vt_tool.ainvoke(domain_from_url)
        tasks["otx_domain"] = otx_tool.ainvoke(domain_from_url)

    # ── Execute all tasks concurrently ─────────────────────────────────────
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    raw_intel: dict[str, Any] = {}
    intel_errors: list[str] = []
    for source, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            # Don't report domain-level failures as errors — the URL-level
            # result is the primary; domain-level is supplementary.
            if not source.endswith("_domain"):
                intel_errors.append(f"{source}: {type(result).__name__}: {result}")
        else:
            raw_intel[source] = result

    # ── Merge URL + domain results (keep the worse signal) ─────────────────
    if ioc_type == "url" and domain_from_url:
        _merge_url_domain_results(raw_intel, "virustotal", normalise_virustotal)
        _merge_url_domain_results(raw_intel, "otx", normalise_otx)

    return {"raw_intel": raw_intel, "intel_errors": intel_errors}


def _merge_url_domain_results(
    raw_intel: dict[str, Any],
    source: str,
    normaliser,
) -> None:
    """
    Merge URL-level and domain-level results for a single source.
    Keeps whichever response normalises to a higher (worse) threat score.
    Removes the '_domain' key after merging.
    """
    domain_key = f"{source}_domain"
    url_result = raw_intel.get(source)
    domain_result = raw_intel.pop(domain_key, None)

    if url_result is None and domain_result is not None:
        # Only domain result available — promote it
        raw_intel[source] = domain_result
    elif url_result is not None and domain_result is not None:
        # Both available — keep the one with the stronger signal
        try:
            url_score = normaliser(url_result)
            domain_score = normaliser(domain_result)
            if domain_score > url_score:
                raw_intel[source] = domain_result
        except Exception:
            pass  # Keep URL result on normalisation error


async def correlation_node(state: AgentState) -> dict:
    """
    Transform raw API responses into a composite threat score.
    Pure Python — no LLM calls. Deterministic, fast, unit-testable.
    Custom Arize span for observability.
    """
    try:
        from opentelemetry import trace
        tracer = trace.get_tracer(__name__)
    except ImportError:
        tracer = None

    raw_intel = state.get("raw_intel", {})
    intel_errors = state.get("intel_errors", [])
    ioc_type = state.get("ioc_type", "")

    composite, breakdown, weights = compute_composite(raw_intel, intel_errors, ioc_type)

    # Manual Arize span
    if tracer:
        try:
            with tracer.start_as_current_span("flowrun.correlate") as span:
                for source, score in breakdown.items():
                    span.set_attribute(f"score.{source}", score)
                span.set_attribute("composite.score", composite)
                span.set_attribute("sources.available", str(list(breakdown.keys())))
        except Exception:
            pass  # Tracing failure must not block triage

    return {
        "composite_score": composite,
        "score_breakdown": breakdown,
        "active_weights": weights,
    }


async def severity_node(state: AgentState) -> dict:
    """
    Map composite score to severity band and generate verdict justification.
    """
    try:
        from opentelemetry import trace
        tracer = trace.get_tracer(__name__)
    except ImportError:
        tracer = None

    composite = state.get("composite_score", 0.0)
    breakdown = state.get("score_breakdown", {})
    band = score_to_severity(composite)
    escalation = band == "CRITICAL"

    # Build justification
    parts = []
    for source, score in breakdown.items():
        if score >= 0.7:
            parts.append(f"{source} reported strong threat signals (score: {score:.2f})")
        elif score >= 0.4:
            parts.append(f"{source} reported moderate signals (score: {score:.2f})")
        elif score > 0.0:
            parts.append(f"{source} reported minor signals (score: {score:.2f})")
        else:
            parts.append(f"{source} reported no threat signals")

    intel_errors = state.get("intel_errors", [])
    if intel_errors:
        parts.append(f"{len(intel_errors)} source(s) were unavailable")

    justification = ". ".join(parts) + "." if parts else "No intelligence data available."

    # Manual Arize span
    if tracer:
        try:
            with tracer.start_as_current_span("flowrun.severity") as span:
                span.set_attribute("severity.band", band)
                span.set_attribute("verdict.justification", justification)
                span.set_attribute("escalation.required", escalation)
        except Exception:
            pass

    return {
        "severity_band": band,
        "verdict_justification": justification,
        "escalation_required": escalation,
    }


async def escalation_gate(state: AgentState) -> dict:
    """
    Human-in-the-loop confirmation for CRITICAL verdicts.

    In CLI mode: pauses and requires the analyst to type 'yes' to proceed.
    In Jupyter mode: input() doesn't work inside async widget callbacks,
    so the gate logs a prominent warning and auto-proceeds. The analyst
    sees the CRITICAL banner in the HTML report and can act accordingly.
    """
    ioc = state['ioc_clean']
    score = state['composite_score']

    # Detect if running inside Jupyter
    _in_jupyter = False
    try:
        from IPython import get_ipython
        shell = get_ipython()
        if shell is not None and shell.__class__.__name__ in (
            "ZMQInteractiveShell", "TerminalInteractiveShell"
        ):
            _in_jupyter = True
    except (ImportError, AttributeError):
        pass

    if _in_jupyter:
        # Jupyter mode: can't use input() — auto-proceed with warning
        import sys
        print(
            f"\n🚨 CRITICAL SEVERITY DETECTED — IOC: {ioc} — Score: {score:.3f}\n"
            f"   Auto-proceeding to report. Review the findings carefully.\n",
            file=sys.stderr,
        )
        return {}

    # CLI mode: interactive confirmation
    print("\n⚠️  CRITICAL SEVERITY DETECTED")
    print(f"   IOC: {ioc}")
    print(f"   Score: {score:.3f}")
    print("\nThis verdict will trigger immediate blocking recommendations.")
    try:
        confirm = input("Proceed? (yes / abort): ").strip().lower()
    except EOFError:
        # Non-interactive environment (piped input, CI, etc.) — auto-proceed
        return {}
    if confirm != "yes":
        raise SystemExit("Triage aborted by analyst at escalation gate.")
    return {}  # No state changes — pass through to report_node


async def report_node(state: AgentState) -> dict:
    """
    Format final threat report (CLI text + HTML for Jupyter).
    Uses GPT-5.2 Thinking (effort=medium) for the verdict justification
    synthesis if raw intel is available, otherwise uses the pre-computed
    justification from severity_node.
    """
    ioc_clean = state.get("ioc_clean", "")
    ioc_type = state.get("ioc_type", "")
    severity_band = state.get("severity_band", "")
    composite_score = state.get("composite_score", 0.0)
    raw_intel = state.get("raw_intel", {})
    intel_errors = state.get("intel_errors", [])
    score_breakdown = state.get("score_breakdown", {})
    active_weights = state.get("active_weights", {})

    # Attempt LLM-enhanced justification if we have raw intel data
    verdict_justification = state.get("verdict_justification", "")
    if raw_intel:
        try:
            llm = get_llm("report")
            from langchain_core.messages import SystemMessage, HumanMessage

            report_prompt = f"""You are a security analyst writing the correlation summary for a threat report.

IOC: {ioc_clean} (type: {ioc_type})
Severity: {severity_band} (composite score: {composite_score:.3f})

Raw intelligence data (summarised per source):
{json.dumps({k: str(v)[:500] for k, v in raw_intel.items()}, indent=2)}

Score breakdown: {json.dumps(score_breakdown)}
Errors: {intel_errors}

Write a concise 2-4 sentence correlation summary explaining why this IOC received this severity.
Cite specific signals from named sources. Be factual and direct.
Do not include recommendations — only explain the verdict."""

            messages = [
                SystemMessage(content="You are a senior threat intelligence analyst."),
                HumanMessage(content=report_prompt),
            ]
            response = await llm.ainvoke(messages)
            verdict_justification = response.content.strip()
        except Exception as exc:
            # Fall back to pre-computed justification if LLM fails
            print(f"⚠️  Report LLM error (using fallback): {exc}", file=sys.stderr)

    # Build Arize trace URL (placeholder — actual URL depends on Arize setup)
    arize_trace_url = "https://app.arize.com"

    # Format CLI report
    report_text = format_cli_report(
        ioc_clean=ioc_clean,
        ioc_type=ioc_type,
        severity_band=severity_band,
        composite_score=composite_score,
        raw_intel=raw_intel,
        verdict_justification=verdict_justification,
        intel_errors=intel_errors,
        arize_trace_url=arize_trace_url,
        score_breakdown=score_breakdown,
        active_weights=active_weights,
    )

    # Format HTML report
    report_html = format_html_report(
        ioc_clean=ioc_clean,
        ioc_type=ioc_type,
        severity_band=severity_band,
        composite_score=composite_score,
        raw_intel=raw_intel,
        verdict_justification=verdict_justification,
        intel_errors=intel_errors,
        arize_trace_url=arize_trace_url,
        score_breakdown=score_breakdown,
        active_weights=active_weights,
    )

    return {
        "report_text": report_text,
        "report_html": report_html,
        "arize_trace_url": arize_trace_url,
        "verdict_justification": verdict_justification,
    }


async def error_node(state: AgentState) -> dict:
    """
    Handle unrecognised IOC types. Produces a clear error report and exits.
    """
    ioc_raw = state.get("ioc_raw", "")
    error_text = (
        f"\n❌ ERROR: Unable to classify IOC: '{ioc_raw}'\n"
        f"   The input could not be identified as a valid IP address, domain, URL,\n"
        f"   file hash (MD5/SHA-1/SHA-256), or CVE identifier.\n"
        f"   Please check the input and try again.\n"
    )
    error_html = (
        f'<div style="border:2px solid #e74c3c; border-radius:8px; padding:16px; margin:8px 0;">'
        f'<h3 style="color:#e74c3c;">❌ Classification Error</h3>'
        f'<p>Unable to classify IOC: <code>{ioc_raw}</code></p>'
        f'<p>The input could not be identified as a valid IP address, domain, URL, '
        f'file hash (MD5/SHA-1/SHA-256), or CVE identifier.</p>'
        f'<p>Please check the input and try again.</p></div>'
    )
    return {
        "report_text": error_text,
        "report_html": error_html,
        "severity_band": "UNKNOWN",
    }


# ── Conditional Edge Functions ────────────────────────────────────────────────

def route_after_classify(state: AgentState) -> str:
    """Route to error node if IOC type could not be determined."""
    return "error" if state.get("ioc_type") == "unknown" else "enrich"


def route_after_severity(state: AgentState) -> str:
    """Route to human escalation gate for CRITICAL verdicts only."""
    return "escalation" if state.get("severity_band") == "CRITICAL" else "report"


# ── Graph Builder ─────────────────────────────────────────────────────────────

def build_graph():
    """
    Build and compile the LangGraph StateGraph for IoC Triage.

    Graph topology:
        input → classify → [unknown? → error → END]
                          → [else → enrich → correlate → severity]
                            → [CRITICAL? → escalation → report → END]
                            → [else → report → END]
    """
    graph = StateGraph(AgentState)

    # Register nodes
    graph.add_node("input", input_node)
    graph.add_node("classify", classifier_node)
    graph.add_node("enrich", enrichment_node)
    graph.add_node("correlate", correlation_node)
    graph.add_node("severity", severity_node)
    graph.add_node("report", report_node)
    graph.add_node("escalation", escalation_gate)
    graph.add_node("error", error_node)

    # Linear edges
    graph.add_edge("input", "classify")
    graph.add_edge("enrich", "correlate")
    graph.add_edge("correlate", "severity")
    graph.add_edge("escalation", "report")
    graph.add_edge("report", END)
    graph.add_edge("error", END)

    # Conditional: unknown IOC type → error; all others → enrich
    graph.add_conditional_edges(
        "classify",
        route_after_classify,
        {"enrich": "enrich", "error": "error"},
    )

    # Conditional: CRITICAL → escalation gate; all others → report
    graph.add_conditional_edges(
        "severity",
        route_after_severity,
        {"escalation": "escalation", "report": "report"},
    )

    graph.set_entry_point("input")
    return graph.compile()
