# agent/report.py
# ─────────────────────────────────────────────────────────────────────────────
# Report formatting — CLI plain-text and HTML (Jupyter) report renderers.
#
# v0.0.26 enhancements:
#   1. Per-engine AV detection names for hash IOCs
#   2. OTX adversary / campaign / tag extraction
#   3. NVD CVSS severity string + attack vector for CVEs
#   4. Conflicting signal callout (highlighted warning)
#   5. TL;DR one-line summary at the top of every report
# v0.0.3 enhancements:
#   6. Package IOC type support (OSV.dev + registry metadata)
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent.scoring import (
    SOURCE_LABELS,
    detect_conflicts,
    extract_vt_detections,
    extract_otx_campaigns,
    extract_nvd_details,
    extract_osv_details,
    generate_tldr,
)

# Severity badge colours for HTML rendering
SEVERITY_COLOURS: dict[str, str] = {
    "CLEAN":    "#27ae60",   # green
    "LOW":      "#f1c40f",   # yellow
    "MEDIUM":   "#e67e22",   # orange
    "HIGH":     "#e74c3c",   # red
    "CRITICAL": "#8b0000",   # dark-red
}

SEVERITY_EMOJI: dict[str, str] = {
    "CLEAN":    "🟢",
    "LOW":      "🟡",
    "MEDIUM":   "🟠",
    "HIGH":     "🔴",
    "CRITICAL": "🚨",
}

RECOMMENDED_ACTIONS: dict[str, str] = {
    "CLEAN":    "No credible threat signals detected. Continue normal monitoring.",
    "LOW":      "Minor or stale signals present. Monitor this IOC — no immediate action required.",
    "MEDIUM":   "Credible signals from one or more sources. Investigate further and consider blocking.",
    "HIGH":     "Strong multi-source threat signals. Block the IOC immediately and open an incident ticket.",
    "CRITICAL": "Confirmed malicious with high confidence. Block immediately, escalate to IR team, and trigger incident response playbook.",
}

ALL_SOURCES = ["virustotal", "abuseipdb", "otx", "urlscan", "nvd", "osv", "osv_multi", "registry"]


# ── Source Summary Helpers ────────────────────────────────────────────────────

def _source_summary(source: str, raw_intel: dict[str, Any], ioc_type: str = "") -> str:
    """Generate a short summary string for a single intelligence source."""
    data = raw_intel.get(source)
    if data is None:
        return "N/A"

    if source == "virustotal":
        d = data.get("data", data)
        attrs = d.get("attributes", d)
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        return f"{mal} malicious, {sus} suspicious out of {total} engines"

    elif source == "abuseipdb":
        d = data.get("data", data)
        score = d.get("abuseConfidenceScore", 0)
        reports = d.get("totalReports", 0)
        country = d.get("countryCode", "N/A")
        isp = d.get("isp", "")
        usage = d.get("usageType", "")
        base = f"Confidence: {score}%, Reports: {reports}, Country: {country}"
        if isp:
            base += f", ISP: {isp}"
        if usage:
            base += f" ({usage})"
        return base

    elif source == "otx":
        campaigns = extract_otx_campaigns(data)
        count = len(campaigns["pulse_names"])
        if count == 0:
            return "No matching threat intelligence pulses"
        parts = [f"{count} pulse(s)"]
        if campaigns["adversaries"]:
            parts.append(f"Threat actors: {', '.join(campaigns['adversaries'])}")
        if campaigns["tags"]:
            parts.append(f"Tags: {', '.join(campaigns['tags'][:5])}")
        names = campaigns["pulse_names"][:3]
        suffix = f" (+{count - 3} more)" if count > 3 else ""
        parts.append(f"Pulses: {', '.join(names)}{suffix}")
        return " | ".join(parts)

    elif source == "urlscan":
        verdicts = data.get("verdicts", {})
        overall = verdicts.get("overall", {})
        score = overall.get("score", 0)
        malicious = overall.get("malicious", False)
        page = data.get("page", {})
        domain = page.get("domain", "N/A")
        return f"Score: {score}, Malicious: {malicious}, Domain: {domain}"

    elif source == "nvd":
        details = extract_nvd_details(data)
        desc = details["description"]
        if len(desc) > 120:
            desc = desc[:117] + "..."
        severity_str = details["severity"]
        vector = details["vector"]
        base = details["base_score"]
        if base > 0:
            return f"CVSS: {base} ({severity_str}), Vector: {vector} — {desc}"
        else:
            return f"CVSS: Awaiting analysis — {desc}"

    elif source == "osv":
        osv_details = extract_osv_details(data)
        count = osv_details["vuln_count"]
        if count == 0:
            return "No known vulnerabilities or malware advisories"
        parts = []
        if osv_details["is_malware"]:
            parts.append("⚠️ CONFIRMED MALWARE (MAL advisory)")
        parts.append(f"{count} advisory/ies (max severity: {osv_details['max_severity']})")
        for adv in osv_details["advisories"][:3]:
            adv_str = adv["id"]
            if adv["summary"]:
                adv_str += f": {adv['summary'][:60]}"
            parts.append(adv_str)
        return " | ".join(parts)

    elif source == "registry":
        if data.get("_unsupported"):
            return f"Registry lookup not supported for {data.get('ecosystem', 'unknown')} ecosystem"
        ecosystem = data.get("ecosystem", "")
        name = data.get("name", "")
        ver = data.get("latest_version", "")
        created = data.get("created", "N/A")
        parts = [f"{ecosystem}:{name} v{ver}"]
        if created and created != "N/A":
            parts.append(f"First published: {created[:10]}")
        if data.get("has_install_scripts"):
            parts.append("⚠️ Has install scripts")
        maintainers = data.get("maintainers", [])
        if maintainers:
            parts.append(f"Maintainers: {', '.join(maintainers[:3])}")
        if not data.get("repository"):
            parts.append("⚠️ No source repo")
        return " | ".join(parts)

    elif source == "osv_multi":
        pkg_name = data.get("package_name", "unknown")
        scanned = data.get("ecosystems_scanned", [])
        hits = data.get("ecosystems_with_hits", [])
        total_vulns = data.get("total_vulns", 0)
        has_malware = data.get("has_malware", False)

        if has_malware:
            return f"🚨 MALWARE detected for '{pkg_name}' in: {', '.join(hits)} ({total_vulns} total advisories across {len(scanned)} ecosystems)"
        elif hits:
            return f"⚠️ {total_vulns} advisory/ies for '{pkg_name}' in: {', '.join(hits)} (scanned {len(scanned)} ecosystems)"
        else:
            return f"✅ No advisories for '{pkg_name}' across {len(scanned)} ecosystems: {', '.join(scanned)}"

    return str(data)[:100]


def _vt_detections_text(raw_intel: dict[str, Any], ioc_type: str) -> str | None:
    """Extract VT detection names for hash IOCs. Returns formatted text or None."""
    if not ioc_type.startswith("hash_"):
        return None
    vt_data = raw_intel.get("virustotal")
    if not vt_data:
        return None
    detections = extract_vt_detections(vt_data)
    if not detections:
        return None
    return detections


def _osv_multi_breakdown_text(raw_intel: dict[str, Any]) -> str | None:
    """Extract per-ecosystem breakdown for multi-scan. Returns formatted text or None."""
    data = raw_intel.get("osv_multi")
    if not data:
        return None
    results = data.get("results", {})
    lines: list[str] = []
    for eco in data.get("ecosystems_scanned", []):
        eco_data = results.get(eco, {})
        vulns = eco_data.get("vulns", [])
        if vulns:
            mal_ids = [v["id"] for v in vulns if v.get("id", "").startswith("MAL-")]
            other_ids = [v["id"] for v in vulns if not v.get("id", "").startswith("MAL-")]
            parts = []
            if mal_ids:
                parts.append(f"🚨 MALWARE: {', '.join(mal_ids[:3])}")
            if other_ids:
                parts.append(f"{len(other_ids)} advisory/ies: {', '.join(other_ids[:3])}")
            lines.append(f"  {eco:14s}  {' | '.join(parts)}")
        else:
            lines.append(f"  {eco:14s}  ✅ clean")
    return "\n".join(lines) if lines else None


def _osv_multi_breakdown_html(raw_intel: dict[str, Any]) -> str:
    """Render per-ecosystem breakdown as HTML for multi-scan."""
    data = raw_intel.get("osv_multi")
    if not data:
        return ""
    results = data.get("results", {})
    rows = ""
    for eco in data.get("ecosystems_scanned", []):
        eco_data = results.get(eco, {})
        vulns = eco_data.get("vulns", [])
        if vulns:
            mal_ids = [v["id"] for v in vulns if v.get("id", "").startswith("MAL-")]
            other_ids = [v["id"] for v in vulns if not v.get("id", "").startswith("MAL-")]
            parts = []
            if mal_ids:
                parts.append(f'<span style="color:#DC2626; font-weight:bold;">🚨 MALWARE: {", ".join(mal_ids[:3])}</span>')
            if other_ids:
                parts.append(f'{len(other_ids)} advisory/ies: {", ".join(other_ids[:3])}')
            status = " | ".join(parts)
        else:
            status = '<span style="color:#16A34A;">✅ clean</span>'
        rows += f'<tr><td style="padding:3px 10px; font-family:monospace;">{eco}</td><td style="padding:3px 10px;">{status}</td></tr>'

    return (
        f'<details style="margin:8px 0;" open>'
        f'<summary style="cursor:pointer; font-weight:bold;">🔍 Per-Ecosystem Breakdown</summary>'
        f'<table style="border-collapse:collapse; margin:8px 0;">'
        f'<tr><th style="text-align:left; padding:3px 10px;">Ecosystem</th>'
        f'<th style="text-align:left; padding:3px 10px;">Status</th></tr>'
        f'{rows}</table></details>'
    )


# ── CLI Report ────────────────────────────────────────────────────────────────

def format_cli_report(
    ioc_clean: str,
    ioc_type: str,
    severity_band: str,
    composite_score: float,
    raw_intel: dict[str, Any],
    verdict_justification: str,
    intel_errors: list[str],
    arize_trace_url: str,
    score_breakdown: dict[str, float] | None = None,
    active_weights: dict[str, float] | None = None,
) -> str:
    """Format the threat report for CLI terminal output."""
    emoji = SEVERITY_EMOJI.get(severity_band, "❓")
    action = RECOMMENDED_ACTIONS.get(severity_band, "Review manually.")
    border = "═" * 60
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # TL;DR
    tldr = generate_tldr(
        ioc_clean, ioc_type, severity_band, composite_score,
        score_breakdown or {}, raw_intel, intel_errors,
    )

    # Findings
    findings_lines = []
    for src in ALL_SOURCES:
        label = SOURCE_LABELS.get(src, src)
        errored = any(src in e for e in intel_errors)
        if errored:
            findings_lines.append(f"  {label:12s}  unavailable")
        elif src in raw_intel:
            summary = _source_summary(src, raw_intel, ioc_type)
            findings_lines.append(f"  {label:12s}  {summary}")

    # VT detection names for hashes
    detections = _vt_detections_text(raw_intel, ioc_type)
    detections_text = ""
    if detections:
        det_lines = "\n    ".join(detections)
        detections_text = f"\nDETECTION SIGNATURES:\n    {det_lines}\n"

    # Multi-ecosystem breakdown for bare package scans
    multi_text = ""
    multi_breakdown = _osv_multi_breakdown_text(raw_intel)
    if multi_breakdown:
        multi_text = f"\nPER-ECOSYSTEM BREAKDOWN:\n{multi_breakdown}\n"

    # Conflicts
    conflicts = detect_conflicts(score_breakdown or {})
    conflicts_text = ""
    if conflicts:
        conflict_lines = "\n  ⚡ ".join(conflicts)
        conflicts_text = f"\n⚠️  CONFLICTING SIGNALS:\n  ⚡ {conflict_lines}\n"

    errors_text = "\n  ".join(intel_errors) if intel_errors else "None"

    # Data confidence
    total_possible = len(score_breakdown or {}) + len(intel_errors)
    available = len(score_breakdown or {})
    confidence_text = ""
    if total_possible > 0 and available < total_possible:
        confidence_text = f"\nDATA CONFIDENCE: {available}/{total_possible} sources responded. Verdict is based on partial data.\n"

    report = f"""
{border}
  FlowRun Streamlet: IoC Triage — THREAT REPORT
{border}
TL;DR:    {tldr}

IOC:      {ioc_clean}
TYPE:     {ioc_type}
VERDICT:  {emoji} {severity_band}
SCORE:    {composite_score:.3f}
TIME:     {timestamp}

INTELLIGENCE FINDINGS:
{chr(10).join(findings_lines)}
{detections_text}{multi_text}{conflicts_text}{confidence_text}
CORRELATION:
  {verdict_justification}

ERRORS (non-fatal):
  {errors_text}

RECOMMENDED ACTIONS:
  {action}

ARIZE TRACE: {arize_trace_url or 'N/A'}
{border}
"""
    return report.strip()


# ── HTML Report ───────────────────────────────────────────────────────────────

def format_html_report(
    ioc_clean: str,
    ioc_type: str,
    severity_band: str,
    composite_score: float,
    raw_intel: dict[str, Any],
    verdict_justification: str,
    intel_errors: list[str],
    arize_trace_url: str,
    score_breakdown: dict[str, float] | None = None,
    active_weights: dict[str, float] | None = None,
) -> str:
    """Format the threat report as styled HTML for Jupyter display."""
    colour = SEVERITY_COLOURS.get(severity_band, "#999")
    emoji = SEVERITY_EMOJI.get(severity_band, "❓")
    action = RECOMMENDED_ACTIONS.get(severity_band, "Review manually.")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── TL;DR ──────────────────────────────────────────────────────────────
    tldr = generate_tldr(
        ioc_clean, ioc_type, severity_band, composite_score,
        score_breakdown or {}, raw_intel, intel_errors,
    )
    tldr_html = (
        f'<div style="background:#f0f4f8; border-left:4px solid {colour}; '
        f'padding:10px 14px; margin:12px 0; font-size:1.05em;">'
        f'<b>TL;DR:</b> {tldr}</div>'
    )

    # ── Findings table ─────────────────────────────────────────────────────
    findings_rows = ""
    for src in ALL_SOURCES:
        label = SOURCE_LABELS.get(src, src)
        errored = any(src in e for e in intel_errors)
        if errored:
            findings_rows += (
                f'<tr><td style="padding:4px 8px;"><b>{label}</b></td>'
                f'<td style="padding:4px 8px; color:#999">unavailable</td></tr>'
            )
        elif src in raw_intel:
            summary = _source_summary(src, raw_intel, ioc_type)
            findings_rows += (
                f'<tr><td style="padding:4px 8px;"><b>{label}</b></td>'
                f'<td style="padding:4px 8px;">{summary}</td></tr>'
            )

    # ── VT detection names (hash IOCs only) ────────────────────────────────
    detections_html = ""
    detections = _vt_detections_text(raw_intel, ioc_type)
    if detections:
        det_items = "".join(
            f'<li style="font-family:monospace; font-size:0.95em;">{d}</li>'
            for d in detections
        )
        detections_html = (
            f'<details style="margin:8px 0;" open>'
            f'<summary style="cursor:pointer; font-weight:bold;">🦠 Detection Signatures</summary>'
            f'<ul style="margin:4px 0;">{det_items}</ul></details>'
        )

    # ── Multi-ecosystem breakdown (package_multi only) ─────────────────────
    multi_html = _osv_multi_breakdown_html(raw_intel)

    # ── Conflict callout ───────────────────────────────────────────────────
    conflicts = detect_conflicts(score_breakdown or {})
    conflict_html = ""
    if conflicts:
        items = "".join(f"<li>{c}</li>" for c in conflicts)
        conflict_html = (
            f'<div style="background:#FEF3C7; border:1px solid #F59E0B; '
            f'border-radius:6px; padding:10px 14px; margin:12px 0;">'
            f'<b>⚠️ Conflicting Signals Detected</b>'
            f'<ul style="margin:6px 0 0 0;">{items}</ul></div>'
        )

    # ── Data confidence ────────────────────────────────────────────────────
    total_possible = len(score_breakdown or {}) + len(intel_errors)
    available = len(score_breakdown or {})
    confidence_html = ""
    if total_possible > 0 and available < total_possible:
        confidence_html = (
            f'<p style="color:#6B7280; font-size:0.9em; margin:4px 0;">'
            f'📊 Data confidence: {available}/{total_possible} sources responded. '
            f'Verdict is based on partial data.</p>'
        )

    # ── Score breakdown ────────────────────────────────────────────────────
    breakdown_rows = ""
    if score_breakdown:
        for src, sc in score_breakdown.items():
            w = active_weights.get(src, 0.0) if active_weights else 0.0
            breakdown_rows += (
                f"<tr><td style='padding:2px 12px;'>{SOURCE_LABELS.get(src, src)}</td>"
                f"<td style='padding:2px 12px;'>{sc:.3f}</td>"
                f"<td style='padding:2px 12px;'>{w:.3f}</td></tr>"
            )

    # ── Errors ─────────────────────────────────────────────────────────────
    errors_html = "<p>None</p>"
    if intel_errors:
        items = "".join(f"<li>{e}</li>" for e in intel_errors)
        errors_html = f"<ul>{items}</ul>"

    # ── IOC styling ────────────────────────────────────────────────────────
    is_hash = ioc_type.startswith("hash_")
    ioc_style = 'font-family:monospace; font-size:1.05em;' if is_hash else ''

    html = f"""
    <div style="border:2px solid {colour}; border-radius:8px; padding:16px; margin:8px 0; font-family:sans-serif; max-width:850px;">
        <h2 style="margin-top:0;">🛡️ FlowRun Streamlet: IoC Triage — Threat Report</h2>
        <div style="display:inline-block; background:{colour}; color:#fff; padding:6px 16px; border-radius:4px; font-size:1.3em; font-weight:bold; margin-bottom:8px;">
            {emoji} {severity_band}
        </div>
        <span style="color:#6B7280; font-size:0.85em; margin-left:12px;">{timestamp}</span>

        {tldr_html}

        <table style="margin:12px 0; border-collapse:collapse;">
            <tr><td style="padding:4px 12px 4px 0; font-weight:bold;">IOC</td>
                <td style="{ioc_style}">{ioc_clean}</td></tr>
            <tr><td style="padding:4px 12px 4px 0; font-weight:bold;">Type</td>
                <td>{ioc_type}</td></tr>
            <tr><td style="padding:4px 12px 4px 0; font-weight:bold;">Composite Score</td>
                <td>{composite_score:.3f}</td></tr>
        </table>

        {conflict_html}
        {confidence_html}

        <h3>📊 Intelligence Findings</h3>
        <table style="border-collapse:collapse; width:100%;">
            {findings_rows}
        </table>

        {detections_html}

        {multi_html}

        <details style="margin:12px 0;">
            <summary style="cursor:pointer; font-weight:bold;">📐 Score Breakdown (click to expand)</summary>
            <table style="border-collapse:collapse; margin:8px 0;">
                <tr><th style="text-align:left; padding:2px 12px;">Source</th>
                    <th style="text-align:left; padding:2px 12px;">Score</th>
                    <th style="text-align:left; padding:2px 12px;">Weight</th></tr>
                {breakdown_rows}
            </table>
        </details>

        <h3>🔗 Correlation</h3>
        <p>{verdict_justification}</p>

        <h3>⚡ Recommended Actions</h3>
        <p>{action}</p>

        <h3>⚠️ Errors (non-fatal)</h3>
        {errors_html}
    </div>
    """
    return html
