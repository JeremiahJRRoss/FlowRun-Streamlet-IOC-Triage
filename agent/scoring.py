# agent/scoring.py
# ─────────────────────────────────────────────────────────────────────────────
# Composite threat score formula, weight sets, per-source normalisers,
# weight redistribution logic, and severity band mapping.
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations
from typing import Any


# ── Weight Sets — Both Must Sum to 1.00 ───────────────────────────────────────

BASE_WEIGHTS: dict[str, float] = {
    "virustotal": 0.40,
    "abuseipdb":  0.30,   # IP type only — redistributed for others
    "otx":        0.20,
    "urlscan":    0.10,   # URL + domain types — redistributed for others
}

CVE_WEIGHTS: dict[str, float] = {
    "otx":        0.40,
    "nvd":        0.60,   # NIST NVD is the primary CVE authority
}

PACKAGE_WEIGHTS: dict[str, float] = {
    "osv":        0.60,   # OSV.dev — primary source for known malicious packages
    "registry":   0.40,   # Registry metadata — age, install scripts, maintainer signals
}

PACKAGE_MULTI_WEIGHTS: dict[str, float] = {
    "osv_multi":  1.00,   # Multi-ecosystem scan — single source, takes worst score
}


# ── Severity Tiers — Five Distinct Bands ──────────────────────────────────────

SEVERITY_TIERS: list[tuple[float, float, str]] = [
    (0.00, 0.10, "CLEAN"),
    (0.11, 0.30, "LOW"),
    (0.31, 0.55, "MEDIUM"),
    (0.56, 0.75, "HIGH"),
    (0.76, 1.00, "CRITICAL"),
]


def score_to_severity(score: float) -> str:
    """Map a composite score (0.0–1.0) to one of five severity bands."""
    for low, high, band in SEVERITY_TIERS:
        if low <= score <= high:
            return band
    # Edge-case safety: scores above 1.0 → CRITICAL, below 0.0 → CLEAN
    return "CRITICAL" if score > 1.0 else "CLEAN"


# ── Per-Source Normalisation Functions ─────────────────────────────────────────
# Each function takes the raw API response dict and returns a float 0.0–1.0.

def normalise_virustotal(raw: dict) -> float:
    """
    Normalise VirusTotal response to 0.0–1.0 using a non-linear curve.

    Even a small number of malicious detections on VirusTotal is a meaningful
    signal — 5 out of 90 engines flagging something is suspicious, not clean.
    A pure linear ratio (5/90 = 0.055) buries this signal. Instead we use a
    tiered curve based on the raw malicious + suspicious detection count:

        0 detections       → 0.00  (clean)
        1–2 detections     → 0.20  (noise / FP range)
        3–5 detections     → 0.40  (low but notable)
        6–15 detections    → 0.60  (credible signal)
        16–30 detections   → 0.80  (strong signal)
        31+ detections     → 1.00  (confirmed malicious)

    Suspicious detections count as half a malicious detection.
    """
    data = raw.get("data", raw)
    attrs = data.get("attributes", data)
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    if total == 0:
        return 0.0

    # Effective detection count (suspicious = half weight)
    detections = malicious + suspicious * 0.5

    if detections <= 0:
        return 0.0
    elif detections <= 2:
        return 0.20
    elif detections <= 5:
        return 0.40
    elif detections <= 15:
        return 0.60
    elif detections <= 30:
        return 0.80
    else:
        return 1.00


def normalise_abuseipdb(raw: dict) -> float:
    """Normalise AbuseIPDB confidence score (0–100) to 0.0–1.0."""
    data = raw.get("data", raw)
    score = data.get("abuseConfidenceScore", 0)
    return score / 100.0


def normalise_otx(raw: dict) -> float:
    """Normalise OTX pulse count to 0.0–1.0."""
    pulse_info = raw.get("pulse_info", raw)
    pulses = pulse_info.get("pulses", [])
    pulse_count = len(pulses)
    if pulse_count == 0:
        return 0.0
    if pulse_count <= 2:
        return 0.5
    return min(1.0, 0.5 + (pulse_count - 2) * 0.1)


def normalise_urlscan(raw: dict) -> float:
    """Normalise urlscan.io verdict to 0.0–1.0."""
    verdicts = raw.get("verdicts", {})
    overall = verdicts.get("overall", {})
    score = overall.get("score", 0)
    if score >= 50:
        return 1.0
    elif score > 0:
        return 0.5
    # Also check malicious flag
    if overall.get("malicious", False):
        return 1.0
    return 0.0


def normalise_nvd(raw: dict) -> float:
    """Normalise NIST NVD CVSS score to 0.0–1.0 (base_score / 10.0)."""
    vulnerabilities = raw.get("vulnerabilities", [])
    if not vulnerabilities:
        return 0.0
    cve_item = vulnerabilities[0]
    cve_data = cve_item.get("cve", {})
    metrics = cve_data.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0, then v2.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            base_score = cvss_data.get("baseScore", 0.0)
            return base_score / 10.0

    return 0.0


def normalise_osv(raw: dict) -> float:
    """
    Normalise OSV.dev response to 0.0–1.0.

    Scoring:
      - Any advisory with "MAL-" prefix (malware)     → 1.00 (instant critical)
      - Any advisory with CVSS >= 9.0                  → 0.90
      - Any advisory with CVSS >= 7.0                  → 0.70
      - Any advisory present (lower severity)          → 0.50
      - No advisories                                  → 0.00
    """
    vulns = raw.get("vulns", [])
    if not vulns:
        return 0.0

    max_score = 0.0
    for v in vulns:
        vuln_id = v.get("id", "")
        # MAL- prefix indicates confirmed malicious package (e.g., MAL-2024-1234)
        if vuln_id.startswith("MAL-"):
            return 1.00

        # Check for CVSS scores in severity or database_specific
        severity_list = v.get("severity", [])
        for sev in severity_list:
            score_str = sev.get("score", "")
            # CVSS vector string — extract base score if present
            if "CVSS:" in score_str:
                try:
                    # Parse base score from vector (last numeric component)
                    parts = score_str.split("/")
                    for p in parts:
                        if p.startswith("CVSS:"):
                            continue
                        try:
                            val = float(p)
                            max_score = max(max_score, val / 10.0)
                        except ValueError:
                            pass
                except Exception:
                    pass

        # Also check database_specific for severity
        db_specific = v.get("database_specific", {})
        severity = db_specific.get("severity", "").upper()
        if severity == "CRITICAL":
            max_score = max(max_score, 0.90)
        elif severity == "HIGH":
            max_score = max(max_score, 0.70)
        elif severity == "MODERATE" or severity == "MEDIUM":
            max_score = max(max_score, 0.50)

    # If we found vulns but couldn't extract a severity, treat as moderate
    if max_score == 0.0 and vulns:
        max_score = 0.50

    return min(1.0, max_score)


def normalise_registry(raw: dict) -> float:
    """
    Normalise package registry metadata to 0.0–1.0.

    Red flags scored:
      - has_install_scripts (npm postinstall hooks)     → +0.40
      - Package age < 7 days                            → +0.30
      - Package age < 30 days                           → +0.15
      - Single maintainer / new author                  → +0.10
      - No source repo link                             → +0.10
      - No red flags                                    → 0.00
    """
    if not raw or raw.get("_unsupported"):
        return 0.0

    score = 0.0

    # Install scripts (npm-specific, major red flag)
    if raw.get("has_install_scripts", False):
        score += 0.40

    # Package age — check if created recently
    created = raw.get("created", "")
    if created:
        try:
            from datetime import datetime, timezone
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            age_days = (now - created_dt).days
            if age_days < 7:
                score += 0.30
            elif age_days < 30:
                score += 0.15
        except Exception:
            pass

    # Maintainer signals
    maintainers = raw.get("maintainers", [])
    if len(maintainers) <= 1:
        score += 0.10

    # No source repo
    if not raw.get("repository"):
        score += 0.10

    return min(1.0, score)


def normalise_osv_multi(raw: dict) -> float:
    """
    Normalise multi-ecosystem OSV scan results to 0.0–1.0.

    Takes the WORST (highest) score across all scanned ecosystems.
    If any ecosystem has a MAL- advisory, returns 1.00 immediately.
    """
    if raw.get("has_malware"):
        return 1.00

    results = raw.get("results", {})
    if not results:
        return 0.0

    max_score = 0.0
    for eco, eco_data in results.items():
        score = normalise_osv(eco_data)
        max_score = max(max_score, score)

    return max_score


# Mapping of source names to their normaliser function
NORMALISERS: dict[str, callable] = {
    "virustotal": normalise_virustotal,
    "abuseipdb":  normalise_abuseipdb,
    "otx":        normalise_otx,
    "urlscan":    normalise_urlscan,
    "nvd":        normalise_nvd,
    "osv":        normalise_osv,
    "registry":   normalise_registry,
    "osv_multi":  normalise_osv_multi,
}


def redistribute_weights(
    base_weights: dict[str, float],
    available_sources: list[str],
) -> dict[str, float]:
    """
    Redistribute weights proportionally so active weights sum to exactly 1.00.

    If a source is unavailable, its weight is redistributed among available
    sources in proportion to their original weights.

    Example: abuseipdb unavailable (weight 0.30)
      → remaining: vt=0.40, otx=0.20, urlscan=0.10 (sum=0.70)
      → redistributed: vt=0.571, otx=0.286, urlscan=0.143 (sum=1.00)
    """
    active = {k: v for k, v in base_weights.items() if k in available_sources}
    total = sum(active.values())
    if total == 0:
        # No sources available — equal weights as fallback
        if available_sources:
            w = 1.0 / len(available_sources)
            return {k: w for k in available_sources}
        return {}
    return {k: v / total for k, v in active.items()}


def compute_composite(
    raw_intel: dict[str, Any],
    intel_errors: list[str],
    ioc_type: str,
) -> tuple[float, dict[str, float], dict[str, float]]:
    """
    Compute the composite threat score from raw intelligence data.

    Returns:
        (composite_score, score_breakdown, active_weights)
    """
    # Select weight set based on IOC type
    if ioc_type == "cve":
        base_weights = CVE_WEIGHTS
    elif ioc_type == "package":
        base_weights = PACKAGE_WEIGHTS
    elif ioc_type == "package_multi":
        base_weights = PACKAGE_MULTI_WEIGHTS
    else:
        base_weights = BASE_WEIGHTS

    # Determine which sources are available (have data in raw_intel)
    available_sources = [s for s in base_weights if s in raw_intel]

    # If no sources available, default to LOW-range score
    if not available_sources:
        return (0.15, {}, {})

    # Normalise each source's raw response
    score_breakdown: dict[str, float] = {}
    for source in available_sources:
        normaliser = NORMALISERS.get(source)
        if normaliser:
            try:
                score_breakdown[source] = normaliser(raw_intel[source])
            except Exception:
                # If normalisation fails, treat as 0.0
                score_breakdown[source] = 0.0
        else:
            score_breakdown[source] = 0.0

    # Redistribute weights among available sources
    active_weights = redistribute_weights(base_weights, list(score_breakdown.keys()))

    # Compute weighted composite score
    composite = sum(
        score_breakdown[source] * active_weights.get(source, 0.0)
        for source in score_breakdown
    )

    # Clamp to [0.0, 1.0]
    composite = max(0.0, min(1.0, composite))

    return (composite, score_breakdown, active_weights)


# ── Source Labels ─────────────────────────────────────────────────────────────

SOURCE_LABELS: dict[str, str] = {
    "virustotal": "VirusTotal",
    "abuseipdb":  "AbuseIPDB",
    "otx":        "OTX",
    "urlscan":    "urlscan.io",
    "nvd":        "NIST NVD",
    "osv":        "OSV.dev",
    "osv_multi":  "OSV.dev (multi-ecosystem)",
    "registry":   "Registry",
}


# ── Conflict Detection ───────────────────────────────────────────────────────

def detect_conflicts(score_breakdown: dict[str, float]) -> list[str]:
    """
    Detect conflicting signals between sources.

    A conflict exists when one source scores < 0.20 (clean) and another
    scores > 0.50 (notable threat signal). Returns a list of human-readable
    conflict descriptions. Empty list means no conflicts.
    """
    if len(score_breakdown) < 2:
        return []

    conflicts: list[str] = []
    sources = list(score_breakdown.items())

    for i, (src_a, score_a) in enumerate(sources):
        for src_b, score_b in sources[i + 1:]:
            label_a = SOURCE_LABELS.get(src_a, src_a)
            label_b = SOURCE_LABELS.get(src_b, src_b)

            if score_a <= 0.20 and score_b >= 0.50:
                conflicts.append(
                    f"{label_a} reports clean ({score_a:.2f}) but "
                    f"{label_b} shows threat signals ({score_b:.2f})"
                )
            elif score_b <= 0.20 and score_a >= 0.50:
                conflicts.append(
                    f"{label_b} reports clean ({score_b:.2f}) but "
                    f"{label_a} shows threat signals ({score_a:.2f})"
                )

    return conflicts


# ── Rich Intel Extraction ────────────────────────────────────────────────────
# Helper functions that extract analyst-relevant details from raw API responses.

def extract_vt_detections(raw: dict, max_names: int = 5) -> list[str]:
    """
    Extract top antivirus detection names from VirusTotal response.
    Returns a list like ["Trojan.GenericKD.12345", "Win32/Malware.ABC"].
    """
    data = raw.get("data", raw)
    attrs = data.get("attributes", data)
    results = attrs.get("last_analysis_results", {})
    names: list[str] = []
    for engine, detail in results.items():
        if isinstance(detail, dict):
            category = detail.get("category", "")
            result_name = detail.get("result")
            if category in ("malicious", "suspicious") and result_name:
                names.append(f"{engine}: {result_name}")
    # Deduplicate result names while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for n in names:
        result_part = n.split(": ", 1)[1] if ": " in n else n
        if result_part not in seen:
            seen.add(result_part)
            unique.append(n)
    return unique[:max_names]


def extract_otx_campaigns(raw: dict) -> dict[str, Any]:
    """
    Extract threat actor and campaign info from OTX response.
    Returns {'adversary': str|None, 'tags': list[str], 'pulse_names': list[str]}
    """
    pulse_info = raw.get("pulse_info", raw)
    pulses = pulse_info.get("pulses", [])

    adversaries: list[str] = []
    all_tags: list[str] = []
    pulse_names: list[str] = []

    for p in pulses:
        name = p.get("name", "")
        if name:
            pulse_names.append(name)
        adv = p.get("adversary", "")
        if adv and adv not in adversaries:
            adversaries.append(adv)
        tags = p.get("tags", [])
        for t in tags:
            if t and t not in all_tags:
                all_tags.append(t)

    return {
        "adversaries": adversaries[:5],
        "tags": all_tags[:10],
        "pulse_names": pulse_names[:5],
    }


def extract_nvd_details(raw: dict) -> dict[str, Any]:
    """
    Extract CVSS severity string, attack vector, and description from NVD.
    Returns {'base_score': float, 'severity': str, 'vector': str, 'description': str}
    """
    vulns = raw.get("vulnerabilities", [])
    if not vulns:
        return {"base_score": 0.0, "severity": "N/A", "vector": "N/A", "description": "No CVE data found"}

    cve = vulns[0].get("cve", {})
    desc_list = cve.get("descriptions", [])
    desc = "No description"
    for d in desc_list:
        if d.get("lang", "") == "en" or not desc_list:
            desc = d.get("value", "No description")
            break
    if not desc or desc == "No description":
        if desc_list:
            desc = desc_list[0].get("value", "No description")

    metrics = cve.get("metrics", {})
    base_score = 0.0
    severity = "N/A"
    vector = "N/A"

    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            base_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "N/A")
            vector = cvss_data.get("attackVector", "N/A")
            break

    # Fallback to v2
    if severity == "N/A":
        v2_list = metrics.get("cvssMetricV2", [])
        if v2_list:
            cvss_data = v2_list[0].get("cvssData", {})
            base_score = cvss_data.get("baseScore", 0.0)
            vector = cvss_data.get("accessVector", "N/A")
            # V2 doesn't have baseSeverity — derive from score
            if base_score >= 9.0:
                severity = "CRITICAL"
            elif base_score >= 7.0:
                severity = "HIGH"
            elif base_score >= 4.0:
                severity = "MEDIUM"
            elif base_score > 0:
                severity = "LOW"

    return {
        "base_score": base_score,
        "severity": severity,
        "vector": vector,
        "description": desc,
    }


def extract_osv_details(raw: dict) -> dict[str, Any]:
    """
    Extract advisory details from OSV.dev response.
    Returns {'vuln_count': int, 'is_malware': bool, 'advisories': list[dict],
             'max_severity': str}
    """
    vulns = raw.get("vulns", [])
    is_malware = False
    advisories: list[dict] = []
    max_severity = "NONE"
    severity_order = {"NONE": 0, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for v in vulns:
        vuln_id = v.get("id", "")
        summary = v.get("summary", "")
        details = v.get("details", "")

        if vuln_id.startswith("MAL-"):
            is_malware = True

        sev = "NONE"
        db_specific = v.get("database_specific", {})
        raw_sev = db_specific.get("severity", "").upper()
        if raw_sev in severity_order:
            sev = raw_sev

        if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
            max_severity = sev

        advisories.append({
            "id": vuln_id,
            "summary": summary[:120],
            "severity": sev,
        })

    return {
        "vuln_count": len(vulns),
        "is_malware": is_malware,
        "advisories": advisories[:5],
        "max_severity": max_severity,
    }


def generate_tldr(
    ioc_clean: str,
    ioc_type: str,
    severity_band: str,
    composite_score: float,
    score_breakdown: dict[str, float],
    raw_intel: dict[str, Any],
    intel_errors: list[str],
) -> str:
    """
    Generate a one-sentence TL;DR summary for the top of the report.
    Examples:
      "Known malicious IP flagged by 45 AV engines with 100% AbuseIPDB confidence."
      "Clean domain with no detections across 3 sources."
      "Critical CVE (CVSS 9.8) with active OTX threat intelligence pulses."
    """
    parts: list[str] = []
    source_count = len(score_breakdown)
    error_count = len(intel_errors)

    # IOC type descriptor
    type_desc = {
        "ip": "IP address",
        "domain": "domain",
        "url": "URL",
        "hash_md5": "file (MD5 hash)",
        "hash_sha1": "file (SHA-1 hash)",
        "hash_sha256": "file (SHA-256 hash)",
        "cve": "vulnerability",
        "package": "package",
        "package_multi": "package (multi-ecosystem scan)",
    }.get(ioc_type, "IOC")

    # Severity descriptor
    sev_desc = {
        "CLEAN": "Clean",
        "LOW": "Low-risk",
        "MEDIUM": "Suspicious",
        "HIGH": "High-risk",
        "CRITICAL": "Confirmed malicious",
    }.get(severity_band, severity_band)

    parts.append(f"{sev_desc} {type_desc}")

    # Add strongest signal details
    vt_data = raw_intel.get("virustotal")
    if vt_data:
        d = vt_data.get("data", vt_data)
        attrs = d.get("attributes", d)
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        if mal > 0:
            total = sum(stats.values()) if stats else 0
            parts.append(f"flagged by {mal}/{total} AV engines")

    abuse_data = raw_intel.get("abuseipdb")
    if abuse_data:
        d = abuse_data.get("data", abuse_data)
        conf = d.get("abuseConfidenceScore", 0)
        if conf > 0:
            parts.append(f"{conf}% AbuseIPDB confidence")

    otx_data = raw_intel.get("otx")
    if otx_data:
        campaigns = extract_otx_campaigns(otx_data)
        if campaigns["adversaries"]:
            parts.append(f"linked to {', '.join(campaigns['adversaries'][:2])}")
        elif campaigns["pulse_names"]:
            count = len(campaigns["pulse_names"])
            parts.append(f"{count} OTX threat pulse{'s' if count != 1 else ''}")

    nvd_data = raw_intel.get("nvd")
    if nvd_data:
        details = extract_nvd_details(nvd_data)
        if details["base_score"] > 0:
            parts.append(f"CVSS {details['base_score']} {details['severity']}")
        elif details["severity"] == "N/A":
            parts.append("awaiting NVD analysis")

    osv_data = raw_intel.get("osv")
    if osv_data:
        osv_details = extract_osv_details(osv_data)
        if osv_details["is_malware"]:
            parts.append("confirmed malicious in OSV.dev (MAL advisory)")
        elif osv_details["vuln_count"] > 0:
            parts.append(f"{osv_details['vuln_count']} OSV advisory/ies ({osv_details['max_severity']})")

    osv_multi_data = raw_intel.get("osv_multi")
    if osv_multi_data:
        hits = osv_multi_data.get("ecosystems_with_hits", [])
        total = osv_multi_data.get("total_vulns", 0)
        if osv_multi_data.get("has_malware"):
            parts.append(f"MALWARE found in {', '.join(hits)}")
        elif hits:
            parts.append(f"{total} advisory/ies across {', '.join(hits)}")
        else:
            scanned = len(osv_multi_data.get("ecosystems_scanned", []))
            parts.append(f"clean across {scanned} ecosystems")

    reg_data = raw_intel.get("registry")
    if reg_data and not reg_data.get("_unsupported"):
        flags: list[str] = []
        if reg_data.get("has_install_scripts"):
            flags.append("has install scripts")
        created = reg_data.get("created", "")
        if created:
            try:
                from datetime import datetime, timezone
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created_dt).days
                if age_days < 7:
                    flags.append(f"created {age_days}d ago")
            except Exception:
                pass
        if flags:
            parts.append(", ".join(flags))

    # Confidence caveat
    if error_count > 0:
        parts.append(f"based on {source_count} of {source_count + error_count} sources")

    # Join with appropriate separator
    if len(parts) <= 1:
        return f"{parts[0]} with no notable signals across queried sources."

    main = parts[0]
    details = ", ".join(parts[1:])
    return f"{main} — {details}."
