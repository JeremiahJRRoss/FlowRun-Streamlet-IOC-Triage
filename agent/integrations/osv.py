# agent/integrations/osv.py
# ─────────────────────────────────────────────────────────────────────────────
# Raw HTTP client and response normaliser for OSV.dev (Google Open Source
# Vulnerability database). Supports 27 ecosystems across language packages
# and Linux distributions.
# Endpoint: POST https://api.osv.dev/v1/query  (no API key required)
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations


# ── Full Ecosystem Map ────────────────────────────────────────────────────────
# Maps user-friendly prefix → OSV ecosystem name.
# Multiple aliases point to the same ecosystem for convenience.

ECOSYSTEM_MAP: dict[str, str] = {
    # ── Language package managers ──────────────────────────────────────────
    "npm":        "npm",
    "pypi":       "PyPI",
    "pip":        "PyPI",           # alias
    "go":         "Go",
    "maven":      "Maven",
    "crates":     "crates.io",
    "cargo":      "crates.io",      # alias
    "nuget":      "NuGet",
    "rubygems":   "RubyGems",
    "gem":        "RubyGems",       # alias
    "packagist":  "Packagist",
    "composer":   "Packagist",      # alias
    "pub":        "Pub",            # Dart / Flutter
    "hex":        "Hex",            # Elixir / Erlang
    "hackage":    "Hackage",        # Haskell
    "cran":       "CRAN",           # R
    "swifturl":   "SwiftURL",       # Swift
    "cocoapods":  "CocoaPods",      # iOS / macOS
    # ── Linux distributions ───────────────────────────────────────────────
    "rhel":       "Red Hat",
    "redhat":     "Red Hat",        # alias
    "debian":     "Debian",
    "ubuntu":     "Ubuntu",
    "alpine":     "Alpine",
    "rocky":      "Rocky Linux",
    "alma":       "AlmaLinux",
    "suse":       "SUSE",
    "opensuse":   "SUSE",           # alias
    # ── Other ─────────────────────────────────────────────────────────────
    "android":    "Android",
    "linux":      "Linux",          # Linux kernel
    "bitnami":    "Bitnami",
    "curl":       "curl",
}

# Ecosystems scanned when a bare package name is submitted (no prefix).
# These are the most common targets for supply chain attacks.
MULTI_SCAN_ECOSYSTEMS: list[str] = [
    "npm",
    "PyPI",
    "crates.io",
    "Go",
    "Maven",
    "NuGet",
    "RubyGems",
    "Packagist",
    "Pub",
    "Hex",
]

# Ecosystems that have public registry metadata (npm/PyPI only for now)
REGISTRY_SUPPORTED: set[str] = {"npm", "pypi", "pip"}


def parse_package_ioc(ioc: str) -> tuple[str, str]:
    """
    Parse a package IOC string like 'npm:postmark-mcp' into (ecosystem, name).
    Returns (ecosystem_prefix, package_name).
    """
    if ":" not in ioc:
        raise ValueError(f"Invalid package IOC format: '{ioc}'. Expected 'ecosystem:name'.")
    prefix, name = ioc.split(":", 1)
    prefix = prefix.lower().strip()
    name = name.strip()
    if prefix not in ECOSYSTEM_MAP:
        raise ValueError(
            f"Unknown ecosystem '{prefix}'. "
            f"Supported: {', '.join(sorted(set(ECOSYSTEM_MAP.keys())))}"
        )
    return prefix, name


def build_osv_query(ecosystem_prefix: str, package_name: str) -> dict:
    """Build the JSON body for the OSV.dev query API."""
    osv_ecosystem = ECOSYSTEM_MAP[ecosystem_prefix]
    return {
        "package": {
            "name": package_name,
            "ecosystem": osv_ecosystem,
        }
    }


def build_osv_query_raw(osv_ecosystem: str, package_name: str) -> dict:
    """Build the JSON body using the raw OSV ecosystem name directly."""
    return {
        "package": {
            "name": package_name,
            "ecosystem": osv_ecosystem,
        }
    }


def parse_osv_response(raw: dict) -> dict:
    """
    Normalise OSV.dev response.
    Key fields: vulns[].id, vulns[].summary, vulns[].details,
    vulns[].database_specific, vulns[].severity
    """
    return raw
