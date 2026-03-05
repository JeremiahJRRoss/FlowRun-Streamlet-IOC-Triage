# agent/integrations/registry.py
# ─────────────────────────────────────────────────────────────────────────────
# Raw HTTP client for package registry metadata.
# Supports npm (registry.npmjs.org) and PyPI (pypi.org/pypi/<name>/json).
# No API keys required. Extracts age, download count, maintainer info, and
# suspicious install script signals.
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations


def build_registry_url(ecosystem: str, package_name: str) -> str:
    """Build the correct registry URL for the given ecosystem and package."""
    if ecosystem == "npm":
        return f"https://registry.npmjs.org/{package_name}"
    elif ecosystem == "pypi":
        return f"https://pypi.org/pypi/{package_name}/json"
    else:
        # Other ecosystems not yet supported for registry metadata
        raise ValueError(f"Registry lookup not supported for ecosystem: {ecosystem}")


def parse_registry_response(ecosystem: str, raw: dict) -> dict:
    """
    Normalise registry metadata into a consistent schema.
    Returns {
        'name': str,
        'ecosystem': str,
        'latest_version': str,
        'created': str,          # ISO date of first publish
        'modified': str,         # ISO date of last publish
        'maintainers': list,     # List of maintainer names/emails
        'description': str,
        'has_install_scripts': bool,  # npm preinstall/postinstall detected
        'weekly_downloads': int | None,
        'homepage': str | None,
        'repository': str | None,
    }
    """
    if ecosystem == "npm":
        return _parse_npm(raw)
    elif ecosystem == "pypi":
        return _parse_pypi(raw)
    return raw


def _parse_npm(raw: dict) -> dict:
    """Parse npm registry response."""
    name = raw.get("name", "")
    dist_tags = raw.get("dist-tags", {})
    latest_ver = dist_tags.get("latest", "")
    time_data = raw.get("time", {})
    created = time_data.get("created", "")
    modified = time_data.get("modified", "")

    # Get maintainers
    maintainers = raw.get("maintainers", [])
    maintainer_names = []
    for m in maintainers:
        if isinstance(m, dict):
            maintainer_names.append(m.get("name", m.get("email", "unknown")))
        elif isinstance(m, str):
            maintainer_names.append(m)

    # Check for install scripts in the latest version
    versions = raw.get("versions", {})
    has_install_scripts = False
    if latest_ver and latest_ver in versions:
        scripts = versions[latest_ver].get("scripts", {})
        suspicious_hooks = ["preinstall", "postinstall", "preuninstall", "install"]
        has_install_scripts = any(h in scripts for h in suspicious_hooks)

    description = raw.get("description", "")
    homepage = raw.get("homepage", None)
    repo = raw.get("repository", {})
    repository = repo.get("url", None) if isinstance(repo, dict) else repo

    return {
        "name": name,
        "ecosystem": "npm",
        "latest_version": latest_ver,
        "created": created,
        "modified": modified,
        "maintainers": maintainer_names,
        "description": description,
        "has_install_scripts": has_install_scripts,
        "weekly_downloads": None,  # Requires separate npm API call
        "homepage": homepage,
        "repository": repository,
    }


def _parse_pypi(raw: dict) -> dict:
    """Parse PyPI JSON API response."""
    info = raw.get("info", {})
    name = info.get("name", "")
    latest_ver = info.get("version", "")
    description = info.get("summary", "")
    author = info.get("author", "") or info.get("maintainer", "")
    homepage = info.get("home_page", None) or info.get("project_url", None)

    # Get release dates
    releases = raw.get("releases", {})
    urls = raw.get("urls", [])
    created = ""
    modified = ""
    if releases:
        all_dates = []
        for ver, files in releases.items():
            for f in files:
                upload_time = f.get("upload_time_iso_8601", "")
                if upload_time:
                    all_dates.append(upload_time)
        if all_dates:
            all_dates.sort()
            created = all_dates[0]
            modified = all_dates[-1]

    project_urls = info.get("project_urls", {}) or {}
    repository = project_urls.get("Source", project_urls.get("Repository", None))

    return {
        "name": name,
        "ecosystem": "pypi",
        "latest_version": latest_ver,
        "created": created,
        "modified": modified,
        "maintainers": [author] if author else [],
        "description": description,
        "has_install_scripts": False,  # PyPI doesn't expose this via JSON API
        "weekly_downloads": None,
        "homepage": homepage,
        "repository": repository,
    }
