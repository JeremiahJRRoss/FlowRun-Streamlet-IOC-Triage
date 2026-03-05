# 🛡️ FlowRun Streamlet: IoC Triage — v0.0.31

Automated Threat Intelligence Triage for Security Operations.

Built with **LangGraph** + **LangChain** + **OpenAI GPT-4o** + **Arize AI**.

## What It Does

Submit any IOC (IP address, domain, URL, file hash, CVE identifier, or **software package**) and the agent will:

1. Classify the IOC type automatically
2. Query up to 7 threat intelligence APIs **in parallel** (VirusTotal, AbuseIPDB, OTX, urlscan.io, NIST NVD, OSV.dev, npm/PyPI registries)
3. Compute a weighted composite threat score (0.0–1.0)
4. Map to one of 5 severity verdicts: **CLEAN → LOW → MEDIUM → HIGH → CRITICAL**
5. Generate a structured threat report with recommended actions
6. Stream a full execution trace to Arize AI for observability

## Quick Start

See [QUICK_START.md](QUICK_START.md) for full setup instructions.

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.template .env   # fill in your API keys
python flowrun_agent.py  # CLI mode
```

For Jupyter, also run:
```bash
pip install ipykernel
python -m ipykernel install --user --name=flowrun --display-name="FlowRun (venv)"
jupyter notebook flowrun_agent.ipynb
# Then: Kernel → Change kernel → FlowRun (venv)
```

## Documentation

| Document | Description |
|----------|-------------|
| [QUICK_START.md](QUICK_START.md) | Setup, installation, and first-run guide |
| [FlowRun_Streamlet_IoC_Triage_User_Manual_v2.3.md](docs/FlowRun_Streamlet_IoC_Triage_User_Manual_v2.md) | Full user manual with usage instructions |
| [FlowRun_Streamlet_IoC_Triage_PRD_v2.md](docs/FlowRun_Streamlet_IoC_Triage_PRD_v2.md) | Product requirements (FR-01–FR-39, NFR-01–NFR-10) |
| [FlowRun_Streamlet_IoC_Triage_Architecture_v2.md](docs/FlowRun_Streamlet_IoC_Triage_Architecture_v2.md) | System architecture and component design |
| [FlowRun_Streamlet_Build_Prompt.md](docs/FlowRun_Streamlet_Build_Prompt.md) | Original engineering build instructions |

## Project Structure

```
flowrun-streamlet-ioc-triage-v0.0.31/
├── flowrun_agent.py          # CLI entry point
├── flowrun_agent.ipynb       # Jupyter Notebook (8 cells)
├── requirements.txt
├── .env.template             # API key template (no values)
├── .gitignore
├── QUICK_START.md
├── README.md
├── agent/
│   ├── graph.py              # LangGraph StateGraph — nodes & edges
│   ├── state.py              # AgentState TypedDict
│   ├── llm.py                # Model config (single file to change models)
│   ├── scoring.py            # Weighted scoring formula & severity mapping
│   ├── report.py             # CLI text & HTML report formatters
│   ├── credentials.py        # .env → os.environ → getpass() resolution
│   ├── tracing.py            # Arize AI / OpenInference setup
│   ├── tools/                # LangChain tool wrappers (5 tools)
│   └── integrations/         # Raw HTTP clients & response parsers
├── tests/                    # 72 tests (pytest)
└── docs/                     # PRD, Architecture, User Manual, Build Prompt
```

## Changing Models

All model configuration lives in `agent/llm.py`. To swap models, edit `MODEL_CONFIG`:

```python
MODEL_CONFIG = {
    "classifier": {"model": "gpt-4o-mini", "temperature": 0.0},
    "report":     {"model": "gpt-4o",      "temperature": 0.3},
}
```

No other file needs to change.

## Changelog

**v0.0.31 — Package supply chain analysis + multi-ecosystem scanning**
- **New IOC type**: `package` — supports `ecosystem:name` format (e.g., `npm:postmark-mcp`, `pypi:requessts`, `rhel:openssl`, `debian:nginx`)
- **New IOC type**: `package_multi` — bare package names (e.g., `traceroute`, `express`) are automatically scanned across all 10 major language ecosystems simultaneously
- **New data source**: OSV.dev (Google) — scans for known malicious packages (MAL advisories) and vulnerabilities. No API key needed.
- **New data source**: Package registry metadata (npm/PyPI) — fetches creation date, maintainer count, install scripts, source repo presence. No API key needed.
- **27 supported ecosystems**: npm, PyPI, crates.io, Go, Maven, NuGet, RubyGems, Packagist, Pub, Hex, CocoaPods, Hackage, CRAN, SwiftURL, Red Hat, Debian, Ubuntu, Alpine, Rocky Linux, AlmaLinux, SUSE, Android, Linux (kernel), Bitnami, curl (with aliases like `pip:`, `cargo:`, `gem:`, `redhat:`)
- **Per-ecosystem breakdown**: Multi-scan reports show results for each ecosystem individually, highlighting which ones have advisories
- **New weight sets**: `PACKAGE_WEIGHTS` (OSV 60%, Registry 40%), `PACKAGE_MULTI_WEIGHTS` (OSV multi 100%)
- **Updated**: All documentation (PRD, Architecture, User Manual, Build Prompt, Addendum)

**v0.0.26 — Enhanced report intelligence**
- **New**: Per-engine AV detection names for hash IOCs (e.g., "Kaspersky: Trojan.Win32.Agent")
- **New**: OTX threat actor and campaign tag extraction shown in findings
- **New**: CVSS severity string and attack vector for CVE reports (e.g., "CVSS: 9.8 (CRITICAL), Vector: NETWORK")
- **New**: Conflicting signal callout — highlighted warning when sources disagree (e.g., VT clean but OTX shows APT pulses)
- **New**: TL;DR one-line summary at the top of every report
- **New**: Timestamp on every report
- **New**: Data confidence indicator when sources are missing

**v0.0.24 — URL→domain dual-query enrichment**
- **New**: When a URL is submitted, the domain is automatically extracted and queried separately against VirusTotal and OTX in addition to the URL-level queries. For each source, the response with the stronger threat signal is kept. This catches cases where a domain has known-bad reputation even if the specific URL path is new.
- **New**: Domains are now also sent to urlscan.io for live browser analysis (prepended with `https://`).

**v0.0.21 — Scoring sensitivity fix**
- **Fixed**: VirusTotal normalizer now uses a non-linear detection-count curve instead of a linear ratio. Even a few malicious detections (e.g. 13/94 engines) now correctly produce a MEDIUM or higher score, matching real-world analyst expectations.

**v0.2 — Runtime compatibility fixes**
- **Fixed**: `arize-otel` register() now uses `project_name` (was `model_id`)
- **Fixed**: Domain IOCs (e.g. `malware.wicar.org`) now classified by regex — no LLM fallback needed
- **Fixed**: Model config uses real, available models (`gpt-4o-mini`, `gpt-4o`) instead of unreleased GPT-5.2
- **Added**: Jupyter kernel setup instructions (ipykernel registration for venv users)
- **Added**: All documentation bundled in `docs/` folder
- **Added**: Quick Start guide with troubleshooting table
- **Updated**: Notebook includes kernel selection guidance and test IOC suggestions
