> **ARCHITECTURAL DESIGN DOCUMENT**
> **FlowRun Streamlet: IoC Triage**
> System Architecture, Component Design & Integration Reference
> LangGraph · LangChain · OpenAI GPT-4o · Arize AI · OpenInference

| **Attribute**         | **Value**                                                    |
|-----------------------|--------------------------------------------------------------|
| **Document Type**     | Architectural Design Document (ADD)                          |
| **Product**           | FlowRun Streamlet: IoC Triage                                |
| **Version**           | v0.0.31 — Reconciled with codebase                          |
| **Agentic Framework** | LangGraph 0.2+ (StateGraph)                                  |
| **LLM Integration**   | LangChain 0.3+ / OpenAI GPT-4o-mini + GPT-4o                |
| **Observability**     | Arize AI via OpenInference OTLP                              |


## 1. Document Purpose & Scope

This document describes the internal structure, component design, data flows, and technical decisions of the FlowRun Streamlet: IoC Triage as implemented in codebase version 0.0.31.

> **Architectural Philosophy**
> Transparency first — every decision traceable to a named source.
> Fail gracefully — partial intelligence is better than no intelligence.
> Separation of concerns — tools, graph, scoring, and reporting are fully decoupled.
> Observable by design — Arize tracing is embedded at the graph level.
> Zero trust credentials — no key ever touches source code, stdout, logs, or notebook output.


## 2. System Context

**2.1 External Dependencies**

| **Dependency**        | **Purpose**                                        | **Host**                  | **Protocol** | **Auth**                 |
|-----------------------|----------------------------------------------------|---------------------------|--------------|--------------------------|
| **OpenAI API**        | GPT-4o-mini (classifier) + GPT-4o (report)         | api.openai.com            | HTTPS/443    | OPENAI_API_KEY           |
| **VirusTotal API v3** | Multi-engine IOC reputation                        | www.virustotal.com        | HTTPS/443    | VIRUSTOTAL_API_KEY       |
| **AbuseIPDB API v2**  | IP abuse scoring & history                         | api.abuseipdb.com         | HTTPS/443    | ABUSEIPDB_API_KEY        |
| **AlienVault OTX v1** | Threat intelligence pulses                         | otx.alienvault.com        | HTTPS/443    | OTX_API_KEY              |
| **urlscan.io API v1** | Live URL/domain sandbox analysis                   | urlscan.io                | HTTPS/443    | URLSCAN_API_KEY          |
| **NIST NVD API 2.0**  | CVE vulnerability data                             | services.nvd.nist.gov     | HTTPS/443    | None required            |
| **OSV.dev API**       | Package vulnerability + malware advisories         | api.osv.dev               | HTTPS/443    | None required            |
| **npm Registry**      | Package metadata (age, maintainers, scripts)       | registry.npmjs.org        | HTTPS/443    | None required            |
| **PyPI JSON API**     | Package metadata (age, author, repo)               | pypi.org                  | HTTPS/443    | None required            |
| **Arize AI (OTLP)**   | Trace export & observability                       | otlp.arize.com:4317       | gRPC/4317    | ARIZE_API_KEY + SPACE_ID |


## 3. Layered Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ LAYER 5 — INTERACTION LAYER                                  │
│ CLI interactive loop | Jupyter Notebook (ipywidgets)         │
├──────────────────────────────────────────────────────────────┤
│ LAYER 4 — AGENT ORCHESTRATION LAYER                          │
│ LangGraph StateGraph | Node definitions | Edge routing       │
├──────────────────────────────────────────────────────────────┤
│ LAYER 3 — LLM & TOOL LAYER                                  │
│ LangChain ChatOpenAI | 9 Tool wrappers | Output parsers      │
├──────────────────────────────────────────────────────────────┤
│ LAYER 2 — INTELLIGENCE INTEGRATION LAYER                     │
│ VT  AbuseIPDB  OTX  urlscan  NVD  OSV.dev  npm  PyPI        │
├──────────────────────────────────────────────────────────────┤
│ LAYER 1 — OBSERVABILITY LAYER                                │
│ OpenInference instrumentation | Arize OTLP exporter          │
└──────────────────────────────────────────────────────────────┘
```


## 4. Project File Structure

```
flowrun-streamlet-ioc-triage-v0.0.31/
│
├── flowrun_agent.py              # CLI entry point — interactive loop
├── flowrun_agent.ipynb           # Jupyter Notebook interface (8 cells)
├── requirements.txt              # Pinned Python dependencies
├── .env.template                 # Template (no values)
├── .gitignore
│
├── agent/
│   ├── __init__.py
│   ├── graph.py                  # LangGraph StateGraph — all nodes & edges (614 lines)
│   ├── state.py                  # AgentState TypedDict schema
│   ├── llm.py                    # MODEL_CONFIG dict + get_llm() factory
│   ├── tracing.py                # Arize / OpenInference tracer setup
│   ├── credentials.py            # Key resolution: .env → os.environ → getpass()
│   ├── scoring.py                # Weights, normalisers, conflict detection, TL;DR (717 lines)
│   ├── report.py                 # CLI text + HTML report formatters (504 lines)
│   │
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── base.py               # ThreatIntelTool abstract base with retry
│   │   ├── virustotal.py         # VirusTotal API v3
│   │   ├── abuseipdb.py          # AbuseIPDB API v2
│   │   ├── otx.py                # AlienVault OTX API v1
│   │   ├── urlscan.py            # urlscan.io two-phase submit/poll
│   │   ├── nvd.py                # NIST NVD API 2.0
│   │   ├── osv.py                # OSV.dev — OSVTool (single) + OSVMultiTool (×10)
│   │   └── registry.py           # npm/PyPI registry metadata
│   │
│   └── integrations/
│       ├── __init__.py
│       ├── virustotal.py         # URL routing (IP/domain/URL/hash endpoints)
│       ├── abuseipdb.py          # Query param builder
│       ├── otx.py                # Indicator type routing
│       ├── urlscan.py            # Response parser
│       ├── nvd.py                # CVE query builder
│       ├── osv.py                # 27-ecosystem map + query builders
│       └── registry.py           # npm/PyPI metadata parsers
│
├── tests/                        # 157 tests
│   ├── test_classifier.py        # 26 tests — all 9 IOC types + edge cases
│   ├── test_scoring.py           # 72 tests — weights, normalisers, conflicts, TL;DR
│   ├── test_tools.py             # 25 tests — URL routing, response parsing
│   └── test_graph.py             # 34 tests — integration with stubbed tools
│
└── docs/
    ├── FlowRun_Streamlet_Build_Prompt.md
    ├── FlowRun_Streamlet_IoC_Triage_Architecture_v2.docx
    ├── FlowRun_Streamlet_IoC_Triage_PRD_v2.docx
    ├── FlowRun_Streamlet_IoC_Triage_User_Manual_v2.3.docx
    └── v0.0.3_ADDENDUM.md
```


## 5. Agent State Design

**5.1 AgentState Schema**

```python
class AgentState(TypedDict):
    # ── INPUT ──────────────────────────────────────────────────
    ioc_raw: str                        # Exact string from user input
    ioc_clean: str                      # Normalised value
    ioc_type: str                       # ip|domain|url|hash_md5|hash_sha1|
                                        # hash_sha256|cve|package|package_multi|unknown
    # ── ENRICHMENT ─────────────────────────────────────────────
    raw_intel: dict[str, Any]           # {source_name: parsed_response_dict}
    intel_errors: list[str]             # Non-fatal: ["abuseipdb: TimeoutError: ..."]
    # ── SCORING ────────────────────────────────────────────────
    score_breakdown: dict[str, float]   # Per-source normalised 0.0–1.0 scores
    composite_score: float              # Weighted aggregate
    active_weights: dict[str, float]    # Re-normalised if sources unavailable
    # ── VERDICT ────────────────────────────────────────────────
    severity_band: str                  # CLEAN|LOW|MEDIUM|HIGH|CRITICAL
    verdict_justification: str          # Plain-English explanation
    escalation_required: bool           # True only when CRITICAL
    # ── OUTPUT ─────────────────────────────────────────────────
    report_text: str                    # CLI-formatted threat report
    report_html: str                    # HTML-formatted report for Jupyter
    arize_trace_url: str                # Direct URL to trace in Arize UI
```

**5.2 State Lifecycle**

| **Node**             | **Fields Written**                                        | **Reads From**                   |
|----------------------|-----------------------------------------------------------|----------------------------------|
| **input_node**       | ioc_raw, ioc_clean, ioc_type                              | —                                |
| **classifier_node**  | ioc_type (overrides), ioc_clean (normalised)              | ioc_raw                          |
| **enrichment_node**  | raw_intel, intel_errors                                   | ioc_clean, ioc_type              |
| **correlation_node** | score_breakdown, composite_score, active_weights          | raw_intel, intel_errors, ioc_type|
| **severity_node**    | severity_band, verdict_justification, escalation_required | composite_score, score_breakdown |
| **report_node**      | report_text, report_html, arize_trace_url, verdict_justification | Full state                |


## 6. LangGraph Graph Design

**6.1 Full Graph Topology**

```
                    ┌─────────────┐
   IOC string ──▶   │ input_node  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────────┐
                    │ classifier_node │◀── GPT-4o-mini (temp=0.0)
                    └──────┬──────────┘
                           │
                   ┌───────▼────────────┐
                   │ [Conditional Edge] │
                   │ type == 'unknown'? │
                   └──┬─────────────────┘
            YES ──────┘          │ NO
              ▼                  ▼
          error_node    ┌───────────────────┐
              │         │  enrichment_node  │◀── asyncio.gather()
              ▼         │  ┌─────────────┐  │
             END        │  │ virustotal  │──┤──▶ VT API (not CVE/pkg)
                        │  │ abuseipdb   │──┤──▶ AbuseIPDB (IP only)
                        │  │ otx         │──┤──▶ OTX API (not pkg)
                        │  │ urlscan     │──┤──▶ urlscan (URL+domain)
                        │  │ nvd         │──┤──▶ NVD (CVE only)
                        │  │ osv         │──┤──▶ OSV.dev (package)
                        │  │ osv_multi   │──┤──▶ OSV.dev ×10 (pkg_multi)
                        │  │ registry    │──┤──▶ npm/PyPI (package)
                        │  │ vt_domain   │──┤──▶ VT domain (URL→domain)
                        │  │ otx_domain  │──┤──▶ OTX domain (URL→domain)
                        │  └─────────────┘  │
                        └────────┬──────────┘
                                 │
                        ┌────────▼──────────┐
                        │ correlation_node  │◀── Python scoring logic
                        └────────┬──────────┘
                                 │
                        ┌────────▼──────────┐
                        │  severity_node    │
                        └────────┬──────────┘
                                 │
                   ┌─────────────▼──────────────┐
                   │ [Conditional Edge]          │
                   │ severity_band == CRITICAL?  │
                   └──┬─────────────────────────┘
            YES ──────┘          │ NO
              ▼                  ▼
        escalation_gate   ┌─────────────┐
        (human-in-loop)   │ report_node │◀── GPT-4o (temp=0.3)
              │           └─────┬───────┘
              └────────┬───────┘
                       ▼
                     END
```

**6.2 Conditional Edge Functions**

```python
def route_after_classify(state):
    return 'error' if state.get('ioc_type') == 'unknown' else 'enrich'

def route_after_severity(state):
    return 'escalation' if state.get('severity_band') == 'CRITICAL' else 'report'
```


## 7. Node Design — Internal Logic

**7.1 input_node** — Strips whitespace, length-limits to 2048 chars, runs regex pre-classification. The regex catches 9 IOC types (package checked first since it uses `:`, which could collide with IPv6):

| Type | Regex Pattern |
|------|--------------|
| `package` | `^(npm\|pypi\|pip\|crates\|...\|curl):[\w./@-]+$` |
| `package_multi` | `^[a-zA-Z][\w-]{1,79}$` (bare name, no dots) |
| `cve` | `^CVE-\d{4}-\d{4,}$` |
| `url` | `^(https?\|ftp)://` |
| `ip` | IPv4 octets or IPv6 hex:colon |
| `hash_sha256` | 64 hex chars |
| `hash_sha1` | 40 hex chars |
| `hash_md5` | 32 hex chars |
| `domain` | Labels.TLD with at least one dot |

Domain checked after hashes (hex-only strings won't match) and before bare package (which has no dots).

**7.2 classifier_node** — If regex resolved the type, passes through with no LLM call. Otherwise invokes GPT-4o-mini via `get_llm("classifier")` with the CLASSIFIER_SYSTEM prompt. Parses with LangChain's JsonOutputParser. If confidence < 0.6 or parsing fails, sets type to "unknown".

**7.3 enrichment_node** — Builds a dynamic task dict based on ioc_type, then fires all with `asyncio.gather(return_exceptions=True)`. For URL types, extracts the domain and adds VT + OTX domain-level queries. After gather, the merge step compares URL-level and domain-level results for each source, keeping whichever has the stronger signal.

**7.4 correlation_node** — Pure Python. Calls `compute_composite(raw_intel, intel_errors, ioc_type)` which selects the appropriate weight set (BASE, CVE, PACKAGE, or PACKAGE_MULTI), normalises each source, redistributes weights for absent sources, and returns the composite score. Also calls `detect_conflicts()` to flag disagreeing sources.

**7.5 severity_node** — Maps composite score to five bands. Generates preliminary justification.

**7.6 escalation_gate** — Detects runtime environment. CLI mode: `input("Proceed?")`. Jupyter mode: auto-proceeds with stderr warning (since `input()` fails in async widget callbacks). Non-interactive mode (piped input, CI): catches EOFError and auto-proceeds.

**7.7 report_node** — Invokes GPT-4o via `get_llm("report")` for correlation summary. Calls `generate_tldr()` for the one-line summary. Calls `format_cli_report()` and `format_html_report()`. Report includes: TL;DR, timestamp, IOC details, per-source findings, AV detection names (hash IOCs), per-ecosystem breakdown (package_multi), conflict callouts, score breakdown, correlation, recommended actions.


## 8. LangChain Tool Layer

**8.1 Tool Base Class** (`agent/tools/base.py`)

All tools inherit from `ThreatIntelTool` (extends LangChain `BaseTool`):
- Async-first: `_arun()` uses `httpx.AsyncClient` (NOT `requests`)
- Exponential backoff: 3 attempts, delays 1.5s → 3.0s
- Each subclass implements only `_fetch(client, ioc) → dict`

**8.2 Tool Implementations**

| **Tool**       | **Module**          | **Endpoint**                                                         | **Auth**        |
|----------------|---------------------|----------------------------------------------------------------------|-----------------|
| **VirusTotal** | tools/virustotal.py | GET /api/v3/{ip_addresses\|domains\|files\|urls}/...                 | X-Apikey header |
| **AbuseIPDB**  | tools/abuseipdb.py  | GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90                     | Key header      |
| **OTX**        | tools/otx.py        | GET /api/v1/indicators/{type}/{ioc}/general                          | X-OTX-API-KEY   |
| **urlscan.io** | tools/urlscan.py    | POST /api/v1/scan/ → poll GET /api/v1/result/{uuid}/ (3s × 10)      | API-Key header  |
| **NIST NVD**   | tools/nvd.py        | GET /rest/json/cves/2.0?cveId={cve}                                  | None            |
| **OSVTool**    | tools/osv.py        | POST api.osv.dev/v1/query (single ecosystem)                        | None            |
| **OSVMultiTool**| tools/osv.py       | POST api.osv.dev/v1/query (×10 ecosystems in parallel)              | None            |
| **RegistryTool**| tools/registry.py  | GET registry.npmjs.org/{pkg} or pypi.org/pypi/{pkg}/json            | None            |


## 9. Scoring Engine (`agent/scoring.py`)

**9.1 Weight Sets** — four dicts, each summing to 1.00:

```python
BASE_WEIGHTS         = {virustotal: 0.40, abuseipdb: 0.30, otx: 0.20, urlscan: 0.10}
CVE_WEIGHTS          = {otx: 0.40, nvd: 0.60}
PACKAGE_WEIGHTS      = {osv: 0.60, registry: 0.40}
PACKAGE_MULTI_WEIGHTS = {osv_multi: 1.00}
```

**9.2 Normalisers** — 8 functions, each returning 0.0–1.0:

| Normaliser | Logic |
|-----------|-------|
| `normalise_virustotal` | Non-linear: 0 det→0.0, 1-2→0.20, 3-5→0.40, 6-15→0.60, 16-30→0.80, 31+→1.00 |
| `normalise_abuseipdb` | `confidenceScore / 100` |
| `normalise_otx` | 0 pulses→0.0, 1-2→0.5, 3+→scaled up |
| `normalise_urlscan` | score≥50→1.0, >0→0.5, malicious→1.0 |
| `normalise_nvd` | `CVSS baseScore / 10.0` |
| `normalise_osv` | MAL-→1.0, CRITICAL→0.90, HIGH→0.70, any→0.50, none→0.0 |
| `normalise_registry` | install scripts +0.40, age<7d +0.30, single maintainer +0.10, no repo +0.10 |
| `normalise_osv_multi` | Worst score across all 10 ecosystems |

**9.3 Conflict Detection** — `detect_conflicts()` flags when one source scores ≤0.20 and another ≥0.50.

**9.4 Rich Intel Extraction** — `extract_vt_detections()`, `extract_otx_campaigns()`, `extract_nvd_details()`, `extract_osv_details()`, `generate_tldr()`.


## 10. Observability Architecture (Arize AI)

**10.1 Instrumentation Initialisation** (`agent/tracing.py`)

```python
from arize.otel import register
from openinference.instrumentation.langchain import LangChainInstrumentor

def init_tracing(project_name='flowrun-streamlet-ioc-triage'):
    tracer_provider = register(
        space_id=os.getenv('ARIZE_SPACE_ID'),
        api_key=os.getenv('ARIZE_API_KEY'),
        project_name=project_name,      # NOTE: project_name, NOT model_id
    )
    LangChainInstrumentor().instrument(tracer_provider=tracer_provider)
    return tracer_provider
```

Auto-instruments all LangChain ChatModel calls, tool invocations, and LangGraph node executions. Custom manual spans added in `correlation_node` (flowrun.correlate) and `severity_node` (flowrun.severity) using `opentelemetry.trace`.

If Arize is unavailable, tracing fails silently — never blocks triage.


## 11. Credential Management

Resolution chain in `agent/credentials.py`:
1. `.env` file via `load_dotenv(override=False)`
2. `os.environ` check
3. `getpass()` for any still-missing keys

Required keys (7): OPENAI_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, URLSCAN_API_KEY, ARIZE_API_KEY, ARIZE_SPACE_ID.

Note: OSV.dev, npm registry, and PyPI JSON API require no API keys.


## 12. Supported Package Ecosystems (27)

The `ECOSYSTEM_MAP` in `agent/integrations/osv.py` supports these prefixes:

**Language packages (17):** npm, pypi (alias: pip), crates.io (alias: cargo), Go, Maven, NuGet, RubyGems (alias: gem), Packagist (alias: composer), Pub, Hex, Hackage, CRAN, SwiftURL, CocoaPods

**Linux distributions (7):** Red Hat (alias: redhat), Debian, Ubuntu, Alpine, Rocky Linux, AlmaLinux, SUSE (alias: opensuse)

**Other (3):** Android, Linux (kernel), Bitnami, curl

**Multi-scan ecosystems** (bare package names scan these 10): npm, PyPI, crates.io, Go, Maven, NuGet, RubyGems, Packagist, Pub, Hex


## 13. Extension Model

To add a new threat intelligence source:
1. Create `agent/integrations/newsource.py` (HTTP client + parser)
2. Create `agent/tools/newsource.py` (subclass ThreatIntelTool, implement `_fetch()`)
3. Add weight to appropriate weight dict in `agent/scoring.py` (ensure sum = 1.00)
4. Add normaliser function + register in NORMALISERS dict
5. Register tool in enrichment_node's task dict, gated on ioc_type
6. If source requires an API key: add to REQUIRED_KEYS in credentials.py + .env.template. If free/open (like OSV.dev): no credential changes needed.

No other files change — graph, state, routing, tracing adapt automatically.

---

*FlowRun Streamlet: IoC Triage — Architecture v3 — Reconciled with codebase v0.0.31*
