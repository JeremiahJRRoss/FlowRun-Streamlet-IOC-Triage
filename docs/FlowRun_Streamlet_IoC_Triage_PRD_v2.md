> **PRODUCT REQUIREMENTS DOCUMENT**
> **FlowRun Streamlet: IoC Triage**
> Automated Threat Intelligence Triage for Security Operations
> LangGraph + LangChain + Arize AI + OpenAI GPT-4o

| **Field**             | **Value**                                                    |
|-----------------------|--------------------------------------------------------------|
| **Document Type**     | Product Requirements Document (PRD)                          |
| **Product Name**      | FlowRun Streamlet: IoC Triage                                |
| **Version**           | v0.0.31                                                      |
| **Status**            | Active — Reconciled with codebase                            |
| **Owner**             | Security Platform Engineering                                |
| **Stakeholders**      | SOC Operations, Security Engineering, Platform Observability |
| **Agentic Framework** | LangGraph + LangChain                                        |
| **Observability**     | Arize AI (OpenInference tracing)                             |


## 1. Executive Summary

The FlowRun Streamlet: IoC Triage is an AI-powered security operations tool that automates the investigation of Indicators of Compromise (IOCs). Built on LangGraph and LangChain with full observability through Arize AI, the agent compresses a 10–25 minute manual analyst workflow into a sub-30-second automated pipeline while producing a full audit trail of every decision made.

| **Attribute**           | **Value**                                                                                |
|-------------------------|------------------------------------------------------------------------------------------|
| **Primary User**        | Tier 1 / Tier 2 SOC Analysts                                                             |
| **Core Value Prop**     | 10-25 min manual triage → sub-30 sec automated triage with full trace audit              |
| **Agentic Framework**   | LangGraph 0.2+ (StateGraph with conditional routing)                                     |
| **LLM**                 | OpenAI GPT-4o-mini (classification) + GPT-4o (report synthesis) via LangChain            |
| **Observability**       | Arize AI with OpenInference auto-instrumentation                                         |
| **Deployment Target**   | Local CLI + Jupyter Notebook (v0.0.31); REST API (v2.0 roadmap)                          |
| **IOC Types Supported** | IP, Domain, URL, File Hash (MD5/SHA-1/SHA-256), CVE, Package, Package Multi-Scan         |


## 2. Problem Statement & Goals

**2.1 Problem Statement**

Security Operations Centers face a structural imbalance between alert volume and analyst capacity. A mid-sized enterprise generates thousands of security alerts per day. Each alert that contains an IOC requires a manual multi-source investigation before an analyst can make a triage decision.

> **Core Problem Statement**
> Security teams are drowning in IOCs that take too long to investigate manually. Existing automation lacks the transparency needed to trust, audit, and improve triage decisions.

**2.2 Goals**

| **ID**   | **Goal**                                                                               |
|----------|----------------------------------------------------------------------------------------|
| **G-01** | Reduce per-IOC triage time from 10–25 minutes to under 30 seconds                      |
| **G-02** | Aggregate intelligence from 4+ sources in a single, standardized workflow              |
| **G-03** | Produce a deterministic, explainable severity verdict for every IOC                    |
| **G-04** | Generate a complete, traceable audit trail for every triage decision via Arize AI      |
| **G-05** | Deliver a Jupyter Notebook interface suitable for demos, training, and experimentation |
| **G-06** | Ensure zero hardcoded credentials — all keys managed via secure runtime injection      |
| **G-07** | Detect malicious software packages across 27 ecosystems via OSV.dev                   |

**2.3 Non-Goals (v0.0.31)**

- No REST API or web UI — CLI and Jupyter only
- No SIEM integration (Splunk, Sentinel, etc.) — planned for v2.0
- No automated remediation (blocking IPs, revoking certs, etc.)
- No bulk IOC ingestion from CSV or file upload


## 3. User Personas

| **Type**      | **Persona**              | **Description**                                                                                                                                         |
|---------------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Primary**   | Tier 1 SOC Analyst       | Investigates IOCs as part of daily alert queue. Needs fast, reliable verdicts with clear recommended actions.                                            |
| **Primary**   | Tier 2 SOC Analyst       | Validates escalated alerts, hunts threats proactively. Uses the agent to accelerate enrichment.                                                         |
| **Secondary** | Security Engineer        | Builds, maintains, and extends the agent. Needs clean architecture, observable behavior, and well-defined integration points.                           |
| **Secondary** | DevSecOps Engineer       | Uses package scanning to detect supply chain attacks in CI/CD pipelines.                                                                                |
| **Tertiary**  | Demo Presenter / Trainer | Runs the Jupyter Notebook version live to explain LangGraph, LangChain, and Arize AI.                                                                  |


## 4. Functional Requirements

**4.1 IOC Input & Classification**

| **ID**    | **Priority** | **Requirement**                                                                                                                                                          |
|-----------|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **FR-01** | MUST         | Accept a single IOC string as input via CLI interactive prompt or Jupyter notebook widget                                                                                |
| **FR-02** | MUST         | Automatically detect IOC type: IPv4/IPv6, domain, URL, MD5 hash, SHA-1 hash, SHA-256 hash, CVE identifier, prefixed package (ecosystem:name), or bare package name      |
| **FR-03** | MUST         | Validate IOC format and surface a clear error message if the format is unrecognizable                                                                                    |
| **FR-04** | SHOULD       | Detect and handle common formatting noise (trailing spaces, mixed case, http vs https prefixes)                                                                          |
| **FR-04a**| MUST         | Bare package names (e.g., `traceroute`) must be auto-scanned across 10 major language ecosystems simultaneously                                                          |

**4.2 Threat Intelligence Enrichment**

| **ID**    | **Priority** | **Requirement**                                                                                                             |
|-----------|--------------|-----------------------------------------------------------------------------------------------------------------------------|
| **FR-05** | MUST         | Query VirusTotal for malicious engine vote count (IP, domain, URL, hash types only — NOT CVE or package)                    |
| **FR-06** | MUST         | Query AbuseIPDB for abuse confidence score, report count, and abuse categories (IP addresses only)                          |
| **FR-07** | MUST         | Query AlienVault OTX for matching threat intelligence pulses and associated threat actor/campaign tags (all types except package) |
| **FR-08** | MUST         | Query urlscan.io for live behavioral sandbox analysis (URL and domain types)                                                |
| **FR-09** | SHOULD       | Query NIST NVD for CVE details and CVSS score (CVE type only)                                                               |
| **FR-09a**| MUST         | Query OSV.dev for known malicious packages and vulnerabilities (package type only). No API key required.                    |
| **FR-09b**| MUST         | Query OSV.dev across 10 language ecosystems simultaneously for bare package names (package_multi type)                      |
| **FR-09c**| SHOULD       | Query npm/PyPI registries for package metadata: creation date, maintainers, install scripts, source repo (package type only)|
| **FR-10** | MUST         | Execute all applicable API queries in parallel, not sequentially                                                            |
| **FR-10a**| MUST         | For URL types, extract the domain and query VT + OTX at both the URL and domain level, keeping the stronger signal          |
| **FR-11** | MUST         | Handle individual API failures gracefully — a single source timeout must not abort the full triage                          |

**4.3 Correlation & Severity Scoring**

| **ID**    | **Priority** | **Requirement**                                                                                                            |
|-----------|--------------|----------------------------------------------------------------------------------------------------------------------------| 
| **FR-12** | MUST         | Aggregate all raw API results into a composite threat score using a defined weighted formula                               |
| **FR-13** | MUST         | Map composite score to one of five severity tiers: CLEAN, LOW, MEDIUM, HIGH, CRITICAL                                      |
| **FR-14** | MUST         | Generate a plain-English justification string explaining the verdict, citing which sources drove the score                 |
| **FR-15** | MUST         | Detect and surface conflicting signals (e.g., VT clean but OTX shows active APT pulse) as a highlighted warning           |
| **FR-16** | MUST         | If severity is CRITICAL, route to a human-in-the-loop confirmation step before finalizing output                           |

**4.4 Report Generation**

| **ID**    | **Priority** | **Requirement**                                                                                                            |
|-----------|--------------|----------------------------------------------------------------------------------------------------------------------------| 
| **FR-17** | MUST         | Render a structured threat report to the terminal (CLI) or notebook output cell (Jupyter)                                 |
| **FR-18** | MUST         | Report must include: TL;DR summary, IOC value/type, per-source findings, correlation summary, severity verdict, recommended actions |
| **FR-18a**| MUST         | For hash IOCs, display top antivirus engine detection names (e.g., "Kaspersky: Trojan.Win32.Agent")                        |
| **FR-18b**| MUST         | For CVE IOCs, display CVSS severity string and attack vector (e.g., "CVSS: 9.8 (CRITICAL), Vector: NETWORK")              |
| **FR-18c**| MUST         | For OTX results, display threat actor names and campaign tags (not just pulse count)                                       |
| **FR-18d**| MUST         | For package_multi IOCs, display per-ecosystem breakdown showing which ecosystems have advisories                           |
| **FR-19** | SHOULD       | Report should be formatted for copy-paste into a SIEM ticket or email                                                     |

**4.5 Credential Management**

| **ID**    | **Priority** | **Requirement**                                                                                                            |
|-----------|--------------|----------------------------------------------------------------------------------------------------------------------------| 
| **FR-21** | MUST         | Never accept or store API keys as hardcoded values in source code                                                          |
| **FR-22** | MUST         | On startup: detect presence of .env file and load keys automatically if found                                              |
| **FR-23** | MUST         | If no .env file: prompt interactively for each key using masked input (getpass)                                            |
| **FR-24** | MUST         | Keys entered interactively must be stored only in memory — never written to disk                                           |
| **FR-25** | MUST         | Jupyter Notebook Cell 2 must never assign API keys as plain-text string literals                                           |
| **FR-26** | SHOULD       | Display a clear warning if .env file is found but one or more required keys are missing                                    |

**4.6 Arize AI Observability**

| **ID**    | **Priority** | **Requirement**                                                                                                            |
|-----------|--------------|----------------------------------------------------------------------------------------------------------------------------| 
| **FR-27** | MUST         | Initialize an OpenInference tracer connected to the user's Arize Space on agent startup                                   |
| **FR-28** | MUST         | Every LangGraph node execution must generate a trace span                                                                  |
| **FR-29** | MUST         | Every LangChain tool call must be captured as a child span                                                                 |
| **FR-30** | MUST         | Severity verdict and composite score must be recorded as span attributes                                                   |
| **FR-31** | MUST         | Export all traces to Arize in real-time using the arize-otel exporter                                                      |
| **FR-32** | SHOULD       | Print a direct URL to the trace in the Arize UI after each run                                                             |

**4.7 Jupyter Notebook Interface**

| **ID**    | **Priority** | **Requirement**                                                                                                            |
|-----------|--------------|----------------------------------------------------------------------------------------------------------------------------| 
| **FR-34** | MUST         | Ship a self-contained Jupyter Notebook mirroring all CLI agent functionality                                               |
| **FR-35** | MUST         | Notebook must follow the 8-cell structure                                                                                  |
| **FR-36** | MUST         | Cell 6 must render an ipywidgets text input and Analyze button                                                             |
| **FR-37** | MUST         | Cell outputs must not display API keys at any point                                                                        |
| **FR-38** | SHOULD       | Each cell must include a markdown explanation suitable for live demo                                                        |


## 5. Non-Functional Requirements

| **ID**     | **Category**    | **Requirement**                                                                                                              |
|------------|-----------------|------------------------------------------------------------------------------------------------------------------------------|
| **NFR-01** | Performance     | End-to-end triage must complete in under 30 seconds under normal API conditions                                              |
| **NFR-02** | Performance     | Parallel enrichment must not serialize API calls — all applicable sources queried concurrently via asyncio.gather()           |
| **NFR-03** | Reliability     | Any single API source failure must not crash the agent — failed sources logged as 'unavailable'                              |
| **NFR-04** | Security        | No API keys stored in code, logs, notebook output, or any persistent file except user-controlled .env                        |
| **NFR-05** | Security        | All outbound API calls must use HTTPS                                                                                        |
| **NFR-06** | Observability   | 100% of agent runs must produce a trace in Arize with all required spans                                                    |
| **NFR-07** | Observability   | Arize trace failure must not block triage completion                                                                         |
| **NFR-08** | Portability     | Agent must run on macOS 12+, Ubuntu 20.04+, and Windows 10+ (via WSL2)                                                       |
| **NFR-09** | Maintainability | Each API integration must be an independent LangChain Tool, replaceable without modifying the graph                          |
| **NFR-10** | Usability       | A user with no prior LangGraph experience must be able to run a triage in under 5 minutes via Jupyter                        |


## 6. Architecture & Technical Design

**6.1 System Layers**

| **Layer**               | **Description**                                                                                                              |
|-------------------------|------------------------------------------------------------------------------------------------------------------------------|
| **Interaction Layer**   | CLI (interactive terminal) + Jupyter Notebook (ipywidgets). Accepts raw IOC input, displays reports.                         |
| **Agent Orchestration** | LangGraph StateGraph with typed AgentState. Manages node execution, conditional routing.                                     |
| **LLM Integration**     | LangChain + OpenAI. GPT-4o-mini (temperature=0.0) for classification. GPT-4o (temperature=0.3) for report synthesis. Both configured in agent/llm.py MODEL_CONFIG. |
| **Tool / API Layer**    | LangChain Tool-wrapped async httpx clients for VirusTotal, AbuseIPDB, OTX, urlscan.io, NIST NVD, OSV.dev, and npm/PyPI registries. |
| **Observability Layer** | OpenInference auto-instrumentation. arize-otel OTLP exporter streaming spans to Arize AI platform.                          |

**6.2 LangGraph Node Definitions**

| **Node Name**        | **Responsibility**                                                                                                                                                 |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **input_node**       | Receives raw IOC string, runs regex pre-classification, initializes AgentState                                                                                      |
| **classifier_node**  | GPT-4o-mini: detects IOC type if regex was inconclusive. Routes to enrichment or error.                                                                            |
| **enrichment_node**  | asyncio.gather(): fires all applicable tool coroutines concurrently. For URL types, also queries domain-level VT + OTX. For package_multi, scans 10 ecosystems.    |
| **correlation_node** | Pure Python: reads raw_intel, applies weighted scoring via compute_composite(raw_intel, intel_errors, ioc_type), detects conflicting signals                        |
| **severity_node**    | Maps composite_score to severity_band (CLEAN/LOW/MEDIUM/HIGH/CRITICAL), writes verdict_justification                                                               |
| **report_node**      | GPT-4o synthesises correlation summary. Formats CLI text + HTML report with TL;DR, detection names, conflict callouts.                                              |
| **escalation_gate**  | If severity_band == CRITICAL: CLI mode → input() prompt; Jupyter mode → auto-proceeds with warning.                                                                |
| **error_node**       | Handles unrecognised IOC types with clear error message.                                                                                                           |

**6.3 AgentState Schema**

```python
class AgentState(TypedDict):
    ioc_raw: str                        # Original user input
    ioc_clean: str                      # Normalised value
    ioc_type: str                       # ip|domain|url|hash_md5|hash_sha1|hash_sha256|cve|package|package_multi|unknown
    raw_intel: dict[str, Any]           # {source_name: parsed_response_dict}
    intel_errors: list[str]             # Non-fatal errors
    score_breakdown: dict[str, float]   # Per-source normalised 0.0–1.0 scores
    composite_score: float              # Weighted aggregate
    active_weights: dict[str, float]    # Re-normalised if sources unavailable
    severity_band: str                  # CLEAN|LOW|MEDIUM|HIGH|CRITICAL
    verdict_justification: str          # Plain-English explanation
    escalation_required: bool           # True only when CRITICAL
    report_text: str                    # CLI-formatted report
    report_html: str                    # HTML-formatted report for Jupyter
    arize_trace_url: str                # URL to trace in Arize UI
```

**6.4 Severity Scoring Formula**

Four weight sets, each summing to 1.00. When sources are unavailable, weights are redistributed proportionally.

**BASE_WEIGHTS** (IP, domain, URL, hash types):

| **Signal**                     | **Weight** | **Normalization**                                                                  |
|--------------------------------|------------|------------------------------------------------------------------------------------|
| **VirusTotal detection count** | 0.40       | Non-linear tiered: 0→0.0, 1-2→0.20, 3-5→0.40, 6-15→0.60, 16-30→0.80, 31+→1.00  |
| **AbuseIPDB confidence score** | 0.30       | Direct 0–100 → 0.0–1.0 (IP only; redistributed for other types)                   |
| **OTX pulse match**            | 0.20       | 0.0 if no pulses, 0.5 if 1–2 pulses, scaled up for 3+                             |
| **urlscan.io verdict**         | 0.10       | score≥50 → 1.0, score>0 → 0.5, malicious flag → 1.0 (URL+domain; redistributed for others) |

**CVE_WEIGHTS** (CVE type only — VirusTotal excluded, has no CVE endpoint):

| **Signal**        | **Weight** | **Normalization**                                     |
|-------------------|------------|-------------------------------------------------------|
| **OTX pulse**     | 0.40       | Same as above                                         |
| **NIST NVD CVSS** | 0.60       | CVSS base score / 10.0                                |

**PACKAGE_WEIGHTS** (prefixed package type, e.g., npm:postmark-mcp):

| **Signal**            | **Weight** | **Normalization**                                                          |
|-----------------------|------------|----------------------------------------------------------------------------|
| **OSV.dev**           | 0.60       | MAL-→1.0, CRITICAL→0.90, HIGH→0.70, any advisory→0.50, none→0.0         |
| **Registry metadata** | 0.40       | install scripts +0.40, age<7d +0.30, single maintainer +0.10, no repo +0.10 |

**PACKAGE_MULTI_WEIGHTS** (bare package name, e.g., traceroute):

| **Signal**                 | **Weight** | **Normalization**                             |
|----------------------------|------------|-----------------------------------------------|
| **OSV.dev multi-scan**     | 1.00       | Takes worst score across all 10 ecosystems    |

**Severity Tiers:**

| **Score Range** | **Verdict** | **Recommended Action**                                       |
|-----------------|-------------|--------------------------------------------------------------|
| 0.00 – 0.10    | 🟢 CLEAN    | No credible threat signals                                   |
| 0.11 – 0.30    | 🟡 LOW      | Minor or stale signals — monitor                             |
| 0.31 – 0.55    | 🟠 MEDIUM   | Credible signals — investigate and consider blocking         |
| 0.56 – 0.75    | 🔴 HIGH     | Strong signals — block and escalate                          |
| 0.76 – 1.00    | 🚨 CRITICAL | Confirmed malicious — block immediately, trigger IR playbook |

**6.5 Technology Stack**

| **Package**                                 | **Version** | **Purpose**                                                            |
|---------------------------------------------|-------------|------------------------------------------------------------------------|
| **LangGraph**                               | 0.2+        | StateGraph orchestration, conditional edges, human-in-the-loop         |
| **LangChain**                               | 0.3+        | Tool definitions, LLM wrappers, output parsers                        |
| **OpenAI Python SDK**                       | 1.0+        | GPT-4o-mini for classification; GPT-4o for report synthesis            |
| **httpx**                                   | 0.27+       | Async HTTP client for all threat intel API calls                       |
| **arize-otel**                              | Latest      | OpenInference OTLP exporter to Arize AI                               |
| **openinference-instrumentation-langchain** | Latest      | Auto-instrumentation for LangChain/LangGraph operations                |
| **python-dotenv**                           | 1.0+        | Loads .env file into os.environ at startup                             |
| **ipywidgets**                              | 8.0+        | Jupyter Notebook IOC input widget                                      |
| **Python**                                  | 3.11+       | Runtime. asyncio required for parallel enrichment.                     |


## 7. External API Integrations

| **Service**            | **Base URL**                                | **Env Variable**   | **IOC Types**            | **Free Tier Limits**        |
|------------------------|---------------------------------------------|--------------------|--------------------------|-----------------------------|
| **VirusTotal v3**      | https://www.virustotal.com/api/v3           | VIRUSTOTAL_API_KEY | IP, domain, URL, hash    | 4 req/min, 500/day          |
| **AbuseIPDB v2**       | https://api.abuseipdb.com/api/v2/check      | ABUSEIPDB_API_KEY  | IP only                  | 1,000 req/day               |
| **AlienVault OTX v1**  | https://otx.alienvault.com/api/v1/indicators| OTX_API_KEY        | IP, domain, URL, hash, CVE | Generous                  |
| **urlscan.io v1**      | https://urlscan.io/api/v1/scan/             | URLSCAN_API_KEY    | URL, domain              | 100 scans/day               |
| **NIST NVD 2.0**       | https://services.nvd.nist.gov/rest/json/cves/2.0 | None         | CVE only                 | 5 req/30s unauthenticated   |
| **OSV.dev**            | https://api.osv.dev/v1/query (POST)         | None               | package, package_multi   | No limits (free, open)      |
| **npm Registry**       | https://registry.npmjs.org/{package}        | None               | package (npm only)       | No limits (free, open)      |
| **PyPI JSON API**      | https://pypi.org/pypi/{package}/json        | None               | package (pypi only)      | No limits (free, open)      |

**API Routing by IOC Type:**

| API            | IP | Domain | URL | Hash | CVE | Package | Package Multi |
|----------------|:--:|:------:|:---:|:----:|:---:|:-------:|:-------------:|
| VirusTotal     | ✅ | ✅     | ✅  | ✅   | ❌  | ❌      | ❌            |
| AbuseIPDB      | ✅ | ❌     | ❌  | ❌   | ❌  | ❌      | ❌            |
| OTX            | ✅ | ✅     | ✅  | ✅   | ✅  | ❌      | ❌            |
| urlscan.io     | ❌ | ✅     | ✅  | ❌   | ❌  | ❌      | ❌            |
| NIST NVD       | ❌ | ❌     | ❌  | ❌   | ✅  | ❌      | ❌            |
| OSV.dev        | ❌ | ❌     | ❌  | ❌   | ❌  | ✅      | ❌            |
| OSV.dev (×10)  | ❌ | ❌     | ❌  | ❌   | ❌  | ❌      | ✅            |
| npm Registry   | ❌ | ❌     | ❌  | ❌   | ❌  | ✅*     | ❌            |
| PyPI JSON API  | ❌ | ❌     | ❌  | ❌   | ❌  | ✅*     | ❌            |

*npm/PyPI registry queried only when ecosystem is npm or pypi respectively.


## 8. Observability Design (Arize AI)

**8.1 Trace Structure**

Each agent run produces a single root trace with spans mirroring the LangGraph execution graph. Auto-instrumented by OpenInference + manual custom spans for correlation and severity nodes.

**8.2 Required Span Attributes**

| **Span Name**         | **Required Attributes**                                                               |
|-----------------------|---------------------------------------------------------------------------------------|
| **flowrun.triage**    | ioc.type, ioc.value, severity.band, composite.score, run.duration_ms                  |
| **flowrun.classify**  | llm.model, llm.prompt_tokens, llm.completion_tokens, ioc.detected_type                |
| **tool.\***           | tool.name, tool.input, tool.output_raw, tool.latency_ms, tool.status                  |
| **flowrun.correlate** | score.{source}, composite.score, weights.active                                       |
| **flowrun.severity**  | severity.band, verdict.justification, escalation.required                              |


## 9. Credential Management

| **Variable Name**      | **Required?** | **Where to Obtain**                 |
|------------------------|---------------|-------------------------------------|
| **OPENAI_API_KEY**     | Required      | platform.openai.com → API Keys      |
| **VIRUSTOTAL_API_KEY** | Required      | virustotal.com → Profile → API Key  |
| **ABUSEIPDB_API_KEY**  | Required      | abuseipdb.com → Account → API       |
| **OTX_API_KEY**        | Required      | otx.alienvault.com → Settings       |
| **URLSCAN_API_KEY**    | Required      | urlscan.io → Settings → API Keys    |
| **ARIZE_API_KEY**      | Required      | app.arize.com → Settings → API Keys |
| **ARIZE_SPACE_ID**     | Required      | app.arize.com → Settings → API Keys |

Note: OSV.dev, npm registry, and PyPI JSON API require no API keys.

Resolution order: (1) .env file → (2) os.environ → (3) interactive getpass(). Keys never logged, printed, or included in Arize span attributes.


## 10. Acceptance Criteria

| **ID**    | **Test Case**                  | **Pass Criterion**                                                                                                                |
|-----------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| **AC-01** | Malicious IP                   | Known-malicious IP returns HIGH or CRITICAL (score > 0.56)                                                                        |
| **AC-02** | Clean IP (8.8.8.8)            | Returns CLEAN or LOW (score < 0.30)                                                                                               |
| **AC-03** | IOC Type Detection             | Correctly identifies: IPv4, domain, URL, MD5, SHA-1, SHA-256, CVE, prefixed package, bare package name                            |
| **AC-04** | Parallel Execution             | Enrichment time ≤ 1.5× slowest single API (not sequential sum)                                                                   |
| **AC-05** | API Failure Tolerance          | VT 500 error → triage completes with remaining sources, report shows "unavailable"                                                |
| **AC-06** | Arize Trace                    | Trace appears in Arize within 10 seconds with all required spans                                                                  |
| **AC-07** | Key Security                   | `grep -r "sk-" .` returns zero hardcoded key values                                                                               |
| **AC-08** | Jupyter Key Masking            | Saved .ipynb contains no API key values in cell outputs                                                                           |
| **AC-09** | CRITICAL Escalation            | CRITICAL verdict pauses in CLI; auto-proceeds with warning in Jupyter                                                             |
| **AC-10** | End-to-End Latency             | Full triage completes in under 30 seconds                                                                                         |
| **AC-11** | Malicious Package              | npm package with MAL- advisory returns CRITICAL                                                                                   |
| **AC-12** | Clean Package                  | Established npm package with no advisories returns CLEAN/LOW                                                                      |
| **AC-13** | Bare Package Multi-Scan        | Bare name scans 10 ecosystems, reports per-ecosystem results                                                                      |
| **AC-14** | Conflicting Signals            | When VT clean but OTX shows pulses, conflict warning appears in report                                                           |


## 11. Risks & Mitigations

| **ID**   | **Severity** | **Risk**                                            | **Mitigation**                                                                              |
|----------|--------------|-----------------------------------------------------|---------------------------------------------------------------------------------------------|
| **R-01** | HIGH         | Free API rate limits exhausted during demo          | Use known-safe test IOCs. Cache results for demo runs.                                      |
| **R-02** | MEDIUM       | VirusTotal key flagged for excessive use            | Implement request throttling. Non-linear VT normaliser reduces need for multiple queries.   |
| **R-03** | MEDIUM       | Arize trace export fails silently                   | Wrap in try/except; log to stderr but never block triage (NFR-07).                          |
| **R-04** | LOW          | GPT-4o-mini misclassifies IOC type                  | Regex pre-classification resolves 9 of 10 IOC types before LLM is called.                  |
| **R-05** | LOW          | urlscan.io public scans expose IOC                  | Documented: use private scan API for sensitive IOCs.                                        |


## 12. Future Roadmap

| **Target** | **Feature**          | **Description**                                                                    |
|------------|----------------------|------------------------------------------------------------------------------------|
| **v2.0**   | REST API             | FastAPI wrapper for programmatic IOC submission                                    |
| **v2.0**   | SIEM Integration     | Cribl, Elastic, and Splunk connectors                                                     |
| **v2.0**   | Bulk IOC Ingestion   | CSV file upload for batch triage                                                   |
| **v2.1**   | Arize Evaluations    | Span and trace-level LLM-as-judge evaluations                                     |
| **v2.1**   | Socket.dev           | Real-time supply chain attack detection (install script analysis, network behavior)|
| **v3.0**   | Multi-Agent SOC      | Supervisor + sub-agent architecture                                                |

---

*FlowRun Streamlet: IoC Triage — PRD v3 — Reconciled with codebase v0.0.31*
