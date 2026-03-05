> **PRODUCT REQUIREMENTS DOCUMENT**
> **FlowRun Streamlet: IoC Triage**
> Automated Threat Intelligence Triage for Security Operations
> LangGraph + LangChain + Arize AI + OpenAI GPT-5.2


|                       |                                                              |
|-----------------------|--------------------------------------------------------------|
| **Field**             | **Value**                                                    |
| **Document Type**     | Product Requirements Document (PRD)                          |
| **Product Name**      | FlowRun Streamlet: IoC Triage                                |
| **Version**           | 1.0.0 — Initial Release                                      |
| **Status**            | Draft — Pending Engineering Review                           |
| **Owner**             | Security Platform Engineering                                |
| **Stakeholders**      | SOC Operations, Security Engineering, Platform Observability |
| **Agentic Framework** | LangGraph + LangChain                                        |
| **Observability**     | Arize AI (OpenInference tracing)                             |




## 1. Executive Summary

The FlowRun Streamlet: IoC Triage is an AI-powered security operations tool that automates the investigation of Indicators of Compromise (IOCs). Built on LangGraph and LangChain with full observability through Arize AI, the agent compresses a 10–25 minute manual analyst workflow into a sub-30-second automated pipeline while producing a full audit trail of every decision made.

This document defines the full product requirements for the v1.0 release, covering functional requirements, non-functional requirements, architecture, API integrations, observability design, user interface specifications, and acceptance criteria.

|                         |                                                                                          |
|-------------------------|------------------------------------------------------------------------------------------|
| **Attribute**           | **Value**                                                                                |
| **Primary User**        | Tier 1 / Tier 2 SOC Analysts                                                             |
| **Core Value Prop**     | 10-25 min manual triage → sub-30 sec automated triage with full trace audit              |
| **Agentic Framework**   | LangGraph 0.2+ (StateGraph with parallel fan-out and conditional routing)                |
| **LLM**                 | OpenAI GPT-5.2 (Instant for classification, Thinking for report synthesis) via LangChain |
| **Observability**       | Arize AI with OpenInference auto-instrumentation                                         |
| **Deployment Target**   | Local CLI + Jupyter Notebook (v1.0); REST API (v2.0 roadmap)                             |
| **IOC Types Supported** | IP Address, Domain, URL, File Hash (MD5 / SHA-1 / SHA-256), CVE Identifier               |




## 2. Problem Statement & Goals

**2.1 Problem Statement**

Security Operations Centers face a structural imbalance between alert volume and analyst capacity. A mid-sized enterprise generates thousands of security alerts per day. Each alert that contains an IOC requires a manual multi-source investigation before an analyst can make a triage decision. The current workflow forces analysts to:

- Manually query 3–6 separate threat intelligence platforms one at a time

- Reconcile inconsistent scoring systems and data formats across sources

- Apply judgment under time pressure with no standardized severity rubric

- Document findings manually in a ticket or SIEM — a process prone to omission

Beyond analyst fatigue and throughput limitations, existing automation tools in this space operate as black boxes. When an automated triage produces a wrong result — a false positive that blocks a legitimate IP, or a false negative that misses a known threat — there is no structured audit trail that explains the reasoning, allowing the same error to recur.


> **Core Problem Statement**
> Security teams are drowning in IOCs that take too long to investigate manually.
> Existing automation lacks the transparency needed to trust, audit, and improve triage decisions.


**2.2 Goals**

|          |                                                                                        |
|----------|----------------------------------------------------------------------------------------|
| **ID**   | **Goal**                                                                               |
| **G-01** | Reduce per-IOC triage time from 10–25 minutes to under 30 seconds                      |
| **G-02** | Aggregate intelligence from 4+ sources in a single, standardized workflow              |
| **G-03** | Produce a deterministic, explainable severity verdict for every IOC                    |
| **G-04** | Generate a complete, traceable audit trail for every triage decision via Arize AI      |
| **G-05** | Deliver a Jupyter Notebook interface suitable for demos, training, and experimentation |
| **G-06** | Ensure zero hardcoded credentials — all keys managed via secure runtime injection      |

**2.3 Non-Goals (v1.0)**

- This version does not include a REST API or web UI — CLI and Jupyter only

- This version does not integrate with SIEM platforms (Splunk, Sentinel, etc.) — planned for v2.0

- This version does not perform automated remediation (blocking IPs, revoking certs, etc.)

- This version does not support bulk IOC ingestion from CSV or file upload




## 3. User Personas

|               |                          |                                                                                                                                                         |
|---------------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Type**      | **Persona**              | **Description**                                                                                                                                         |
| **Primary**   | Tier 1 SOC Analyst       | Investigates IOCs as part of daily alert queue. Needs fast, reliable verdicts with clear recommended actions. May not have deep threat intel expertise. |
| **Primary**   | Tier 2 SOC Analyst       | Validates escalated alerts, hunts threats proactively. Uses the agent to accelerate enrichment on suspicious artifacts found during investigation.      |
| **Secondary** | Security Engineer        | Builds, maintains, and extends the agent. Needs clean architecture, observable behavior, and well-defined integration points.                           |
| **Secondary** | SOC Manager / CISO       | Reviews triage quality and audit logs in Arize. Interested in metrics: false positive rate, triage throughput, and verdict accuracy over time.          |
| **Tertiary**  | Demo Presenter / Trainer | Runs the Jupyter Notebook version live to explain LangGraph, LangChain, and Arize AI to a technical or semi-technical audience.                         |




## 4. Functional Requirements

**4.1 IOC Input & Classification**

|           |              |                                                                                                                                           |
|-----------|--------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| **ID**    | **Priority** | **Requirement**                                                                                                                           |
| **FR-01** | MUST         | Accept a single IOC string as input via CLI interactive prompt or Jupyter notebook widget                                                 |
| **FR-02** | MUST         | Automatically detect IOC type: IPv4 address, domain name, URL, MD5 hash, SHA-1 hash, SHA-256 hash, CVE identifier (CVE-YYYY-NNNNN format) |
| **FR-03** | MUST         | Validate IOC format and surface a clear error message if the format is unrecognizable                                                     |
| **FR-04** | SHOULD       | Detect and handle IOCs with common formatting noise (trailing spaces, mixed case domains, http vs https prefixes)                         |

**4.2 Threat Intelligence Enrichment**

|           |              |                                                                                                             |
|-----------|--------------|-------------------------------------------------------------------------------------------------------------|
| **ID**    | **Priority** | **Requirement**                                                                                             |
| **FR-05** | MUST         | Query VirusTotal for malicious engine vote count, suspicious count, and community verdict for all IOC types |
| **FR-06** | MUST         | Query AbuseIPDB for abuse confidence score, report count, and abuse categories (IP addresses only)          |
| **FR-07** | MUST         | Query AlienVault OTX for matching threat intelligence pulses and associated threat actor/campaign tags      |
| **FR-08** | MUST         | Query urlscan.io for live behavioral sandbox analysis (URL IOC type only)                                   |
| **FR-09** | SHOULD       | Query NIST NVD for CVE details and CVSS score (if IOC matches CVE format)                                   |
| **FR-10** | MUST         | Execute all applicable API queries in parallel, not sequentially                                            |
| **FR-11** | MUST         | Handle individual API failures gracefully — a single source timeout must not abort the full triage          |

**4.3 Correlation & Severity Scoring**

|           |              |                                                                                                                            |
|-----------|--------------|----------------------------------------------------------------------------------------------------------------------------|
| **ID**    | **Priority** | **Requirement**                                                                                                            |
| **FR-12** | MUST         | Aggregate all raw API results into a composite threat score using a defined weighted formula                               |
| **FR-13** | MUST         | Map composite score to one of five severity tiers: CLEAN, LOW, MEDIUM, HIGH, CRITICAL                                      |
| **FR-14** | MUST         | Generate a plain-English justification string explaining the verdict, citing which sources drove the score                 |
| **FR-15** | SHOULD       | Flag and surface data conflicts — e.g., VirusTotal clean but OTX shows active APT pulse — as a noted anomaly in the report |
| **FR-16** | MUST         | If severity is CRITICAL, route to a human-in-the-loop confirmation step before finalizing output                           |

**4.4 Report Generation**

|           |              |                                                                                                                                                                   |
|-----------|--------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **ID**    | **Priority** | **Requirement**                                                                                                                                                   |
| **FR-17** | MUST         | Render a structured threat report to the terminal (CLI) or notebook output cell (Jupyter)                                                                         |
| **FR-18** | MUST         | Report must include: IOC value and type, per-source intelligence findings, correlation summary, severity verdict with justification, and recommended next actions |
| **FR-19** | SHOULD       | Report should be formatted for copy-paste into a SIEM ticket or email without additional editing                                                                  |
| **FR-20** | COULD        | Optionally export the report as a JSON file to a configurable output directory                                                                                    |

**4.5 Credential Management**

|           |              |                                                                                                                                                                                                                                                                                |
|-----------|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **ID**    | **Priority** | **Requirement**                                                                                                                                                                                                                                                                |
| **FR-21** | MUST         | Never accept or store API keys as hardcoded values in source code                                                                                                                                                                                                              |
| **FR-22** | MUST         | On startup: detect presence of .env file and load keys automatically if found                                                                                                                                                                                                  |
| **FR-23** | MUST         | If no .env file is found: prompt the user interactively for each key using masked input (getpass)                                                                                                                                                                              |
| **FR-24** | MUST         | Keys entered interactively must be stored only in memory for the session — never written to disk                                                                                                                                                                               |
| **FR-25** | MUST         | Jupyter Notebook Cell 2 must never assign API keys as plain-text string literals. Permitted approaches are: (a) getpass() for masked interactive input, or (b) load_dotenv() loading from a .env file. Direct string assignment (e.g., KEY='sk-abc') is prohibited in any cell |
| **FR-26** | SHOULD       | Display a clear warning if the .env file is found but one or more required keys are missing                                                                                                                                                                                    |

**4.6 Arize AI Observability**

|           |              |                                                                                                             |
|-----------|--------------|-------------------------------------------------------------------------------------------------------------|
| **ID**    | **Priority** | **Requirement**                                                                                             |
| **FR-27** | MUST         | Initialize an OpenInference tracer connected to the user's Arize Space on agent startup                     |
| **FR-28** | MUST         | Every LangGraph node execution must generate a trace span with input state, output state, and latency       |
| **FR-29** | MUST         | Every LangChain tool call (API request) must be captured as a child span under its parent node span         |
| **FR-30** | MUST         | The severity verdict and composite score must be recorded as span attributes on the Severity Node span      |
| **FR-31** | MUST         | Export all traces to Arize in real-time using the arize-otel exporter                                       |
| **FR-32** | SHOULD       | Print a direct URL to the trace in the Arize UI to terminal/notebook output after each run                  |
| **FR-33** | COULD        | Support span-level LLM-as-judge evaluations for triage verdict quality (as demonstrated in Arize eval labs) |

**4.7 Jupyter Notebook Interface**

|           |              |                                                                                                                                                   |
|-----------|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| **ID**    | **Priority** | **Requirement**                                                                                                                                   |
| **FR-34** | MUST         | Ship a self-contained Jupyter Notebook (flowrun_agent.ipynb) that mirrors all CLI agent functionality                                             |
| **FR-35** | MUST         | Notebook must follow the 8-cell structure defined in the User Manual (Install, Keys, Tracing, Tools, Graph, Run, Results, Arize Link)             |
| **FR-36** | MUST         | Cell 6 must render an ipywidgets text input and Analyze button — not rely on raw input()                                                          |
| **FR-37** | MUST         | Cell outputs must not display API keys at any point — enforced by using only getpass() or load_dotenv() in Cell 2, never direct string assignment |
| **FR-38** | SHOULD       | Each cell must include a markdown explanation of what it does and why, suitable for a live demo or classroom use                                  |
| **FR-39** | SHOULD       | Cell 7 should render the threat report in a styled HTML display block, not plain text                                                             |




## 5. Non-Functional Requirements

|            |                 |                                                                                                                              |
|------------|-----------------|------------------------------------------------------------------------------------------------------------------------------|
| **ID**     | **Category**    | **Requirement**                                                                                                              |
| **NFR-01** | Performance     | End-to-end triage (input to report) must complete in under 30 seconds under normal API response conditions                   |
| **NFR-02** | Performance     | Parallel enrichment fan-out must not serialize API calls — all applicable sources queried concurrently                       |
| **NFR-03** | Reliability     | Any single API source failure must not cause the agent to crash — failed sources logged as 'unavailable' in the report       |
| **NFR-04** | Security        | No API keys stored in code, logs, notebook output, or any persistent file except a user-controlled .env                      |
| **NFR-05** | Security        | All outbound API calls must use HTTPS                                                                                        |
| **NFR-06** | Observability   | 100% of agent runs must produce a trace in Arize with all required spans — no silent failures                                |
| **NFR-07** | Observability   | Arize trace failure (network issue, invalid key) must not block the agent from completing a triage and outputting a report   |
| **NFR-08** | Portability     | Agent must run on macOS 12+, Ubuntu 20.04+, and Windows 10+ (via WSL2) with no OS-specific dependencies                      |
| **NFR-09** | Maintainability | Each API integration must be implemented as an independent LangChain Tool, replaceable without modifying the graph structure |
| **NFR-10** | Usability       | A user with no prior LangGraph experience must be able to run a triage in under 5 minutes using the Jupyter Notebook         |




## 6. Architecture & Technical Design

**6.1 System Layers**

|                         |                                                                                                                                                                                                                     |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Layer**               | **Description**                                                                                                                                                                                                     |
| **Interaction Layer**   | CLI (interactive terminal) + Jupyter Notebook (ipywidgets). Accepts raw IOC input, displays reports.                                                                                                                |
| **Agent Orchestration** | LangGraph StateGraph with typed AgentState. Manages all node execution, conditional routing, and parallel fan-out.                                                                                                  |
| **LLM Integration**     | LangChain + OpenAI GPT-5.2. GPT-5.2 Instant (gpt-5.2-chat-latest, effort=low) for IOC classification. GPT-5.2 Thinking (gpt-5.2, effort=medium) for report synthesis. Both configured in agent/llm.py MODEL_CONFIG. |
| **Tool / API Layer**    | LangChain Tool-wrapped HTTP clients for VirusTotal, AbuseIPDB, OTX, urlscan.io, and NIST NVD.                                                                                                                       |
| **Observability Layer** | OpenInference auto-instrumentation. arize-otel OTLP exporter streaming spans to Arize AI platform.                                                                                                                  |

**6.2 LangGraph Node Definitions**

|                      |                                                                                                                                                                                                  |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Node Name**        | **Responsibility**                                                                                                                                                                               |
| **input_node**       | Receives raw IOC string, initializes AgentState with ioc_raw field, passes to classifier                                                                                                         |
| **classifier_node**  | GPT-5.2 Instant (gpt-5.2-chat-latest, reasoning_effort=low): detects IOC type (ip/domain/url/hash/cve), validates format, writes ioc_type to state. Routes to enrichment or error.               |
| **enrichment_node**  | asyncio parallel execution: fires all applicable LangChain tool coroutines concurrently via asyncio.gather(). Collects results into raw_intel dict in state. NVD tool invoked for CVE type only. |
| **correlation_node** | Pure Python: reads raw_intel, applies weighted scoring formula, computes composite_score float, writes to state.                                                                                 |
| **severity_node**    | Maps composite_score to severity_band string (CLEAN/LOW/MEDIUM/HIGH/CRITICAL), writes verdict_justification to state.                                                                            |
| **report_node**      | Formats final structured threat report from full state. Renders to CLI or Jupyter output. Prepares Arize span attributes.                                                                        |
| **escalation_gate**  | Conditional edge: if severity_band == CRITICAL, invokes human-in-the-loop prompt before final output. Otherwise routes to report.                                                                |

**6.3 AgentState Schema**


> **TypedDict — AgentState**
> ioc_raw: str # Original user input
> ioc_type: str # Detected type: ip | domain | url | hash | cve
> ioc_clean: str # Normalized IOC value
> raw_intel: dict[str, Any] # Keyed by source name, raw API response
> composite_score: float # 0.0 (clean) to 1.0 (critical)
> severity_band: str # CLEAN | LOW | MEDIUM | HIGH | CRITICAL
> verdict_justification: str # Plain-English explanation of verdict
> report: str # Final formatted threat report
> errors: list[str] # Non-fatal errors from failed API calls


**6.4 Severity Scoring Formula**

The composite threat score is computed as a weighted average across available sources. Weights must sum to 1.00 and are re-normalised automatically when a source is unavailable. Two weight sets are defined based on IOC type.

Standard Weight Set (all IOC types except CVE):

|                                |            |                                                                                                 |
|--------------------------------|------------|-------------------------------------------------------------------------------------------------|
| **Signal**                     | **Weight** | **Normalization**                                                                               |
| **VirusTotal malicious ratio** | 0.40       | malicious_count / total_engines                                                                 |
| **AbuseIPDB confidence score** | 0.30       | Direct 0–100 → 0.0–1.0 normalization (IP only; weight redistributed for other types)            |
| **OTX pulse match**            | 0.20       | 0.0 if no pulses, 0.5 if 1–2 pulses, 1.0 if 3+ pulses                                           |
| **urlscan.io verdict**         | 0.10       | 0.0 = clean, 0.5 = suspicious, 1.0 = malicious (URL only; weight redistributed for other types) |

CVE Weight Set (used only when ioc_type == 'cve'):

|                                |            |                                                       |
|--------------------------------|------------|-------------------------------------------------------|
| **Signal**                     | **Weight** | **Normalization**                                     |
| **VirusTotal malicious ratio** | 0.50       | malicious_count / total_engines                       |
| **OTX pulse match**            | 0.30       | 0.0 if no pulses, 0.5 if 1–2 pulses, 1.0 if 3+ pulses |
| **NIST NVD CVSS score**        | 0.20       | CVSS base score / 10.0 (e.g., CVSS 9.8 → 0.98)        |

|                 |             |                                                              |
|-----------------|-------------|--------------------------------------------------------------|
| **Score Range** | **Verdict** | **Recommended Action**                                       |
| **0.00 – 0.10** | 🟢 CLEAN    | No credible threat signals                                   |
| **0.11 – 0.30** | 🟡 LOW      | Minor or stale signals — monitor                             |
| **0.31 – 0.55** | 🟠 MEDIUM   | Credible signals — investigate and consider blocking         |
| **0.56 – 0.75** | 🔴 HIGH     | Strong signals — block and escalate                          |
| **0.76 – 1.00** | 🚨 CRITICAL | Confirmed malicious — block immediately, trigger IR playbook |

**6.5 Technology Stack**

|                                             |             |                                                                                  |
|---------------------------------------------|-------------|----------------------------------------------------------------------------------|
| **Package**                                 | **Version** | **Purpose**                                                                      |
| **LangGraph**                               | 0.2+        | StateGraph orchestration, parallel fan-out, conditional edges, human-in-the-loop |
| **LangChain**                               | 0.3+        | Tool definitions, LLM wrappers, output parsers, async tool execution             |
| **OpenAI Python SDK**                       | 1.0+        | GPT-5.2 Instant for classification; GPT-5.2 Thinking for report synthesis        |
| **arize-otel**                              | Latest      | OpenInference OTLP exporter to Arize AI platform                                 |
| **openinference-instrumentation-langchain** | Latest      | Auto-instrumentation for all LangChain/LangGraph operations                      |
| **requests**                                | 2.31+       | HTTP client for threat intel API calls                                           |
| **python-dotenv**                           | 1.0+        | Loads .env file into os.environ at startup                                       |
| **ipywidgets**                              | 8.0+        | Jupyter Notebook IOC input widget and styled output rendering                    |
| **Python**                                  | 3.11+       | Runtime. asyncio required for parallel enrichment.                               |




## 7. External API Integrations

|                    |                                 |                    |                 |                           |
|--------------------|---------------------------------|--------------------|-----------------|---------------------------|
| **Service**        | **Base URL**                    | **Env Variable**   | **IOC Types**   | **Free Tier Limits**      |
| **VirusTotal**     | api.virustotal.com/api/v3       | VIRUSTOTAL_API_KEY | All             | 4 req/min, 500/day (free) |
| **AbuseIPDB**      | api.abuseipdb.com/api/v2/check  | ABUSEIPDB_API_KEY  | IP only         | 1,000 req/day (free)      |
| **AlienVault OTX** | otx.alienvault.com/api/v1       | OTX_API_KEY        | All             | Generous (free)           |
| **urlscan.io**     | urlscan.io/api/v1/scan          | URLSCAN_API_KEY    | URL only        | 100 scans/day (free)      |
| **NIST NVD**       | services.nvd.nist.gov/rest/json | None required      | CVE format only | 5 req/30s unauthenticated |


> **Rate Limit Strategy**
> Each LangChain Tool wrapper must implement exponential backoff with 3 retry attempts on 429 (rate limited) or 5xx responses.
> The enrichment node must record a non-fatal error in AgentState.errors if a source remains unavailable after retries.
> The correlation node must re-normalize weights if one or more sources are unavailable, distributing their weight proportionally.




## 8. Observability Design (Arize AI)

**8.1 Trace Structure**

Each agent run produces a single root trace with a hierarchical span tree that mirrors the LangGraph execution graph. The structure below defines the required span hierarchy:


```
**Required Span Hierarchy per Triage Run**
ROOT SPAN: flowrun.triage (full run latency, IOC input, severity output)
├─ SPAN: flowrun.classify (LLM call for IOC type detection)
├─ SPAN: flowrun.enrich (parallel fan-out container)
│ ├─ SPAN: tool.virustotal (API call, raw response)
│ ├─ SPAN: tool.abuseipdb (API call, raw response — IP only)
│ ├─ SPAN: tool.otx (API call, raw response)
│ └─ SPAN: tool.urlscan (API call, raw response — URL only)
├─ SPAN: flowrun.correlate (scoring logic, composite_score)
├─ SPAN: flowrun.severity (verdict assignment, justification)
└─ SPAN: flowrun.report (report formatting, Arize link generation)
```


**8.2 Required Span Attributes**

|                       |                                                                                       |
|-----------------------|---------------------------------------------------------------------------------------|
| **Span Name**         | **Required Attributes**                                                               |
| **flowrun.triage**    | ioc.type, ioc.value, severity.band, composite.score, run.duration_ms                  |
| **flowrun.classify**  | llm.model, llm.prompt_tokens, llm.completion_tokens, ioc.detected_type                |
| **tool.\***           | tool.name, tool.input, tool.output_raw, tool.latency_ms, tool.status (success\|error) |
| **flowrun.correlate** | score.virustotal, score.abuseipdb, score.otx, score.urlscan, composite.score          |
| **flowrun.severity**  | severity.band, verdict.justification                                                  |

**8.3 Evaluation Hooks (Future)**

Following the Arize evaluation framework demonstrated in the Arize Agent Mastery Course (lab6_evals), the following evaluation tasks are planned for v1.1:

- Span-level: Retrieval relevance scoring on OTX pulse matches using LLM-as-judge

- Trace-level: Verdict accuracy evaluation against known-good IOC ground truth dataset

- Trace-level: Analyst acceptance rate tracking (did the analyst agree with the verdict?)




## 9. Credential Management Specification

|                        |               |                                     |
|------------------------|---------------|-------------------------------------|
| **Variable Name**      | **Required?** | **Where to Obtain**                 |
| **OPENAI_API_KEY**     | Required      | platform.openai.com → API Keys      |
| **VIRUSTOTAL_API_KEY** | Required      | virustotal.com → Profile → API Key  |
| **ABUSEIPDB_API_KEY**  | Required      | abuseipdb.com → Account → API       |
| **OTX_API_KEY**        | Required      | otx.alienvault.com → Settings       |
| **URLSCAN_API_KEY**    | Required      | urlscan.io → Settings → API Keys    |
| **ARIZE_API_KEY**      | Required      | app.arize.com → Settings → API Keys |
| **ARIZE_SPACE_ID**     | Required      | app.arize.com → Settings → API Keys |

The agent's startup sequence must follow this credential resolution order:

1.  Check for .env file in the working directory and load with python-dotenv if found

2.  Check os.environ for each required variable (supports Docker/CI injection)

3.  If any required variable is still missing: invoke interactive getpass() prompt for that variable

4.  If all keys are present from any combination of sources: proceed with agent initialization

5.  Keys must never be logged, printed to stdout, or included in any Arize span attribute




## 10. Acceptance Criteria

|           |                                |                                                                                                                                                                               |
|-----------|--------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **ID**    | **Test Case**                  | **Pass Criterion**                                                                                                                                                            |
| **AC-01** | IOC Triage — Happy Path        | Given a known-malicious IP (e.g., one listed on AbuseIPDB with \>90% confidence), the agent must return a severity verdict of HIGH or CRITICAL with a composite score \> 0.56 |
| **AC-02** | IOC Triage — Clean IP          | Given a known-clean IP (e.g., 8.8.8.8), the agent must return CLEAN or LOW with a composite score \< 0.30                                                                     |
| **AC-03** | IOC Type Detection — All Types | The classifier node must correctly identify the IOC type for: an IPv4 address, a domain, an https:// URL, a 32-char MD5 hash, and a 64-char SHA-256 hash                      |
| **AC-04** | Parallel Execution             | The total enrichment time for a 4-source query must not exceed 1.5× the slowest single API response time (not 4× sequential time)                                             |
| **AC-05** | API Failure Tolerance          | If VirusTotal returns a 500 error, the agent must complete triage using remaining sources and include 'VirusTotal: unavailable' in the report                                 |
| **AC-06** | Arize Trace                    | After every successful run, a trace must appear in the configured Arize Space within 10 seconds, containing all required spans and attributes                                 |
| **AC-07** | Key Security                   | Running 'grep -r sk- .' and 'grep -r api_key .' on the codebase must return zero hardcoded key values                                                                         |
| **AC-08** | Jupyter — Key Masking          | After running Cell 2 with getpass(), the saved .ipynb file must not contain any API key values in cell outputs                                                                |
| **AC-09** | CRITICAL Escalation Gate       | When a CRITICAL verdict is produced, the agent must pause and display a human confirmation prompt before outputting the final report                                          |
| **AC-10** | End-to-End Latency             | Under normal API conditions, the full triage cycle from IOC input to report display must complete in under 30 seconds                                                         |




## 11. Risks & Mitigations

|          |              |                                                     |                                                                                                                            |
|----------|--------------|-----------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| **ID**   | **Severity** | **Risk**                                            | **Mitigation**                                                                                                             |
| **R-01** | HIGH         | Free API rate limits exhausted during demo          | Use known-safe IOC test values (8.8.8.8 for clean, known OSINT IOCs for malicious). Cache results for demo run.            |
| **R-02** | MEDIUM       | VirusTotal API key flagged for excessive use        | Implement request throttling with 15-second sleep between calls if running multiple tests in sequence.                     |
| **R-03** | MEDIUM       | Arize trace export fails silently                   | Wrap Arize export in try/except; log failure to stderr but do not block triage completion (NFR-07).                        |
| **R-04** | MEDIUM       | GPT-5.2 Instant misclassifies an IOC type           | Add regex-based pre-classification as a fallback before the LLM call; LLM only invoked if regex is inconclusive.           |
| **R-05** | LOW          | urlscan.io public scans expose IOC to third parties | Document clearly: urlscan.io public scans are visible. For sensitive IOCs, disable urlscan or use private scan API (paid). |
| **R-06** | LOW          | Python version incompatibility                      | Pin all dependencies in requirements.txt with tested versions. Target Python 3.11 specifically.                            |




## 12. Delivery Milestones

|          |                      |                                                                                                                                                     |
|----------|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| **ID**   | **Milestone**        | **Deliverables**                                                                                                                                    |
| **M-01** | Project Scaffolding  | requirements.txt, .env.template, folder structure, LangGraph skeleton with stub nodes, Arize tracer initialized                                     |
| **M-02** | API Tool Layer       | All 5 LangChain Tool wrappers implemented and unit-tested with mock responses. Parallel fan-out confirmed.                                          |
| **M-03** | Core Agent — CLI     | Full StateGraph operational. IOC classification, enrichment, correlation, severity, and report nodes all functional. CLI interactive loop complete. |
| **M-04** | Arize Integration    | All spans emitting to Arize with correct attributes. Trace structure validated in Arize UI. CRITICAL escalation gate tested.                        |
| **M-05** | Jupyter Notebook     | flowrun_agent.ipynb complete with all 8 cells, ipywidgets IOC input, styled HTML report output, getpass key handling, Arize link in Cell 8.         |
| **M-06** | Testing & Acceptance | All 10 acceptance criteria verified. README.md complete. Demo script rehearsed against live APIs.                                                   |




## 13. Future Roadmap (Post v1.0)

|            |                      |                                                                                                                                                                   |
|------------|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Target** | **Feature**          | **Description**                                                                                                                                                   |
| **v2.0**   | REST API             | FastAPI wrapper around the LangGraph agent enabling programmatic IOC submission and JSON report retrieval                                                         |
| **v2.0**   | SIEM Integration     | Splunk and Microsoft Sentinel connectors to auto-enrich and close alerts directly from the triage verdict                                                         |
| **v2.0**   | Bulk IOC Ingestion   | CSV file upload support for batch triage of multiple IOCs in a single run                                                                                         |
| **v2.0**   | Slack Bot Interface  | Slack app that accepts IOC submissions via slash command and returns the threat report to the channel                                                             |
| **v2.1**   | Arize Evaluations    | Span and trace-level LLM-as-judge evaluations for verdict quality and OTX retrieval relevance (per lab6_evals pattern)                                            |
| **v2.1**   | RAG-Enhanced Context | ChromaDB vector store of historical threat reports and IOC context for enriched report synthesis (per lab5_RAG pattern)                                           |
| **v3.0**   | Multi-Agent SOC      | Supervisor + sub-agent architecture with dedicated Threat Intel, Vulnerability Intel, and Breach Check agents (per lab3_agent_architectures orchestrator pattern) |

FlowRun Streamlet: IoC Triage • PRD v1.0 • LangGraph + LangChain + Arize AI • INTERNAL CONFIDENTIAL
