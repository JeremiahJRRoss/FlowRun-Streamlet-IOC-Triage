> **ARCHITECTURAL DESIGN DOCUMENT**
> **FlowRun Streamlet: IoC Triage**
> System Architecture, Component Design & Integration Reference
> LangGraph · LangChain · OpenAI GPT-5.2 · Arize AI · OpenInference


|                       |                                                              |
|-----------------------|--------------------------------------------------------------|
| **Attribute**         | **Value**                                                    |
| **Document Type**     | Architectural Design Document (ADD)                          |
| **Product**           | FlowRun Streamlet: IoC Triage                                |
| **Version**           | 1.0.0                                                        |
| **Classification**    | Internal — Engineering Reference                             |
| **Agentic Framework** | LangGraph 0.2+ (StateGraph)                                  |
| **LLM Integration**   | LangChain 0.3+ / OpenAI GPT-5.2 (Instant + Thinking)         |
| **Observability**     | Arize AI via OpenInference OTLP                              |
| **Target Audience**   | Security Engineers, Platform Engineers, Technical Architects |




## 1. Document Purpose & Scope

This Architectural Design Document (ADD) describes the internal structure, component design, data flows, integration patterns, and technical decisions that underpin the FlowRun Streamlet: IoC Triage. It is written for engineers who will build, extend, debug, or review the system and assumes familiarity with Python async programming, directed acyclic graphs, REST APIs, and LLM-based agents.

The document covers: the layered system architecture; the LangGraph StateGraph design in full detail; each node's internal logic; the LangChain tool integration pattern; the Arize AI / OpenInference observability pipeline; the credential management subsystem; the Jupyter Notebook interface architecture; error handling and resilience design; and the extension model for adding new threat intelligence sources.


> **Architectural Philosophy**
> Transparency first — every decision the agent makes must be traceable to a specific data signal from a named source.
> Fail gracefully — no single external API failure should abort the triage. Partial intelligence is better than no intelligence.
> Separation of concerns — tool definitions, graph orchestration, scoring logic, and report rendering are fully decoupled modules.
> Observable by design — Arize tracing is not an afterthought; spans are instrumented at the graph level, not bolted on post-hoc.
> Zero trust credentials — no key ever touches source code, stdout, logs, or notebook cell output.




## 2. System Context

**2.1 Context Diagram (C4 Level 1)**

The following diagram illustrates how the FlowRun Streamlet: IoC Triage sits within its broader operational environment. The agent mediates between a human SOC analyst and five external threat intelligence services, while streaming observability data to the Arize AI platform.


```
┌─────────────────────────────────────────────────────────────────────────┐
│ OPERATIONAL ENVIRONMENT │
│ │
│ ┌───────────────┐ ┌───────────────────────────────────────┐ │
│ │ SOC Analyst │──IOC──▶│ FLOWRUN STREAMLET: IoC TRIAGE │ │
│ │ (Human User) │◀─Rpt──│ (LangGraph + LangChain + GPT-5.2) │ │
│ └───────────────┘ └────────────┬──────────────────────────┘ │
│ │ │
│ ┌───────────────────────────┼──────────────────────┐ │
│ │ Threat Intelligence APIs │ │ │
│ ▼ ▼ ▼ ▼ ▼ │ │
│ VirusTotal AbuseIPDB OTX urlscan.io NIST NVD │ │
│ │ │
│ ┌────────────────────────────────────────────────────────┐ │ │
│ │ ARIZE AI PLATFORM │◀───┘ │
│ │ (Trace Collection + Evaluation UI) │ │
│ └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```


**2.2 External Dependencies**

|                       |                                                                          |                       |              |                          |
|-----------------------|--------------------------------------------------------------------------|-----------------------|--------------|--------------------------|
| **Dependency**        | **Purpose**                                                              | **Host**              | **Protocol** | **Auth**                 |
| **OpenAI API**        | LLM inference — GPT-5.2 Instant (classifier) + GPT-5.2 Thinking (report) | api.openai.com        | HTTPS/443    | OPENAI_API_KEY           |
| **VirusTotal API v3** | Multi-engine IOC reputation                                              | api.virustotal.com    | HTTPS/443    | VIRUSTOTAL_API_KEY       |
| **AbuseIPDB API v2**  | IP abuse scoring & history                                               | api.abuseipdb.com     | HTTPS/443    | ABUSEIPDB_API_KEY        |
| **AlienVault OTX v1** | Threat intelligence pulses                                               | otx.alienvault.com    | HTTPS/443    | OTX_API_KEY              |
| **urlscan.io API v1** | Live URL sandbox analysis                                                | urlscan.io            | HTTPS/443    | URLSCAN_API_KEY          |
| **NIST NVD API**      | CVE vulnerability data                                                   | services.nvd.nist.gov | HTTPS/443    | None required            |
| **Arize AI (OTLP)**   | Trace export & observability                                             | otlp.arize.com:4317   | gRPC/4317    | ARIZE_API_KEY + SPACE_ID |




## 3. Layered Architecture

The system is organised into five discrete horizontal layers. Each layer communicates only with the layer immediately below it, ensuring loose coupling and independent testability.


```
┌──────────────────────────────────────────────────────────────┐
│ LAYER 5 — INTERACTION LAYER │
│ CLI interactive loop | Jupyter Notebook (ipywidgets) │
├──────────────────────────────────────────────────────────────┤
│ LAYER 4 — AGENT ORCHESTRATION LAYER │
│ LangGraph StateGraph | Node definitions | Edge routing │
├──────────────────────────────────────────────────────────────┤
│ LAYER 3 — LLM & TOOL LAYER │
│ LangChain ChatOpenAI | Tool wrappers | Output parsers │
├──────────────────────────────────────────────────────────────┤
│ LAYER 2 — INTELLIGENCE INTEGRATION LAYER │
│ VirusTotal AbuseIPDB OTX urlscan.io NIST NVD │
├──────────────────────────────────────────────────────────────┤
│ LAYER 1 — OBSERVABILITY LAYER │
│ OpenInference instrumentation | Arize OTLP exporter │
└──────────────────────────────────────────────────────────────┘
```


|                       |                                                                                                                    |                                |                  |
|-----------------------|--------------------------------------------------------------------------------------------------------------------|--------------------------------|------------------|
| **Layer**             | **Responsibility**                                                                                                 | **Key Modules**                | **Scope**        |
| **5 — Interaction**   | Accepts raw IOC string from analyst. Renders final threat report. Contains no business logic.                      | CLI module + Jupyter cells 6–7 | User-facing only |
| **4 — Orchestration** | LangGraph StateGraph managing node execution order, parallel fan-out, conditional routing, and shared state.       | agent/graph.py                 | Core agent logic |
| **3 — LLM & Tools**   | LangChain tool definitions wrapping HTTP clients. ChatOpenAI for LLM calls. OutputParser for structured responses. | agent/tools/\*.py agent/llm.py | AI & API calls   |
| **2 — Intelligence**  | Raw HTTP calls to each threat intelligence API. Response parsing and normalization to canonical schemas.           | agent/integrations/\*.py       | External IO      |
| **1 — Observability** | OpenInference auto-instrumentation capturing spans from all layers. OTLP exporter streaming to Arize.              | agent/tracing.py               | Cross-cutting    |




## 4. Project File Structure

```
flowrun-streamlet-ioc-triage/
│
├── flowrun_agent.py # CLI entry point — interactive loop
├── flowrun_agent.ipynb # Jupyter Notebook interface (8 cells)
├── requirements.txt # Pinned Python dependencies
├── .env.template # Template showing all required env vars (no values)
├── .gitignore # Excludes .env, __pycache__, .ipynb_checkpoints
│
├── agent/
│ ├── __init__.py
│ ├── graph.py # LangGraph StateGraph definition — all nodes & edges
│ ├── state.py # AgentState TypedDict schema
│ ├── llm.py # ChatOpenAI initialisation + classifier prompt
│ ├── tracing.py # Arize / OpenInference tracer setup
│ ├── credentials.py # Key resolution: .env → os.environ → getpass()
│ ├── scoring.py # Composite threat score formula & severity mapping
│ ├── report.py # Report formatter — CLI text + HTML (Jupyter)
│ │
│ ├── tools/
│ │ ├── __init__.py
│ │ ├── virustotal.py # LangChain Tool: VirusTotal API v3
│ │ ├── abuseipdb.py # LangChain Tool: AbuseIPDB API v2
│ │ ├── otx.py # LangChain Tool: AlienVault OTX API v1
│ │ ├── urlscan.py # LangChain Tool: urlscan.io API v1
│ │ └── nvd.py # LangChain Tool: NIST NVD API
│ │
│ └── integrations/
│ ├── __init__.py
│ ├── virustotal.py # Raw HTTP client + response schema
│ ├── abuseipdb.py
│ ├── otx.py
│ ├── urlscan.py
│ └── nvd.py
│
└── tests/
├── test_classifier.py
├── test_scoring.py
├── test_tools.py # Uses mock HTTP responses
└── test_graph.py # Integration test with stubbed tools
```




## 5. Agent State Design

LangGraph's StateGraph requires a single TypedDict that serves as the shared memory for all nodes. Every node receives the full state as input and returns a partial state dict containing only the fields it modified. LangGraph merges these partial updates using its Annotated reducer pattern.

**5.1 AgentState Schema**


```
# agent/state.py
from typing import TypedDict, Annotated, Any
from langgraph.graph.message import add_messages
class AgentState(TypedDict):
# ── INPUT ──────────────────────────────────────────────────
ioc_raw: str # Exact string from user input
ioc_clean: str # Normalised (stripped, lowercased domain/url)
ioc_type: str # 'ip' | 'domain' | 'url' | 'hash_md5' |
# 'hash_sha1' | 'hash_sha256' | 'cve' | 'unknown'
# ── ENRICHMENT ─────────────────────────────────────────────
raw_intel: dict[str, Any] # {source_name: parsed_response_dict}
intel_errors: list[str] # Non-fatal: ["abuseipdb: timeout", ...]
# ── SCORING ────────────────────────────────────────────────
score_breakdown: dict[str, float] # Per-source normalised 0.0–1.0 scores
composite_score: float # Weighted aggregate
active_weights: dict[str, float] # Re-normalised if sources unavailable
# ── VERDICT ────────────────────────────────────────────────
severity_band: str # 'CLEAN'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'
verdict_justification: str # Plain-English explanation of verdict
escalation_required: bool # True only when severity_band == 'CRITICAL'
# ── OUTPUT ─────────────────────────────────────────────────
report_text: str # CLI-formatted threat report
report_html: str # HTML-formatted report for Jupyter
arize_trace_url: str # Direct URL to trace in Arize UI
```


**5.2 State Lifecycle**

The table below tracks which fields are written by each node, giving a clear picture of how state grows as execution proceeds through the graph.

|                      |                                                           |                                  |
|----------------------|-----------------------------------------------------------|----------------------------------|
| **Node**             | **Fields Written**                                        | **Reads From**                   |
| **input_node**       | ioc_raw, ioc_clean, ioc_type                              | —                                |
| **classifier_node**  | ioc_type (overrides), ioc_clean (normalised)              | ioc_raw                          |
| **enrichment_node**  | raw_intel, intel_errors                                   | ioc_clean, ioc_type              |
| **correlation_node** | score_breakdown, composite_score, active_weights          | raw_intel, intel_errors          |
| **severity_node**    | severity_band, verdict_justification, escalation_required | composite_score, score_breakdown |
| **report_node**      | report_text, report_html, arize_trace_url                 | Full state                       |




## 6. LangGraph Graph Design

**6.1 Full Graph Topology**


```
┌─────────────┐
IOC string ──▶│ input_node │
└──────┬──────┘
│
┌──────▼──────────┐
│ classifier_node │◀── GPT-5.2 Instant (effort=low)
└──────┬──────────┘
│
┌─────────▼──────────┐
│ [Conditional Edge] │
│ type == 'unknown'? │
└──┬──────────────────┘
YES ─────┘ │ NO
▼ ▼
error_node ┌───────────────┐
│ enrichment_node│ ◀── Parallel fan-out
│ ┌──────────┐ │
│ │virustotal│ │──▶ VirusTotal API
│ ├──────────┤ │
│ │abuseipdb │ │──▶ AbuseIPDB API (IP only)
│ ├──────────┤ │
│ │ otx │ │──▶ AlienVault OTX API
│ ├──────────┤ │
│ │ urlscan │ │──▶ urlscan.io API (URL only)
│ ├──────────┤ │
│ │ nvd │ │──▶ NIST NVD API (CVE only)
│ └──────────┘ │
└───────┬───────┘
│
┌─────────▼──────────┐
│ correlation_node │◀── Python scoring logic
└─────────┬──────────┘
│
┌─────────▼──────────┐
│ severity_node │
└─────────┬──────────┘
│
┌─────────────▼──────────────┐
│ [Conditional Edge] │
│ severity_band == CRITICAL? │
└──┬──────────────────────────┘
YES ─────┘ │ NO
▼ ▼
escalation_gate ┌─────────────┐
(human-in-loop) │ report_node │
│ └─────┬───────┘
└─────────┬────────────┘
▼
┌──────────┐
│ END │
└──────────┘
```


**6.2 Graph Construction Code Pattern**


```
# agent/graph.py (abbreviated structural pattern)
from langgraph.graph import StateGraph, END
from agent.state import AgentState
from agent.nodes import (
input_node, classifier_node, enrichment_node,
correlation_node, severity_node, report_node,
escalation_gate, error_node
)
def build_graph() -> CompiledGraph:
graph = StateGraph(AgentState)
# ── Register nodes ─────────────────────────────────────
graph.add_node('input', input_node)
graph.add_node('classify', classifier_node)
graph.add_node('enrich', enrichment_node)
graph.add_node('correlate', correlation_node)
graph.add_node('severity', severity_node)
graph.add_node('report', report_node)
graph.add_node('escalation', escalation_gate)
graph.add_node('error', error_node)
# ── Linear edges ───────────────────────────────────────
graph.add_edge('input', 'classify')
graph.add_edge('enrich', 'correlate')
graph.add_edge('correlate', 'severity')
graph.add_edge('escalation','report')
graph.add_edge('report', END)
graph.add_edge('error', END)
# ── Conditional: unknown IOC type ───────────────────────
graph.add_conditional_edges('classify', route_after_classify, {
'enrich': 'enrich',
'error': 'error'
})
# ── Conditional: CRITICAL escalation gate ──────────────
graph.add_conditional_edges('severity', route_after_severity, {
'escalation': 'escalation',
'report': 'report'
})
graph.set_entry_point('input')
return graph.compile()
```


**6.3 Conditional Edge Functions**


> def route_after_classify(state: AgentState) -> str:
> """Route to error node if IOC type could not be determined."""
> return 'error' if state['ioc_type'] == 'unknown' else 'enrich'
> def route_after_severity(state: AgentState) -> str:
> """Route to human escalation gate for CRITICAL verdicts only."""
> return 'escalation' if state['severity_band'] == 'CRITICAL' else 'report'




## 7. Node Design — Internal Logic

**7.1 input_node**

Responsibility: Receive the raw IOC string and perform lightweight pre-processing before the LLM classifier is invoked. This node is intentionally minimal — no external calls, no LLM usage.

|                          |                                                                                                                                 |
|--------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| **Operation**            | **Rationale**                                                                                                                   |
| **Strip whitespace**     | Remove leading/trailing spaces that commonly appear in copy-pasted IOCs                                                         |
| **Lowercase normalise**  | Lowercase domains and URLs (IPs and hashes are case-insensitive already)                                                        |
| **Scheme normalisation** | Ensure URLs begin with http:// or https:// if missing                                                                           |
| **Regex pre-check**      | Attempt fast regex classification for IPv4, MD5, SHA-1, SHA-256 before LLM call — set ioc_type to 'pending_llm' if inconclusive |
| **State initialisation** | Write ioc_raw, ioc_clean, and preliminary ioc_type to state                                                                     |

**7.2 classifier_node**

Responsibility: Determine the IOC type with high confidence. Uses a structured GPT-5.2 Instant call (model: gpt-5.2-chat-latest, reasoning_effort: low) with a constrained JSON output schema. Fast and cost-efficient for this deterministic task. The LLM is only invoked if the regex pre-check in input_node was inconclusive.


```
# agent/llm.py — per-task model configuration
# ─────────────────────────────────────────────────────────────────────
# To change the model or reasoning effort for any task, edit ONE entry
# in MODEL_CONFIG below. No other file needs to change.
# ─────────────────────────────────────────────────────────────────────
MODEL_CONFIG: dict[str, dict] = {
# IOC type classification — fast, deterministic, tiny JSON output.
# GPT-5.2 Instant is ideal: low latency, sufficient for structured output.
"classifier": {
"model": "gpt-5.2-chat-latest", # GPT-5.2 Instant
"reasoning_effort": "low",
"temperature": 0.0, # deterministic — same IOC always same type
},
# Threat report synthesis — multi-source, nuanced natural language output.
# GPT-5.2 Thinking at medium effort: quality without xhigh latency.
"report": {
"model": "gpt-5.2", # GPT-5.2 Thinking
"reasoning_effort": "medium",
"temperature": 0.3,
},
}
def get_llm(task: str) -> ChatOpenAI:
"""Return a ChatOpenAI instance configured for the named task."""
cfg = MODEL_CONFIG[task]
return ChatOpenAI(
model=cfg["model"],
temperature=cfg.get("temperature", 0.0),
model_kwargs={"reasoning_effort": cfg["reasoning_effort"]}
if "reasoning_effort" in cfg else {},
)
# ── Classifier prompt ─────────────────────────────────────────────────
CLASSIFIER_SYSTEM = """
You are a security analyst IOC classifier.
Classify the given string into exactly one of these types:
ip → IPv4 or IPv6 address
domain → Hostname or FQDN (no scheme, no path)
url → Full URL with scheme (http/https/ftp)
hash_md5 → 32 hex characters
hash_sha1 → 40 hex characters
hash_sha256 → 64 hex characters
cve → CVE identifier (CVE-YYYY-NNNNN format)
unknown → Cannot be classified
Respond ONLY with a JSON object:
{ "type": "<type>", "clean": "<normalised_value>", "confidence": 0.0-1.0 }
"""
# Usage in classifier_node:
# llm = get_llm('classifier') → gpt-5.2-chat-latest, effort=low
# Usage in report_node:
# llm = get_llm('report') → gpt-5.2, effort=medium
# Output is parsed with LangChain's JsonOutputParser
# If confidence < 0.6, ioc_type is set to 'unknown' → routes to error_node
```


**7.3 enrichment_node (Parallel Fan-Out)**

Responsibility: Execute all applicable threat intelligence API calls concurrently and collect results into the raw_intel dict. This is the most architecturally significant node because it uses LangGraph's native async fan-out pattern.

The node builds a dynamic list of coroutines based on the detected IOC type, then executes all of them with asyncio.gather(return_exceptions=True). Failed coroutines are caught and appended to intel_errors rather than allowed to propagate.


> # agent/nodes.py — enrichment_node (structural pattern)
> async def enrichment_node(state: AgentState) -> dict:
> ioc_type = state['ioc_type']
> ioc_clean = state['ioc_clean']
> # Build task list based on IOC type
> tasks = { 'virustotal': vt_tool.ainvoke(ioc_clean),
> 'otx': otx_tool.ainvoke(ioc_clean) }
> if ioc_type == 'ip':
> tasks['abuseipdb'] = abuseipdb_tool.ainvoke(ioc_clean)
> if ioc_type == 'url':
> tasks['urlscan'] = urlscan_tool.ainvoke(ioc_clean)
> if ioc_type == 'cve':
> tasks['nvd'] = nvd_tool.ainvoke(ioc_clean)
> # Execute all tasks concurrently
> results = await asyncio.gather(*tasks.values(), return_exceptions=True)
> raw_intel, intel_errors = {}, []
> for source, result in zip(tasks.keys(), results):
> if isinstance(result, Exception):
> intel_errors.append(f'{source}: {type(result).__name__}: {result}')
> else:
> raw_intel[source] = result
> return { 'raw_intel': raw_intel, 'intel_errors': intel_errors }


**7.4 correlation_node**

Responsibility: Transform raw, heterogeneous API responses into a single composite threat score. All logic is pure Python with no LLM calls — deterministic, fast, and unit-testable.

The node applies per-source normalisation functions that produce a float between 0.0 (clean) and 1.0 (highly malicious). Weights are then applied. If a source is absent (API failure or inapplicable), its weight is redistributed proportionally among available sources.


> # agent/scoring.py
> # Standard weights — used for all IOC types except CVE
> # Weights sum to 1.00. Sources not applicable to a given IOC type
> # are excluded and remaining weights re-normalised to maintain sum = 1.00.
> BASE_WEIGHTS = {
> 'virustotal': 0.40,
> 'abuseipdb': 0.30, # IP only
> 'otx': 0.20,
> 'urlscan': 0.10, # URL only
> }
> # CVE-specific weights — used only when ioc_type == 'cve'
> # AbuseIPDB and urlscan are not applicable to CVE identifiers.
> CVE_WEIGHTS = {
> 'virustotal': 0.50,
> 'otx': 0.30,
> 'nvd': 0.20, # NIST NVD — CVE type only
> }
> def normalise_virustotal(raw: dict) -> float:
> stats = raw.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
> malicious = stats.get('malicious', 0)
> suspicious = stats.get('suspicious', 0)
> total = sum(stats.values()) or 1
> return (malicious + suspicious * 0.5) / total
> def normalise_abuseipdb(raw: dict) -> float:
> score = raw.get('data', {}).get('abuseConfidenceScore', 0)
> return score / 100.0
> def normalise_otx(raw: dict) -> float:
> pulse_count = len(raw.get('pulse_info', {}).get('pulses', []))
> if pulse_count == 0: return 0.0
> if pulse_count <= 2: return 0.5
> return min(1.0, 0.5 + (pulse_count - 2) * 0.1)
> def compute_composite(raw_intel: dict, intel_errors: list) -> tuple[float, dict, dict]:
> """Returns (composite_score, score_breakdown, active_weights)"""
> # ... weight redistribution + scoring logic ...


**7.5 severity_node**

|                 |             |                                                                            |
|-----------------|-------------|----------------------------------------------------------------------------|
| **Score Range** | **Verdict** | **Analyst Guidance**                                                       |
| **0.00 – 0.10** | 🟢 CLEAN    | No credible threat signals detected across all queried sources.            |
| **0.11 – 0.30** | 🟡 LOW      | Stale or minor signals. Monitor; no immediate action required.             |
| **0.31 – 0.55** | 🟠 MEDIUM   | Credible signals from one or more sources. Investigate; consider blocking. |
| **0.56 – 0.75** | 🔴 HIGH     | Strong multi-source signals. Block immediately and open incident ticket.   |
| **0.76 – 1.00** | 🚨 CRITICAL | Confirmed malicious with high confidence. Block + escalate to IR team.     |

**7.6 escalation_gate (Human-in-the-Loop)**

When severity_band is CRITICAL, execution pauses and a confirmation prompt is rendered to the analyst before the final report is released. This implements LangGraph's interrupt_before pattern.


> # CRITICAL escalation in CLI mode
> def escalation_gate(state: AgentState) -> dict:
> print("\n⚠️ CRITICAL SEVERITY DETECTED")
> print(f" IOC: {state['ioc_clean']}")
> print(f" Score: {state['composite_score']:.3f}")
> print("\nThis verdict will trigger immediate blocking recommendations.")
> confirm = input("Proceed? (yes / abort): ").strip().lower()
> if confirm != 'yes':
> raise SystemExit('Triage aborted by analyst at escalation gate.')
> return {} # No state changes — pass through to report_node




## 8. LangChain Tool Layer

Each threat intelligence API is wrapped as a LangChain BaseTool subclass. This design provides a consistent interface, enables async execution, integrates automatically with OpenInference tracing, and allows tools to be swapped or extended without modifying the graph.

**8.1 Tool Base Class Pattern**


> # agent/tools/base.py
> from langchain.tools import BaseTool
> from pydantic import Field
> import httpx, asyncio
> class ThreatIntelTool(BaseTool):
> """Abstract base for all threat intelligence tool wrappers."""
> api_key: str = Field(default_factory=lambda: os.getenv('...'))
> base_url: str = ''
> max_retries: int = 3
> retry_delay: float= 1.5 # seconds, doubles on each retry
> async def _arun(self, ioc: str) -> dict:
> """Async execution with exponential backoff retry."""
> for attempt in range(self.max_retries):
> try:
> async with httpx.AsyncClient(timeout=15.0) as client:
> return await self._fetch(client, ioc)
> except (httpx.TimeoutException, httpx.HTTPStatusError) as e:
> if attempt == self.max_retries - 1:
> raise
> await asyncio.sleep(self.retry_delay * (2 ** attempt))
> async def _fetch(self, client: httpx.AsyncClient, ioc: str) -> dict:
> raise NotImplementedError
> def _run(self, ioc: str) -> dict:
> return asyncio.run(self._arun(ioc)) # sync fallback for non-async contexts


**8.2 Tool Implementations**

|                |                           |                                                                      |                 |                                                                  |
|----------------|---------------------------|----------------------------------------------------------------------|-----------------|------------------------------------------------------------------|
| **Tool**       | **Module**                | **Endpoint**                                                         | **Auth**        | **Key Response Fields**                                          |
| **VirusTotal** | agent/tools/virustotal.py | GET /api/v3/ip_addresses/{ip} (or /domains/, /files/, /urls/)        | X-Apikey header | dict: last_analysis_stats, community_score, tags                 |
| **AbuseIPDB**  | agent/tools/abuseipdb.py  | GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true        | Key header      | dict: abuseConfidenceScore, totalReports, usageType, countryCode |
| **OTX**        | agent/tools/otx.py        | GET /api/v1/indicators/{type}/{ioc}/general (pulses, tags, sections) | X-OTX-API-KEY   | dict: pulse_info.pulses\[\].name, tags, adversary                |
| **urlscan.io** | agent/tools/urlscan.py    | POST /api/v1/scan/ then GET /api/v1/result/{uuid}/                   | API-Key header  | dict: verdicts.overall.score, page.domain, screenshot_url        |
| **NIST NVD**   | agent/tools/nvd.py        | GET /rest/json/cves/2.0?cveId={cve}                                  | None            | dict: cveMetadata, cvssMetricV31, weaknesses                     |

**8.3 urlscan.io Two-Phase Flow**

urlscan.io is architecturally distinct because it is an asynchronous service — the scan must be submitted first, then polled until complete. The urlscan Tool implements this internally with a polling loop, hiding the complexity from the graph.


> # agent/tools/urlscan.py — Two-phase scan pattern
> async def _fetch(self, client, url: str) -> dict:
> # Phase 1: Submit scan
> submit_resp = await client.post(
> 'https://urlscan.io/api/v1/scan/',
> headers={'API-Key': self.api_key, 'Content-Type': 'application/json'},
> json={'url': url, 'visibility': 'public'}
> )
> uuid = submit_resp.json()['uuid']
> # Phase 2: Poll for result (max 30s, 3s interval)
> for _ in range(10):
> await asyncio.sleep(3)
> result_resp = await client.get(f'https://urlscan.io/api/v1/result/{uuid}/')
> if result_resp.status_code == 200:
> return result_resp.json()
> raise TimeoutError(f'urlscan result not ready for {uuid} after 30s')




## 9. Credential Management Architecture

Credential management is a first-class architectural concern. The design ensures no key ever appears in source code, log output, terminal history, or notebook cell output, while still providing a frictionless experience for both first-time users and daily operators.

**9.1 Resolution Chain**


> # agent/credentials.py
> REQUIRED_KEYS = [
> 'OPENAI_API_KEY', 'VIRUSTOTAL_API_KEY', 'ABUSEIPDB_API_KEY',
> 'OTX_API_KEY', 'URLSCAN_API_KEY', 'ARIZE_API_KEY', 'ARIZE_SPACE_ID'
> ]
> def resolve_credentials() -> None:
> """
> Resolution order (highest to lowest priority):
> 1. Already in os.environ (Docker/CI injection or previous .env load)
> 2. .env file in current working directory (loaded via python-dotenv)
> 3. Interactive getpass() prompt for any still-missing keys
> """
> # Step 1: Try .env file
> if Path('.env').exists():
> load_dotenv(dotenv_path='.env', override=False) # override=False respects existing env
> # Step 2: Identify missing keys
> missing = [k for k in REQUIRED_KEYS if not os.getenv(k)]
> # Step 3: Interactive prompt for missing keys only
> if missing:
> print('\nSome API keys are missing. Enter them below (input is masked):\n')
> for key in missing:
> value = getpass(f' {key}: ')
> os.environ[key] = value # in-memory only
> # Step 4: Final validation — raise if still missing
> still_missing = [k for k in REQUIRED_KEYS if not os.getenv(k)]
> if still_missing:
> raise EnvironmentError(f'Required keys not provided: {still_missing}')


**9.2 Jupyter Notebook Key Isolation**

In the Jupyter Notebook context, the getpass() library masks input and — critically — the entered value is never stored in the cell output. However, there are additional risks specific to notebooks:

|                           |              |                                                       |                       |
|---------------------------|--------------|-------------------------------------------------------|-----------------------|
| **Risk**                  | **Severity** | **Mitigation**                                        | **Enforcement**       |
| **Key in cell output**    | HIGH         | getpass() masks input; output cell remains empty      | By design             |
| **Key in .ipynb JSON**    | HIGH         | getpass() never returns value to output stream        | By design             |
| **Key in notebook vars**  | MEDIUM       | Variable assigned only in os.environ, not a named var | Architectural pattern |
| **Key in Arize spans**    | HIGH         | Span attribute allowlist excludes all \*\_KEY fields  | tracing.py filter     |
| **Key in error messages** | MEDIUM       | Exception handler sanitises messages before display   | credentials.py        |




## 10. Observability Architecture (Arize AI)

Observability is architecturally embedded at the graph level, not added as an afterthought. The OpenInference library auto-instruments all LangChain and LangGraph operations, and the arize-otel exporter streams spans in real-time to the Arize platform using the OTLP protocol.

**10.1 Instrumentation Initialisation**


> # agent/tracing.py
> from arize.otel import register
> from openinference.instrumentation.langchain import LangChainInstrumentor
> def init_tracing(project_name: str = 'flowrun-streamlet-ioc-triage') -> TracerProvider:
> tracer_provider = register(
> space_id = os.getenv('ARIZE_SPACE_ID'),
> api_key = os.getenv('ARIZE_API_KEY'),
> model_id = project_name,
> )
> # Auto-instruments ALL LangChain ChatModel calls, tool invocations,
> # and LangGraph node executions with OpenInference-compliant spans
> LangChainInstrumentor().instrument(tracer_provider=tracer_provider)
> return tracer_provider
> # Called once at agent startup — before graph.compile() is invoked


**10.2 Span Hierarchy & Attribute Mapping**


```
ROOT TRACE: flowrun.triage
Attributes: ioc.type, ioc.value, severity.band, composite.score,
run.duration_ms, error.count
│
├── SPAN: langchain.llm (classifier_node — GPT-5.2 Instant (gpt-5.2-chat-latest, effort=low))
│ Attributes: llm.model_name, llm.prompt_tokens,
│ llm.completion_tokens, llm.temperature,
│ input.value (classifier prompt), output.value (type JSON)
│
├── SPAN: langchain.tool (enrichment_node — VirusTotal)
│ Attributes: tool.name='virustotal', input.value, output.value,
│ tool.latency_ms, tool.status='success'|'error'
│
├── SPAN: langchain.tool (enrichment_node — AbuseIPDB, if IP type)
│ Attributes: tool.name='abuseipdb', ...same pattern...
│
├── SPAN: langchain.tool (enrichment_node — OTX)
├── SPAN: langchain.tool (enrichment_node — urlscan, if URL type)
├── SPAN: langchain.tool (enrichment_node — NVD, if CVE type)
│
├── SPAN: flowrun.correlate (correlation_node — custom span)
│ Attributes: score.virustotal, score.abuseipdb, score.otx,
│ score.urlscan, composite.score, weights.active
│
└── SPAN: flowrun.severity (severity_node — custom span)
Attributes: severity.band, verdict.justification,
escalation.required
```


**10.3 Custom Span Instrumentation Pattern**

While LangChain and LangGraph operations are auto-instrumented, the correlation and severity nodes require manual span creation using the OpenTelemetry API to capture their custom attributes.


> # agent/nodes.py — manual span example in correlation_node
> from opentelemetry import trace
> from openinference.semconv.trace import SpanAttributes
> tracer = trace.get_tracer(__name__)
> def correlation_node(state: AgentState) -> dict:
> with tracer.start_as_current_span('flowrun.correlate') as span:
> composite, breakdown, weights = compute_composite(
> state['raw_intel'], state['intel_errors']
> )
> # Record score breakdown as span attributes
> for source, score in breakdown.items():
> span.set_attribute(f'score.{source}', score)
> span.set_attribute('composite.score', composite)
> span.set_attribute('sources.available', list(breakdown.keys()))
> return {
> 'composite_score': composite,
> 'score_breakdown': breakdown,
> 'active_weights': weights
> }




## 11. Jupyter Notebook Architecture

The Jupyter Notebook version is not a simplified demo — it is a fully functional interface that calls the same agent/graph.py module as the CLI. The notebook is responsible only for the interaction layer (Cell 6 input, Cell 7 output), while all business logic runs from the shared agent package.

**11.1 Cell Architecture**

|            |                   |                                                                                                           |                       |
|------------|-------------------|-----------------------------------------------------------------------------------------------------------|-----------------------|
| **Cell**   | **Name**          | **Responsibility**                                                                                        | **Module**            |
| **Cell 1** | Install & Import  | pip install block (commented out for reuse). All import statements. Confirms Python 3.11+ version.        | agent/\_\_init\_\_.py |
| **Cell 2** | Credential Setup  | getpass() or load_dotenv() key resolution. Calls agent.credentials.resolve_credentials().                 | agent/credentials.py  |
| **Cell 3** | Tracing Init      | Calls agent.tracing.init_tracing(). Prints confirmation that Arize connection is established.             | agent/tracing.py      |
| **Cell 4** | Tool Definitions  | Instantiates all 5 LangChain Tool objects. Prints tool names for confirmation.                            | agent/tools/\*.py     |
| **Cell 5** | Graph Compilation | Calls agent.graph.build_graph(). Optionally renders graph structure as ASCII diagram.                     | agent/graph.py        |
| **Cell 6** | IOC Input Widget  | ipywidgets.Text input + Button. On click: validates input, calls graph.ainvoke(), triggers Cell 7 update. | ipywidgets            |
| **Cell 7** | Report Display    | IPython.display.HTML renders report_html from state. Formats severity badge with colour coding.           | agent/report.py       |
| **Cell 8** | Arize Link        | Prints arize_trace_url from state. Displays clickable HTML link to trace in Arize dashboard.              | agent/tracing.py      |

**11.2 Widget Interaction Pattern**


> # Cell 6 — ipywidgets interaction pattern
> import ipywidgets as widgets
> from IPython.display import display, HTML, clear_output
> ioc_input = widgets.Text(placeholder='Enter IOC: IP, domain, URL, or hash...',
> layout=widgets.Layout(width='60%'))
> analyze_btn = widgets.Button(description='Analyze', button_style='danger')
> output_area = widgets.Output()
> async def on_analyze_click(b):
> with output_area:
> clear_output(wait=True)
> ioc = ioc_input.value.strip()
> if not ioc:
> display(HTML('<p style="color:red">Please enter an IOC.</p>'))
> return
> display(HTML('<p>🔍 Triaging <b>{}</b>...</p>'.format(ioc)))
> # Run agent graph
> result_state = await graph.ainvoke({'ioc_raw': ioc})
> # Cell 7 update is triggered by the shared output_area widget
> display(HTML(result_state['report_html']))
> display(HTML(f'<a href="{result_state["arize_trace_url"]}"
> target="_blank">🔗 View trace in Arize</a>'))
> analyze_btn.on_click(lambda b: asyncio.ensure_future(on_analyze_click(b)))
> display(widgets.HBox([ioc_input, analyze_btn]), output_area)




## 12. Error Handling & Resilience Design

The system distinguishes between three categories of error, each handled differently to maximise triage completion rate and analyst utility.

|                            |                                                                                  |                                                                                             |                            |
|----------------------------|----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|----------------------------|
| **Category**               | **Trigger**                                                                      | **Behaviour**                                                                               | **Enforcement Location**   |
| **Fatal Error**            | Unrecognisable IOC type; missing all API keys; graph initialisation failure      | Halt with clear error message. Never produce a partial report.                              | Route to error_node → END  |
| **Non-fatal Source Error** | Single API timeout, 429 rate limit, 5xx server error                             | Log to intel_errors in state. Re-normalise weights. Include 'source unavailable' in report. | enrichment_node try/except |
| **Warning**                | Low classifier confidence (\<0.6); no OTX pulses found; urlscan still processing | Include caveat in report. Do not affect scoring unless directly relevant.                   | report_node formatting     |

**12.1 Retry Architecture**

All five LangChain Tools implement exponential backoff via the ThreatIntelTool base class. The retry schedule is: attempt 1 immediately, attempt 2 after 1.5s, attempt 3 after 3.0s. After three failures, the exception propagates to enrichment_node's gather handler and is recorded as a non-fatal intel_error.

**12.2 Weight Re-normalisation on Source Failure**


> # agent/scoring.py — weight redistribution
> def redistribute_weights(base_weights: dict, available_sources: list) -> dict:
> """
> If a source is unavailable, redistribute its weight proportionally
> among available sources so the composite score always sums to 1.0.
> Example: abuseipdb unavailable (weight 0.30)
> → remaining weights: vt=0.40, otx=0.20, urlscan=0.10 (sum=0.70)
> → redistribute: vt=0.571, otx=0.286, urlscan=0.143 (sum=1.00)
> """
> active = {k: v for k, v in base_weights.items() if k in available_sources}
> total = sum(active.values())
> return {k: v/total for k, v in active.items()}




## 13. Security Architecture

|                           |                                                                                                                                                             |
|---------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Control**               | **Implementation**                                                                                                                                          |
| **Credential Isolation**  | Keys live only in os.environ in-memory. getpass() prevents terminal echo. .env excluded from version control via .gitignore.                                |
| **Outbound TLS only**     | All HTTP calls use httpx with default TLS verification enabled. No plaintext HTTP. Certificate pinning not required for v1.0.                               |
| **Input sanitisation**    | IOC strings are normalised and length-limited (max 2048 chars) before being passed to any external API to prevent injection.                                |
| **Span attribute filter** | A span attribute allowlist in tracing.py explicitly excludes any attribute key matching \*\_KEY, \*\_SECRET, \*\_TOKEN, \*\_PASSWORD.                       |
| **urlscan.io privacy**    | urlscan.io public scans are visible to third parties. Documented in User Manual. Sensitive IOCs should use the private scan API (paid tier) in production.  |
| **API key rotation**      | The .env.template and README document how to revoke and rotate all keys. No key is used beyond a single session's os.environ lifetime.                      |
| **LLM prompt injection**  | The classifier node's prompt is a closed system prompt. The IOC value is passed as a separate user message, not interpolated into the system prompt string. |




## 14. Performance Architecture

The dominant latency driver is the parallel enrichment step. The design goal is to complete a full triage in under 30 seconds under normal API response conditions.

**14.1 Latency Budget**

|                      |                      |                                                                                                   |
|----------------------|----------------------|---------------------------------------------------------------------------------------------------|
| **Stage**            | **Latency Estimate** | **Notes**                                                                                         |
| **input_node**       | \<50ms               | Regex, string ops only. No I/O.                                                                   |
| **classifier_node**  | 400–900ms            | GPT-5.2 Instant call (effort=low). Faster than Thinking. Cached if regex pre-check resolves type. |
| **enrichment_node**  | 5–20s                | Bounded by slowest single API (parallel). urlscan.io is typically slowest at 10–15s.              |
| **correlation_node** | \<20ms               | Pure Python arithmetic. No I/O.                                                                   |
| **severity_node**    | \<5ms                | Simple threshold mapping. No I/O.                                                                 |
| **report_node**      | 100–300ms            | String formatting + HTML rendering. No external I/O.                                              |
| **Arize export**     | \<500ms              | Async OTLP gRPC export — non-blocking, does not delay report output.                              |
| **TOTAL (typical)**  | ~8–22s               | Dominated by enrichment parallelism.                                                              |

**14.2 Async Architecture**

The entire agent is async-native. The CLI entry point uses asyncio.run() to execute the graph. The Jupyter interface uses asyncio.ensure_future() within the widget callback. All five Tool classes implement \_arun() as native coroutines, allowing asyncio.gather() to achieve true parallel I/O.


> **Why asyncio.gather over ThreadPoolExecutor**
> Pure I/O-bound workload: all API calls are network I/O with zero CPU work during wait time.
> asyncio.gather() has lower overhead than thread pool scheduling for 5 concurrent tasks.
> return_exceptions=True allows individual task failures to be handled gracefully without cancelling siblings.
> LangGraph's StateGraph natively supports async node functions with ainvoke().




## 15. Extension Model — Adding New Intelligence Sources

The architecture is designed so that new threat intelligence sources can be added without modifying the LangGraph graph, the correlation logic's core loop, or any existing tool. The following steps are all that is required:

1.  Create a new integration module at agent/integrations/newsource.py implementing the raw HTTP client and response normaliser function.

2.  Create a new tool module at agent/tools/newsource.py subclassing ThreatIntelTool and implementing \_fetch().

3.  Add the new source's base weight to BASE_WEIGHTS in agent/scoring.py (or CVE_WEIGHTS if applicable only to CVE IOC type). Ensure weights in each dict continue to sum to 1.00 after re-normalisation.

4.  Add the new source's normaliser function to the NORMALISERS dict in agent/scoring.py.

5.  Register the new tool instance in enrichment_node's task dictionary, gated on the applicable ioc_type(s).

6.  Add the new source's API key variable to REQUIRED_KEYS in agent/credentials.py and to .env.template.


> **No other files need to change**
> The graph topology, state schema, conditional edges, severity thresholds, report formatter, and Arize tracing all adapt automatically.
> Weight redistribution in correlation_node handles the new source being absent for incompatible IOC types.
> OpenInference auto-instrumentation will capture the new tool's spans without any additional tracing code.




## 16. Deployment Architecture

**16.1 v1.0 — Local Deployment**

|                   |                                                                      |
|-------------------|----------------------------------------------------------------------|
| **Attribute**     | **Specification**                                                    |
| **Runtime**       | Python 3.11+ virtual environment (venv or conda)                     |
| **Entry Point**   | python flowrun_agent.py (CLI) \| jupyter notebook (Jupyter)          |
| **Configuration** | .env file or interactive getpass() at startup                        |
| **Dependencies**  | requirements.txt — fully pinned versions for reproducibility         |
| **OS Support**    | macOS 12+, Ubuntu 20.04+, Windows 10+ (WSL2)                         |
| **Network**       | Outbound HTTPS to 5 APIs + gRPC to Arize. No inbound ports required. |
| **Persistence**   | None — stateless. Each run is independent. No database.              |

**16.2 v2.0 — Containerised API Deployment (Roadmap)**


> # Dockerfile concept for v2.0 REST API deployment
> FROM python:3.11-slim
> WORKDIR /app
> COPY requirements.txt .
> RUN pip install --no-cache-dir -r requirements.txt
> COPY agent/ ./agent/
> COPY flowrun_api.py .
> # Keys injected as environment variables — never baked into image
> # docker run -e OPENAI_API_KEY=... -e VIRUSTOTAL_API_KEY=... flowrun-streamlet
> EXPOSE 8000
> CMD ["uvicorn", "flowrun_api:app", "--host", "0.0.0.0", "--port", "8000"]


FlowRun Streamlet: IoC Triage · Architectural Design Document v1.0 · LangGraph + LangChain + Arize AI · INTERNAL
