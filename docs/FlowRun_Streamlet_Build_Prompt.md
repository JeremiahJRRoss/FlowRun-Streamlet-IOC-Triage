# BUILD PROMPT — FlowRun Streamlet: IoC Triage
## Complete Engineering Instructions for Claude

---

## CONTEXT & YOUR MISSION

You are being asked to build a complete, working application called **FlowRun Streamlet: IoC Triage**. Three reference documents are attached to this conversation:

1. **FlowRun_Streamlet_IoC_Triage_User_Manual_v2.docx** — describes the product from a user perspective, how it behaves, and how credentials are managed
2. **FlowRun_Streamlet_IoC_Triage_PRD_v2.docx** — contains all functional requirements (FR-01 through FR-39), non-functional requirements (NFR-01 through NFR-10), the scoring formula, acceptance criteria, and the full tech stack
3. **FlowRun_Streamlet_IoC_Triage_Architecture_v2.docx** — contains the complete system design: every module, every node, the AgentState schema, all LangGraph graph topology, LangChain tool patterns, Arize tracing setup, scoring code, and the Jupyter Notebook cell architecture

**Read all three documents thoroughly before writing a single line of code.** They are the single source of truth. Where a detail is not specified in this prompt, defer to the documents.

Your job is to produce the **complete, runnable v1.0 application** — every file, every module, no stubs, no placeholders.

---

## WHAT YOU ARE BUILDING

A security operations tool that:
- Accepts a single IOC (IP address, domain, URL, file hash, or CVE identifier) from an analyst
- Queries up to 5 threat intelligence APIs **concurrently** using `asyncio.gather()`
- Correlates results using a weighted scoring formula into a composite threat score (0.0–1.0)
- Maps the score to one of **five** severity verdicts: CLEAN, LOW, MEDIUM, HIGH, CRITICAL
- Outputs a structured threat report
- Sends a full execution trace to Arize AI for observability
- Pauses for human confirmation before releasing a CRITICAL verdict
- Runs as both a **CLI application** and a **Jupyter Notebook**

---

## MANDATORY TECHNICAL STACK

Use exactly these. Do not substitute alternatives.

| Component | Library / Version |
|---|---|
| Agent orchestration | `langgraph >= 0.2` — StateGraph |
| LLM framework | `langchain >= 0.3`, `langchain-openai >= 0.1` |
| Language model (classifier) | OpenAI GPT-5.2 Instant — `gpt-5.2-chat-latest`, `reasoning_effort=low` |
| Language model (report) | OpenAI GPT-5.2 Thinking — `gpt-5.2`, `reasoning_effort=medium` |
| HTTP client | `httpx` (async) |
| Observability | `arize-otel` + `openinference-instrumentation-langchain` |
| Tracing protocol | OTLP → Arize AI |
| Key loading | `python-dotenv` |
| Notebook widgets | `ipywidgets >= 8.0` |
| Runtime | Python 3.11+, `asyncio` |

Install command for `requirements.txt`:
```
langgraph>=0.2
langchain>=0.3
langchain-openai>=0.1
openai>=1.0
httpx>=0.27
arize-otel
openinference-instrumentation-langchain
python-dotenv>=1.0
ipywidgets>=8.0
```

---

## PROJECT FILE STRUCTURE

Create every file listed below. No file may be omitted.

```
flowrun-streamlet-ioc-triage/
│
├── flowrun_agent.py              # CLI entry point
├── flowrun_agent.ipynb           # Jupyter Notebook (8 cells)
├── requirements.txt
├── .env.template                 # Shows all required variable names — NO values
├── .gitignore                    # Must include: .env, __pycache__, .ipynb_checkpoints
│
├── agent/
│   ├── __init__.py
│   ├── graph.py                  # LangGraph StateGraph — all nodes and edges
│   ├── state.py                  # AgentState TypedDict
│   ├── llm.py                    # MODEL_CONFIG dict + get_llm(task) factory — one place to change any model
│   ├── tracing.py                # Arize / OpenInference tracer setup
│   ├── credentials.py            # Key resolution: .env → os.environ → getpass()
│   ├── scoring.py                # Composite score formula, BASE_WEIGHTS, CVE_WEIGHTS
│   ├── report.py                 # Report formatter — CLI text + HTML (Jupyter)
│   │
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── base.py               # ThreatIntelTool abstract base class with retry
│   │   ├── virustotal.py
│   │   ├── abuseipdb.py
│   │   ├── otx.py
│   │   ├── urlscan.py            # Two-phase: submit scan then poll result
│   │   └── nvd.py
│   │
│   └── integrations/
│       ├── __init__.py
│       ├── virustotal.py         # Raw HTTP client + response normaliser
│       ├── abuseipdb.py
│       ├── otx.py
│       ├── urlscan.py
│       └── nvd.py
│
└── tests/
    ├── test_classifier.py        # Tests IOC type detection for all 7 types
    ├── test_scoring.py           # Tests weight formula, CVE weights, redistribution
    ├── test_tools.py             # Uses httpx mock responses
    └── test_graph.py             # Integration test with stubbed tools
```

---

## CRITICAL IMPLEMENTATION RULES

Read each of these carefully. Violations will break the application.

### 1. IOC Types — Seven, Not Six
The classifier must detect and handle exactly **seven** IOC types:
- `ip` — IPv4 or IPv6
- `domain` — hostname/FQDN without scheme
- `url` — full URL with http/https/ftp scheme
- `hash_md5` — exactly 32 hex characters
- `hash_sha1` — exactly 40 hex characters
- `hash_sha256` — exactly 64 hex characters
- `cve` — CVE-YYYY-NNNNN format
- `unknown` — routes to error_node

### 2. Severity Tiers — Five, Not Four
Map composite scores to exactly **five** distinct tiers:
```
0.00 – 0.10  →  CLEAN
0.11 – 0.30  →  LOW
0.31 – 0.55  →  MEDIUM
0.56 – 0.75  →  HIGH
0.76 – 1.00  →  CRITICAL
```
CRITICAL must trigger the escalation gate (human-in-the-loop pause). HIGH does not.

### 3. Scoring Weights — Two Separate Dicts, Both Must Sum to 1.00
**BASE_WEIGHTS** (all IOC types except CVE):
```python
BASE_WEIGHTS = {
    'virustotal': 0.40,
    'abuseipdb':  0.30,  # IP type only — redistributed for others
    'otx':        0.20,
    'urlscan':    0.10,  # URL type only — redistributed for others
}
```
**CVE_WEIGHTS** (only when ioc_type == 'cve'):
```python
CVE_WEIGHTS = {
    'virustotal': 0.50,
    'otx':        0.30,
    'nvd':        0.20,
}
```
When sources are absent (API failure or inapplicable type), redistribute their weight proportionally so the active weights always sum to exactly 1.00.

### 4. Parallelism — asyncio.gather(), Not LangGraph Fan-Out
The enrichment node is a **single async LangGraph node** that calls all applicable tools concurrently using `asyncio.gather(return_exceptions=True)`. Do NOT split enrichment into multiple parallel graph nodes.

```python
async def enrichment_node(state: AgentState) -> dict:
    tasks = {'virustotal': vt_tool.ainvoke(state['ioc_clean']),
             'otx':        otx_tool.ainvoke(state['ioc_clean'])}
    if state['ioc_type'] == 'ip':
        tasks['abuseipdb'] = abuseipdb_tool.ainvoke(state['ioc_clean'])
    if state['ioc_type'] == 'url':
        tasks['urlscan'] = urlscan_tool.ainvoke(state['ioc_clean'])
    if state['ioc_type'] == 'cve':
        tasks['nvd'] = nvd_tool.ainvoke(state['ioc_clean'])
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    raw_intel, intel_errors = {}, []
    for source, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            intel_errors.append(f'{source}: {type(result).__name__}: {result}')
        else:
            raw_intel[source] = result
    return {'raw_intel': raw_intel, 'intel_errors': intel_errors}
```

### 5. urlscan.io — Two-Phase Async Poll
urlscan.io requires submitting a scan and then polling for results. Implement the two-phase flow inside the tool's `_fetch()` method:
- POST to `/api/v1/scan/` to get a UUID
- Poll GET `/api/v1/result/{uuid}/` every 3 seconds, up to 10 attempts (30s max)
- Raise `TimeoutError` if result is not ready after 30s

### 6. Credentials — Three-Step Resolution, No Hardcoding
Implement in `agent/credentials.py` in this exact resolution order:
1. Load `.env` file if present (using `load_dotenv(override=False)`)
2. Check `os.environ` for each required key
3. Call `getpass()` interactively for any still-missing keys

Required keys: `OPENAI_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `URLSCAN_API_KEY`, `ARIZE_API_KEY`, `ARIZE_SPACE_ID`

**Never** hardcode a key value. **Never** print a key to stdout. **Never** include a key in any Arize span attribute.

### 7. AgentState — Use This Exact Schema
```python
from typing import TypedDict, Any

class AgentState(TypedDict):
    ioc_raw:               str
    ioc_clean:             str
    ioc_type:              str
    raw_intel:             dict[str, Any]
    intel_errors:          list[str]
    score_breakdown:       dict[str, float]
    composite_score:       float
    active_weights:        dict[str, float]
    severity_band:         str
    verdict_justification: str
    escalation_required:   bool
    report_text:           str
    report_html:           str
    arize_trace_url:       str
```

### 8. LangGraph Graph Topology — Exact Structure Required
```
input_node
    ↓
classifier_node
    ↓ (conditional)
    ├─ ioc_type == 'unknown' → error_node → END
    └─ all other types → enrichment_node
                              ↓
                         correlation_node
                              ↓
                          severity_node
                              ↓ (conditional)
                    ├─ CRITICAL → escalation_gate → report_node → END
                    └─ all others → report_node → END
```

### 9. Arize Tracing — Auto-Instrumentation + Custom Spans
In `agent/tracing.py`:
```python
from arize.otel import register
from openinference.instrumentation.langchain import LangChainInstrumentor

def init_tracing(project_name='flowrun-streamlet-ioc-triage'):
    tracer_provider = register(
        space_id=os.getenv('ARIZE_SPACE_ID'),
        api_key=os.getenv('ARIZE_API_KEY'),
        model_id=project_name,
    )
    LangChainInstrumentor().instrument(tracer_provider=tracer_provider)
    return tracer_provider
```

Add manual spans in `correlation_node` and `severity_node` using `opentelemetry.trace` with attributes as specified in the Architecture document Section 10.2.

### 10. Tool Retry Logic — Exponential Backoff
Every tool must implement 3 retry attempts with exponential backoff: 1.5s, 3.0s delays. A tool that fails all 3 attempts must raise an exception (which `enrichment_node` catches as a non-fatal `intel_error`).

---

## AGENT/LLM.PY — MODEL CONFIGURATION

This is the **single file that controls which model is used for every task**. Implement it exactly as shown. No other file should contain a hardcoded model string.

```python
# agent/llm.py
# ─────────────────────────────────────────────────────────────────────────────
# MASTER MODEL CONFIGURATION
# To change the model, variant, or reasoning effort for any task in the agent,
# edit ONE entry in MODEL_CONFIG below. Nothing else needs to change.
# ─────────────────────────────────────────────────────────────────────────────

from langchain_openai import ChatOpenAI

MODEL_CONFIG: dict[str, dict] = {

    # ── IOC Type Classification ───────────────────────────────────────────────
    # Task: Classify a raw string into one of 7 IOC types. Returns tiny JSON.
    # Why Instant: Deterministic, structured output, latency-sensitive (first node).
    # Why effort=low: No multi-step reasoning needed for pattern recognition.
    "classifier": {
        "model":            "gpt-5.2-chat-latest",  # GPT-5.2 Instant
        "reasoning_effort": "low",
        "temperature":      0.0,
    },

    # ── Threat Report Synthesis ───────────────────────────────────────────────
    # Task: Synthesise raw multi-source intel into a structured threat report.
    # Why Thinking: Needs to reconcile conflicting signals, write analyst guidance.
    # Why effort=medium: Quality matters; xhigh would add unnecessary latency.
    "report": {
        "model":            "gpt-5.2",  # GPT-5.2 Thinking
        "reasoning_effort": "medium",
        "temperature":      0.3,
    },
}


def get_llm(task: str) -> ChatOpenAI:
    """
    Return a ChatOpenAI instance configured for the named task.

    Usage:
        classifier_llm = get_llm("classifier")   # gpt-5.2-chat-latest, effort=low
        report_llm     = get_llm("report")        # gpt-5.2, effort=medium

    To swap a model for any task, edit MODEL_CONFIG above — not this function.
    """
    if task not in MODEL_CONFIG:
        raise ValueError(f"Unknown task '{task}'. Valid tasks: {list(MODEL_CONFIG)}")
    cfg = MODEL_CONFIG[task]
    kwargs = {}
    if "reasoning_effort" in cfg:
        kwargs["model_kwargs"] = {"reasoning_effort": cfg["reasoning_effort"]}
    return ChatOpenAI(
        model=cfg["model"],
        temperature=cfg.get("temperature", 0.0),
        **kwargs,
    )


# ── Classifier system prompt ──────────────────────────────────────────────────
CLASSIFIER_SYSTEM = """
You are a security analyst IOC classifier.
Classify the given string into exactly one of these types:
  ip          → IPv4 or IPv6 address
  domain      → Hostname or FQDN (no scheme, no path)
  url         → Full URL with scheme (http/https/ftp)
  hash_md5    → Exactly 32 hex characters
  hash_sha1   → Exactly 40 hex characters
  hash_sha256 → Exactly 64 hex characters
  cve         → CVE identifier (CVE-YYYY-NNNNN format)
  unknown     → Cannot be classified

Respond ONLY with a JSON object — no preamble, no markdown:
{ "type": "<type>", "clean": "<normalised_value>", "confidence": 0.0 }

Where "clean" is the normalised form: lowercase domains/URLs,
uppercase hex hashes, uppercase CVE identifiers.
If confidence < 0.6, set type to "unknown".
"""
```

Use `JsonOutputParser` from LangChain to parse the classifier response. If parsing fails, default to `ioc_type = 'unknown'`.

**In every node that needs an LLM:**
```python
# classifier_node
llm = get_llm("classifier")

# report_node
llm = get_llm("report")
```

**Never** instantiate `ChatOpenAI` directly with a hardcoded model string anywhere else in the codebase.

---

## JUPYTER NOTEBOOK — EXACT 8-CELL STRUCTURE

The notebook `flowrun_agent.ipynb` must contain exactly 8 cells in this order:

**Cell 1 — Install & Import**
```python
# Uncomment to install on first run
# !pip install -r requirements.txt

import os, asyncio
from agent.credentials import resolve_credentials
from agent.tracing import init_tracing
from agent.graph import build_graph
import ipywidgets as widgets
from IPython.display import display, HTML, clear_output
```

**Cell 2 — API Key Setup**
```python
# Option A: Interactive masked input (recommended for shared environments)
# Option B: Load from .env file (recommended for daily use)
# NEVER assign keys as plain string literals in this cell.

resolve_credentials()
print("✅ All API keys resolved.")
```

**Cell 3 — Tracing Init**
```python
tracer_provider = init_tracing()
print("✅ Arize tracing initialised. Project: flowrun-streamlet-ioc-triage")
```

**Cell 4 — Tool Definitions**
```python
from agent.tools.virustotal import VirusTotalTool
from agent.tools.abuseipdb import AbuseIPDBTool
from agent.tools.otx import OTXTool
from agent.tools.urlscan import URLScanTool
from agent.tools.nvd import NVDTool

vt_tool       = VirusTotalTool()
abuseipdb_tool = AbuseIPDBTool()
otx_tool      = OTXTool()
urlscan_tool  = URLScanTool()
nvd_tool      = NVDTool()
print(f"✅ Tools ready: {[t.name for t in [vt_tool, abuseipdb_tool, otx_tool, urlscan_tool, nvd_tool]]}")
```

**Cell 5 — Graph Compilation**
```python
graph = build_graph()
print("✅ LangGraph StateGraph compiled.")
```

**Cell 6 — IOC Input Widget**
```python
ioc_input   = widgets.Text(
    placeholder='Enter IOC: IP, domain, URL, hash, or CVE...',
    layout=widgets.Layout(width='65%')
)
analyze_btn = widgets.Button(description='⚡ Analyze', button_style='danger',
                              layout=widgets.Layout(width='120px'))
output_area = widgets.Output()

async def on_click(b):
    with output_area:
        clear_output(wait=True)
        ioc = ioc_input.value.strip()
        if not ioc:
            display(HTML('<p style="color:red">⚠️ Please enter an IOC.</p>'))
            return
        display(HTML(f'<p>🔍 Triaging <b>{ioc}</b> — please wait...</p>'))
        result = await graph.ainvoke({'ioc_raw': ioc})
        display(HTML(result['report_html']))
        if result.get('arize_trace_url'):
            display(HTML(f'<p><a href="{result["arize_trace_url"]}" target="_blank">🔗 View trace in Arize</a></p>'))

analyze_btn.on_click(lambda b: asyncio.ensure_future(on_click(b)))
display(widgets.VBox([widgets.HBox([ioc_input, analyze_btn]), output_area]))
```

**Cell 7 — Report Display**
(Output is rendered inline in Cell 6's output_area widget — no separate display code needed. Add a markdown cell explaining this.)

**Cell 8 — Arize Link**
```python
# After running a triage in Cell 6, the Arize trace link appears automatically
# in the output area. You can also navigate directly:
print("Arize dashboard: https://app.arize.com")
print("Look for project: flowrun-streamlet-ioc-triage")
```

---

## REPORT FORMAT

### CLI (`report_text`)
```
══════════════════════════════════════════════════
  FlowRun Streamlet: IoC Triage — THREAT REPORT
══════════════════════════════════════════════════
IOC:      <value>
TYPE:     <type>
VERDICT:  <SEVERITY_BAND>
SCORE:    <0.000>

INTELLIGENCE FINDINGS:
  VirusTotal:  <summary>
  AbuseIPDB:   <summary or N/A>
  OTX:         <summary>
  urlscan.io:  <summary or N/A>
  NIST NVD:    <summary or N/A>

CORRELATION:
  <verdict_justification>

ERRORS (non-fatal):
  <list intel_errors, or "None">

RECOMMENDED ACTIONS:
  <action based on severity band>

ARIZE TRACE: <arize_trace_url>
══════════════════════════════════════════════════
```

### Jupyter (`report_html`)
Render the same information as styled HTML with:
- A coloured severity badge (green/yellow/orange/red/dark-red)
- A collapsible section for raw intelligence findings
- Monospace font for hash values
- Clear section headers

---

## ERROR HANDLING REQUIREMENTS

| Scenario | Required Behaviour |
|---|---|
| Unknown IOC type | Route to `error_node`, print clear message, exit gracefully |
| Single API timeout or 5xx | Log to `intel_errors`, continue with remaining sources |
| All APIs fail | Complete triage with empty `raw_intel`, severity defaults to LOW with note |
| Arize export fails | Log warning to stderr, do NOT block triage completion |
| Missing API key after all 3 resolution steps | Raise `EnvironmentError` with clear message listing which keys are missing |
| CRITICAL verdict | Pause, display confirmation prompt, exit if analyst types anything other than `yes` |

---

## ACCEPTANCE CRITERIA (All Must Pass)

Before delivering the code, verify each of these manually or via the test suite:

1. **AC-01** — A known-malicious IP returns severity HIGH or CRITICAL (composite score > 0.56)
2. **AC-02** — `8.8.8.8` (Google DNS) returns CLEAN or LOW (score < 0.30)
3. **AC-03** — Classifier correctly identifies: an IPv4, a domain, an https:// URL, a 32-char MD5, a 40-char SHA-1, a 64-char SHA-256, and a CVE-YYYY-NNNNN string
4. **AC-04** — Enrichment completes in ≤ 1.5× the slowest single API call (parallelism confirmed)
5. **AC-05** — If VirusTotal returns a 500 error, triage completes using remaining sources; report includes "virustotal: unavailable"
6. **AC-06** — After every run, a trace appears in Arize within 10 seconds with all required spans
7. **AC-07** — `grep -r "sk-\|_KEY\s*=" .` returns zero hardcoded key values
8. **AC-08** — Saved `.ipynb` file contains no API key values in cell outputs
9. **AC-09** — A forced CRITICAL verdict pauses execution and prompts the analyst before outputting the report
10. **AC-10** — Full triage completes in under 30 seconds under normal API conditions

---

## DELIVERY INSTRUCTIONS

1. **Output every file in full** — no truncation, no "rest of file omitted", no `# ... same as before`. Every file must be complete and immediately runnable.

2. **Deliver files in this order:**
   - `requirements.txt`
   - `.env.template`
   - `.gitignore`
   - `agent/state.py`
   - `agent/credentials.py`
   - `agent/tracing.py`
   - `agent/llm.py`
   - `agent/scoring.py`
   - `agent/report.py`
   - `agent/tools/base.py`
   - `agent/tools/virustotal.py`
   - `agent/tools/abuseipdb.py`
   - `agent/tools/otx.py`
   - `agent/tools/urlscan.py`
   - `agent/tools/nvd.py`
   - `agent/integrations/virustotal.py`
   - `agent/integrations/abuseipdb.py`
   - `agent/integrations/otx.py`
   - `agent/integrations/urlscan.py`
   - `agent/integrations/nvd.py`
   - `agent/graph.py`
   - `flowrun_agent.py`
   - `flowrun_agent.ipynb`
   - `tests/test_classifier.py`
   - `tests/test_scoring.py`
   - `tests/test_tools.py`
   - `tests/test_graph.py`

3. **After all files**, provide a "Quick Start" section with the exact commands to:
   - Create a virtual environment
   - Install dependencies
   - Copy and fill in `.env.template`
   - Run the CLI
   - Launch the Jupyter Notebook

4. **Do not ask clarifying questions.** The three attached documents answer every ambiguity. If a minor implementation detail is unspecified in both this prompt and the documents, make the most reasonable professional choice and note it briefly in a comment.

5. **Do not summarise what you are about to do.** Begin immediately with `requirements.txt`.

---

## COMMON MISTAKES TO AVOID

- ❌ Do NOT hardcode any model string (e.g., `ChatOpenAI(model="gpt-5.2")`) outside of `MODEL_CONFIG` in `agent/llm.py`
- ❌ Do NOT use the same model for all tasks — classifier uses `gpt-5.2-chat-latest` (Instant, effort=low); report uses `gpt-5.2` (Thinking, effort=medium)
- ❌ Do NOT instantiate `ChatOpenAI` directly in node files — always call `get_llm("task_name")`

- ❌ Do NOT implement only 4 severity tiers — there are **five** (CLEAN, LOW, MEDIUM, HIGH, CRITICAL)
- ❌ Do NOT omit CVE as an IOC type — the NVD tool is only reachable via CVE classification
- ❌ Do NOT add NVD to BASE_WEIGHTS — it belongs only in CVE_WEIGHTS
- ❌ Do NOT let scoring weights sum to anything other than 1.00 in each weight set
- ❌ Do NOT implement LangGraph multi-node fan-out for enrichment — use asyncio.gather() inside one node
- ❌ Do NOT use `input()` in Jupyter cells — use `ipywidgets`
- ❌ Do NOT print API keys anywhere — not in logs, not in error messages, not in spans
- ❌ Do NOT allow a single API failure to abort the whole triage
- ❌ Do NOT allow Arize export failure to block the triage report output
- ❌ Do NOT use `requests` for the async tool layer — use `httpx` with `AsyncClient`

---

*This prompt references: FlowRun_Streamlet_IoC_Triage_User_Manual_v2.docx, FlowRun_Streamlet_IoC_Triage_PRD_v2.docx, FlowRun_Streamlet_IoC_Triage_Architecture_v2.docx*

---

## v0.0.3 ADDENDUM — Package Supply Chain IOC Type

### New IOC Type: `package`

The classifier must now detect and handle an **eighth** IOC type:
- `package` — `ecosystem:name` format (e.g., `npm:postmark-mcp`, `pypi:requessts`)

Supported ecosystems: npm, PyPI, crates.io, Go, Maven, NuGet, RubyGems, Packagist

The regex must check for `package` **before** CVE (both use `:` character).

### New Data Sources (No API Keys Required)

**OSV.dev** — POST `https://api.osv.dev/v1/query`
- Checks for known malicious packages (MAL- advisories) and vulnerabilities
- Body: `{"package": {"name": "<n>", "ecosystem": "<ecosystem>"}}`

**Package Registry Metadata** — npm: `https://registry.npmjs.org/{pkg}`, PyPI: `https://pypi.org/pypi/{pkg}/json`
- Extracts creation date, maintainer count, install scripts, source repo presence

### New Weight Set

```python
PACKAGE_WEIGHTS = {
    "osv":      0.60,
    "registry": 0.40,
}
```

### Scoring: OSV Normaliser

```
MAL- advisory present           → 1.00 (instant CRITICAL)
Advisory with CRITICAL severity  → 0.90
Advisory with HIGH severity      → 0.70
Advisory present (lower/unknown) → 0.50
No advisories                    → 0.00
```

### Scoring: Registry Normaliser

```
Has install scripts (npm)        → +0.40
Package age < 7 days             → +0.30
Package age < 30 days            → +0.15
Single maintainer                → +0.10
No source repository             → +0.10
```

### Enrichment Node Routing

Package IOCs skip VirusTotal, AbuseIPDB, OTX, urlscan, and NVD. Only OSV.dev and Registry are queried.

### New Files

```
agent/tools/osv.py
agent/tools/registry.py
agent/integrations/osv.py
agent/integrations/registry.py
```
