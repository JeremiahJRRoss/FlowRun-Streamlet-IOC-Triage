> **🛡️ FLOWRUN STREAMLET: IoC TRIAGE**
> **User Manual & Technical Reference**
> Automated Threat Intelligence Triage for Security Operations

| **Version** v0.0.31 | **Framework** LangChain + LangGraph |
|---|---|
| **Status** Active Release | **Observability** Arize AI |


## 1. What is the FlowRun Streamlet: IoC Triage?

The FlowRun Streamlet: IoC Triage is an AI-powered security analysis tool built on LangGraph and LangChain that automatically investigates Indicators of Compromise (IOCs) — the digital fingerprints left behind by malicious actors, malware, and cyberattacks.

When you provide the agent with a suspicious artifact — an IP address, domain name, URL, file hash (MD5, SHA-1, or SHA-256), CVE identifier, or software package name — it acts like a virtual Tier 1 SOC analyst. It simultaneously queries multiple threat intelligence sources, correlates the results, assigns a severity verdict, and delivers a structured, human-readable threat report within seconds.

> **Definition: Indicator of Compromise (IOC)**
> An IOC is a piece of forensic data — such as an IP address, domain, file hash, URL, or package name — that may indicate a system has been breached or that an attack is underway.

Every action the agent takes is automatically traced and sent to Arize AI for real-time observability, performance monitoring, and post-incident review.


## 2. The Problem the Agent Solves

**2.1 The SOC Analyst Bottleneck**

Modern SOCs are overwhelmed. Analysts must manually check VirusTotal, AbuseIPDB, AlienVault OTX, and other platforms one at a time, correlate findings from 3–6 different sources, make judgment calls under time pressure, write up findings, and escalate or close accordingly. Each manual triage takes 10–25 minutes per IOC.

**2.2 The Supply Chain Gap**

Beyond traditional IOCs, software supply chain attacks are a growing threat. Malicious packages on npm, PyPI, and other registries can compromise development environments before traditional security tools detect them. The agent now scans for these threats across 27 ecosystems.

> **The Core Problem in One Sentence**
> Security teams are drowning in IOCs that take too long to investigate manually, and existing automation lacks the transparency needed to trust and improve it.


## 3. What the Agent Does

The FlowRun Streamlet compresses a 10-25 minute manual investigation into a sub-30-second automated pipeline with full observability.

**3.1 Automated Multi-Source Intelligence Gathering**

The agent queries all applicable APIs in parallel — the total time is bounded by the slowest single call, not the sum of all calls.

| **Intelligence Source**    | **What It Provides**                                                                                           | **IOC Types**      |
|----------------------------|-----------------------------------------------------------------------------------------------------------------|--------------------|
| **VirusTotal**             | Checks against 90+ AV engines. Returns detection counts, community verdict, threat labels.                     | IP, domain, URL, hash |
| **AbuseIPDB**              | Abuse confidence score (0-100%), report count, country, ISP, usage type.                                        | IP only            |
| **AlienVault OTX**         | Threat intelligence pulses — curated threat reports with adversary names, campaign tags.                        | IP, domain, URL, hash, CVE |
| **urlscan.io**             | Live sandboxed browser scan — screenshots, network behavior, blocklist matches.                                | URL, domain        |
| **NIST NVD**               | CVE records: CVSS score, severity rating (CRITICAL/HIGH/MEDIUM/LOW), attack vector, affected products.         | CVE only           |
| **OSV.dev**                | Google's open-source vulnerability database. Detects known malicious packages (MAL advisories) and vulnerabilities across 27 ecosystems. No API key required. | package, package_multi |
| **Package Registry**       | npm/PyPI metadata: creation date, maintainer count, install scripts (postinstall hooks), source repository presence. | package (npm/pypi) |

**3.2 Intelligent Correlation & Severity Scoring**

The agent's correlation node reconciles conflicting signals using weighted scoring logic. Four weight sets handle different IOC categories:

- **Standard IOCs** (IP, domain, URL, hash): VirusTotal 40%, AbuseIPDB 30% (IP only), OTX 20%, urlscan 10% (URL/domain only). When sources are inapplicable, weights redistribute automatically.
- **CVE type**: OTX 40%, NIST NVD 60%. VirusTotal is excluded (it has no CVE endpoint).
- **Prefixed package** (e.g., `npm:postmark-mcp`): OSV.dev 60%, registry metadata 40%.
- **Bare package name** (e.g., `traceroute`): Scans 10 ecosystems simultaneously via OSV.dev. Worst score wins.

The VirusTotal normaliser uses a non-linear detection count curve: even a few malicious detections (e.g., 13 out of 94 engines) correctly produce a meaningful score rather than being buried by a low linear ratio.

The agent then assigns one of five severity verdicts:

| **Verdict**     | **Score Range** | **Meaning & Recommended Action**                                      |
|-----------------|-----------------|------------------------------------------------------------------------|
| **🟢 CLEAN**    | 0.00 – 0.10     | No credible threat signals. Safe to proceed.                          |
| **🟡 LOW**      | 0.11 – 0.30     | Minor or outdated signals. Monitor.                                   |
| **🟠 MEDIUM**   | 0.31 – 0.55     | Credible signals. Investigate and consider blocking.                  |
| **🔴 HIGH**     | 0.56 – 0.75     | Strong multi-source signals. Block and open incident ticket.          |
| **🚨 CRITICAL** | 0.76 – 1.00     | Confirmed malicious. Block, escalate to IR team, trigger IR playbook. |

**3.3 Enhanced Report Features (v0.0.26+)**

Every report includes:

- **TL;DR summary** — One sentence at the top (e.g., "Confirmed malicious file — flagged by 50/100 AV engines, linked to APT28")
- **Timestamp** — When the triage was performed
- **Per-engine AV detection names** (hash IOCs) — Shows specific malware family names, not just counts
- **OTX threat actor & campaign tags** — Names the adversaries and campaigns
- **CVSS severity string** (CVE IOCs) — Shows "CRITICAL", "HIGH", etc. alongside the numeric score, plus the attack vector
- **Conflicting signal warning** — Highlighted callout when sources disagree (e.g., VT clean but OTX shows APT pulses)
- **Data confidence indicator** — Notes when the verdict is based on partial data
- **Per-ecosystem breakdown** (package_multi) — Shows which ecosystems have advisories


## 4. How to Use the Agent

**4.1 Starting the Agent**

Ensure all environment variables are configured (see Section 8), then: `python flowrun_agent.py`

**4.2 Submitting an IOC**

Type or paste your IOC and press Enter. The agent automatically detects the type.

| **IOC Type**                      | **Example Input**                                              |
|-----------------------------------|----------------------------------------------------------------|
| **IP Address**                    | `8.8.8.8`                                                      |
| **Domain**                        | `malware.wicar.org`                                            |
| **URL**                           | `https://phishing-attempt.xyz/login`                           |
| **File Hash (MD5)**               | `44d88612fea8a8f36de82e1278abb02f`                             |
| **File Hash (SHA-256)**           | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| **CVE Identifier**                | `CVE-2021-44228`                                               |
| **Prefixed Package**              | `npm:postmark-mcp`  `pypi:requessts`  `rhel:openssl`          |
| **Bare Package (multi-scan)**     | `traceroute`  `express`  `left-pad`                            |

**Bare package names** (no ecosystem prefix) are automatically scanned across 10 major language ecosystems simultaneously: npm, PyPI, crates.io, Go, Maven, NuGet, RubyGems, Packagist, Pub, and Hex.

**Supported prefixed ecosystems (27):** npm, pypi (alias: pip), crates (alias: cargo), go, maven, nuget, rubygems (alias: gem), packagist (alias: composer), pub, hex, hackage, cran, swifturl, cocoapods, rhel (alias: redhat), debian, ubuntu, alpine, rocky, alma, suse (alias: opensuse), android, linux, bitnami, curl.


## 5. How the Agent Works

**5.1 LangGraph State Machine**

The agent is built as a LangGraph StateGraph with 8 nodes. Each node reads from and writes to a shared state object.

**5.2 Node-by-Node Execution Flow**

| **Node**                | **Function**                                                                                                                 |
|-------------------------|------------------------------------------------------------------------------------------------------------------------------|
| **1. INPUT NODE**       | Receives IOC string, runs regex pre-classification (catches 9 types before LLM is called).                                   |
| **2. CLASSIFIER NODE**  | If regex resolved the type, passes through. Otherwise uses GPT-4o-mini (temperature=0.0) to classify. Routes to enrichment or error. |
| **3. ENRICHMENT NODE**  | Fires all applicable API calls concurrently via asyncio.gather(). For URLs, also queries VT + OTX at the domain level. For bare packages, scans 10 ecosystems. |
| **4. CORRELATION NODE** | Applies weighted scoring: selects weight set by IOC type, normalises each source, detects conflicting signals, computes composite score. |
| **5. SEVERITY NODE**    | Maps composite score to CLEAN/LOW/MEDIUM/HIGH/CRITICAL. Generates justification.                                            |
| **6. REPORT NODE**      | GPT-4o (temperature=0.3) synthesises correlation summary. Formats report with TL;DR, detection names, conflict callouts.     |
| **7. ESCALATION GATE**  | CRITICAL verdicts: CLI → confirmation prompt; Jupyter → auto-proceeds with warning.                                          |
| **8. ERROR NODE**       | Handles unrecognised IOC types with clear error message.                                                                     |


## 6. Architecture

**6.1 System Layers**

| **Layer**               | **Components**                                                                          |
|-------------------------|-----------------------------------------------------------------------------------------|
| **Interaction Layer**   | CLI interactive loop + Jupyter Notebook (ipywidgets)                                    |
| **Agent Orchestration** | LangGraph StateGraph — node execution, conditional routing, shared state                |
| **LLM & Tool Layer**    | LangChain tool wrappers for 9 APIs. OpenAI GPT-4o-mini (classifier) + GPT-4o (report). All model config in agent/llm.py. |
| **Intelligence Layer**  | VirusTotal, AbuseIPDB, OTX, urlscan.io, NIST NVD, OSV.dev, npm Registry, PyPI JSON API |
| **Observability Layer** | Arize AI receiving OpenInference-formatted traces                                       |

**6.2 Technology Stack**

| **Component**               | **Technology**                                                           |
|-----------------------------|--------------------------------------------------------------------------|
| **Orchestration Framework** | LangGraph 0.2+ — StateGraph with conditional edges                      |
| **LLM Framework**           | LangChain 0.3+ — tool definitions, LLM wrappers, output parsers         |
| **Language Models**          | OpenAI GPT-4o-mini (classifier, temp=0.0) + GPT-4o (report, temp=0.3)  |
| **HTTP Client**             | httpx 0.27+ (async) — all API calls                                     |
| **Threat Intel APIs**       | VirusTotal, AbuseIPDB, OTX, urlscan.io, NIST NVD, OSV.dev, npm, PyPI   |
| **Observability**           | Arize AI via arize-otel + openinference-instrumentation-langchain        |
| **Language / Runtime**      | Python 3.11+ with asyncio                                               |


## 7. Minimum Requirements

**7.1 System Requirements**

| **Requirement**      | **Specification**                                                       |
|----------------------|-------------------------------------------------------------------------|
| **Operating System** | macOS 12+, Ubuntu 20.04+, or Windows 10+ (via WSL2)                     |
| **Python Version**   | Python 3.11 or higher                                                   |
| **RAM**              | Minimum 4 GB (8 GB recommended)                                         |
| **Network**          | Outbound HTTPS to api.openai.com, virustotal.com, abuseipdb.com, otx.alienvault.com, urlscan.io, nvd.nist.gov, api.osv.dev, registry.npmjs.org, pypi.org, and app.arize.com |

**7.2 Required API Keys**

| **Environment Variable** | **Source & Notes**                                                          |
|--------------------------|-----------------------------------------------------------------------------|
| **OPENAI_API_KEY**       | OpenAI account with GPT-4o API access.                                      |
| **VIRUSTOTAL_API_KEY**   | Free community account. 4 req/min, 500/day.                                |
| **ABUSEIPDB_API_KEY**    | Free account. 1,000 req/day.                                                |
| **OTX_API_KEY**          | Free AlienVault OTX account.                                                |
| **URLSCAN_API_KEY**      | Free account. 100 public scans/day.                                         |
| **ARIZE_API_KEY**        | Arize AI account (free tier). Settings → API Keys.                          |
| **ARIZE_SPACE_ID**       | Found alongside API key in Arize dashboard.                                 |

Note: OSV.dev, npm registry, and PyPI JSON API require no API keys.

**7.3 Python Dependencies**

```
pip install langgraph langchain langchain-openai openai httpx arize-otel openinference-instrumentation-langchain python-dotenv ipywidgets
```


## 8. How to Set Up Your API Keys

The agent never hardcodes API keys. Keys are handled via secure interactive prompt or .env file.

**8.1 Option A — Interactive Prompt (First Run)**

Launch without a .env file and enter each key when prompted (masked input, stored in memory only).

**8.2 Option B — .env File (Daily Use)**

Create `.env` in the project root:

```
OPENAI_API_KEY=paste_your_key_here
VIRUSTOTAL_API_KEY=paste_your_key_here
ABUSEIPDB_API_KEY=paste_your_key_here
OTX_API_KEY=paste_your_key_here
URLSCAN_API_KEY=paste_your_key_here
ARIZE_API_KEY=paste_your_key_here
ARIZE_SPACE_ID=paste_your_space_id_here
```

No quotes around values. Add `.env` to `.gitignore`. Never share, commit, or paste into chat.


## 9. Using the Jupyter Notebook

**9.1 Prerequisites**

```bash
pip install notebook ipykernel langgraph langchain langchain-openai openai httpx arize-otel openinference-instrumentation-langchain python-dotenv ipywidgets
```

> **Important: Register Virtual Environment as Jupyter Kernel**
> ```bash
> source .venv/bin/activate
> pip install ipykernel
> python -m ipykernel install --user --name=flowrun --display-name="FlowRun (venv)"
> ```
> Then in notebook: Kernel → Change kernel → select "FlowRun (venv)".

**9.2 Notebook Cell Structure**

| **Cell** | **Purpose**                                                                |
|----------|----------------------------------------------------------------------------|
| Cell 1   | Install & Import — all required libraries                                 |
| Cell 2   | API Key Setup — getpass() or load_dotenv()                                |
| Cell 3   | Arize Tracing Init                                                        |
| Cell 4   | Tool Definitions — instantiates all LangChain tools                       |
| Cell 5   | Graph Compilation                                                         |
| Cell 6   | IOC Input Widget — text field + Analyze button. Results render inline.     |
| Cell 7   | Report Display — rendered inline in Cell 6's output area                  |
| Cell 8   | Arize Link                                                                |

> **Tip — Kernel Restart**
> If the agent hangs: Kernel → Restart & Clear Output, verify "FlowRun (venv)" is selected, re-run from Cell 1.

---

*FlowRun Streamlet: IoC Triage — User Manual v3 — Reconciled with codebase v0.0.31*
