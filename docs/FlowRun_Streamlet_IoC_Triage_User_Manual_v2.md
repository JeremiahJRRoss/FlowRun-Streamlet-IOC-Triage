> **🛡️ FLOWRUN STREAMLET: IoC TRIAGE**
> **User Manual & Technical Reference**
> Automated Threat Intelligence Triage for Security Operations


| **Version** 1.0.0 **Status** Initial Release | **Framework** LangChain + LangGraph **Observability** Arize AI |
| --- | --- |


**1. What is the FlowRun Streamlet: IoC Triage?**

The FlowRun Streamlet: IoC Triage is an AI-powered security analysis tool built on LangGraph and LangChain that automatically investigates Indicators of Compromise (IOCs) — the digital fingerprints left behind by malicious actors, malware, and cyberattacks.

When you provide the agent with a suspicious artifact — an IP address, domain name, URL, file hash (MD5, SHA-1, or SHA-256), or CVE identifier — it acts like a virtual Tier 1 SOC analyst. It simultaneously queries multiple threat intelligence sources, correlates the results, assigns a severity verdict, and delivers a structured, human-readable threat report within seconds.


> **Definition: Indicator of Compromise (IOC)**
> An IOC is a piece of forensic data — such as an IP address, domain, file hash, or URL — that may indicate a system has been breached or that an attack is underway. Triaging IOCs is one of the most time-intensive daily tasks for Security Operations Center (SOC) analysts.


Every action the agent takes — each tool call, reasoning step, and decision — is automatically traced and sent to Arize AI for real-time observability, performance monitoring, and post-incident review.

**2. The Problem the Agent Solves**

**2.1 The SOC Analyst Bottleneck**

Modern Security Operations Centers are overwhelmed. A mid-sized enterprise can generate tens of thousands of security alerts per day, and a meaningful portion of those involve IOCs that require manual investigation. Analysts must:

- Open a browser and manually check VirusTotal, AbuseIPDB, AlienVault OTX, and other platforms one at a time

- Correlate findings from 3-6 different sources, each with different scoring systems and data formats

- Make a judgment call on severity — often under time pressure

- Write up findings in a ticket or report

- Escalate or close the alert accordingly

Each manual triage cycle takes an experienced analyst 10–25 minutes per IOC. During a high-alert period or active incident, this creates dangerous delays and analyst fatigue.

**2.2 The Observability Gap**

Even organizations that have some automation in place often lack visibility into how their automated tools are making decisions. When an AI-assisted triage gets it wrong — flagging a legitimate IP as malicious, or missing a known threat — there is no audit trail to understand why.


> **The Core Problem in One Sentence**
> Security teams are drowning in IOCs that take too long to investigate manually, and existing automation lacks the transparency needed to trust and improve it.


**3. What the Agent Does to Solve This**

The FlowRun Streamlet: IoC Triage compresses a 10-25 minute manual investigation into a sub-30-second automated pipeline, while providing full observability into every decision made.

**3.1 Automated Multi-Source Intelligence Gathering**

The agent queries all configured threat intelligence APIs in parallel — not sequentially — meaning the total time is bounded by the slowest single API call rather than the sum of all calls.

|                            |                                                                                                                                                                                                                                                                  |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Intelligence Source**    | **What It Provides**                                                                                                                                                                                                                                             |
| **VirusTotal**             | Checks the IOC against 90+ antivirus engines and threat intel feeds. Returns engine votes, malicious/suspicious/clean breakdown, and community threat labels.                                                                                                    |
| **AbuseIPDB**              | Returns an abuse confidence score (0-100%) for IP addresses, the number of abuse reports, and the categories of malicious activity reported by the community.                                                                                                    |
| **AlienVault OTX**         | Returns open-source threat intelligence 'pulses' — curated threat reports from the global security community that have tagged this IOC, providing campaign-level context.                                                                                        |
| **urlscan.io**             | For URLs, performs a live sandboxed browser scan, capturing screenshots, network behavior, and blocklist matches to detect phishing and malware delivery pages.                                                                                                  |
| **NIST NVD**               | For CVE identifiers, retrieves official vulnerability records including CVSS scores, affected products, and remediation guidance.                                                                                                                                |
| **OSV.dev (NEW)**          | For package IOCs (npm, PyPI, crates.io, Go, Maven, etc.), queries Google’s open-source vulnerability database for known malicious packages (MAL advisories) and security vulnerabilities. No API key required.                                                   |
| **Package Registry (NEW)** | Fetches package metadata from npm and PyPI registries: creation date, maintainer count, install scripts (npm postinstall hooks), and source repository presence. Flags supply chain red flags like brand-new packages with install scripts. No API key required. |

**3.2 Intelligent Correlation & Severity Scoring**

Raw API data is rarely consistent. One source may rate an IP as high-risk while another has no data on it. The agent's correlation node reconciles conflicting signals using weighted scoring logic, taking into account:

- The number of malicious engine detections relative to total engines queried

- The AbuseIPDB confidence score and recency of reports

- Whether the IOC appears in any active threat intelligence pulses

- The behavioral characteristics of the URL (if applicable)

For CVE identifier IOCs, the agent uses a separate weight set: OTX (40%) and NIST NVD (60%). For package IOCs (e.g., npm:postmark-mcp), the agent uses OSV.dev (60%) and package registry metadata (40%). No API keys are required for package analysis.

The agent then assigns one of five severity verdicts:

|                 |                                                                                                               |
|-----------------|---------------------------------------------------------------------------------------------------------------|
| **Verdict**     | **Meaning & Recommended Action**                                                                              |
| **🟢 CLEAN**    | No credible threat signals found across sources. Safe to proceed with normal monitoring.                      |
| **🟡 LOW**      | Minor or outdated signals present. Monitor but no immediate action required.                                  |
| **🟠 MEDIUM**   | Credible threat signals from one or more sources. Investigate and consider blocking.                          |
| **🔴 HIGH**     | Strong multi-source signals. Block the IOC and open an incident ticket immediately.                           |
| **🚨 CRITICAL** | Confirmed malicious with high confidence. Block, escalate to IR team, and trigger incident response playbook. |

**3.3 Structured Threat Report Generation**

After correlation, the agent's reporting node produces a structured threat report that includes the IOC type and value, all raw intelligence findings, the correlation summary, the severity verdict with justification, and recommended next steps.

**3.4 Full Observability via Arize AI**

Every step of the agent's execution is instrumented with OpenInference-compatible traces and sent to Arize. Security teams can see exactly which tools were called, what data was returned, how the severity was calculated, and how long each step took — creating a full audit trail for every triage decision.

**4. How to Use the Agent**

**4.1 Starting the Agent**

Ensure all environment variables are configured (see Section 7), then launch the agent from the command line:


> **Command Line Launch**
> python flowrun_agent.py The agent will start an interactive session and prompt you for input.


**4.2 Submitting an IOC**

Once the agent is running, you will see an input prompt. Simply type or paste your IOC and press Enter. The agent automatically detects the IOC type — you do not need to specify it.

|                                   |                                                                                                                   |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------------|
| **IOC Type**                      | **Example Input**                                                                                                 |
| **IP Address**                    | 8.8.8.8 203.0.113.42                                                                                              |
| **Domain**                        | malicious-example.com suspicious-site.net                                                                         |
| **File Hash (MD5/SHA-1/SHA-256)** | 44d88612fea8a8f36de82e1278abb02f (MD5) da39a3ee5e6b4b0d3255bfef95601890afd80709 (SHA-1) abc123...def456 (SHA-256) |
| **URL**                           | https://phishing-attempt.xyz/login                                                                                |
| **CVE Identifier**                | CVE-2024-12345 CVE-2021-44228                                                                                     |
| **Package (NEW in v0.0.3)**       | npm:postmark-mcp pypi:requessts crates:evil-crate                                                                 |

**4.3 Understanding the Output**

After submitting an IOC, the agent will display a real-time status indicator as it queries each source, followed by the full threat report. Each report begins with a one-sentence TL;DR summary of the key finding, followed by the IOC details, intelligence findings (including per-engine AV detection names for file hashes, OTX threat actor and campaign tags, and CVSS severity ratings for CVEs), a conflicting signal warning if sources disagree, the correlation summary, the severity verdict with justification, and recommended next steps.

1.  IOC Summary — The artifact you submitted and its detected type

2.  Intelligence Findings — Raw results from each API source

3.  Correlation Summary — How signals were reconciled across sources

4.  Severity Verdict — CLEAN / LOW / MEDIUM / HIGH / CRITICAL with justification

5.  Recommended Actions — Specific steps the analyst should consider taking

**4.4 Reviewing Traces in Arize**

After each triage run, a trace is automatically sent to your Arize dashboard. To review it:

6.  Log into your Arize account at app.arize.com

7.  Navigate to your configured Space and find the Sentinel project

8.  Click on the latest trace to see the full execution tree

9.  Expand individual nodes to inspect tool inputs, outputs, latency, and token usage

10. Use the Arize evaluation tools to score the quality of the triage decision

**5. How the Agent Works**

**5.1 LangGraph State Machine**

The agent is built as a LangGraph StateGraph — a directed graph where each node performs a specific function and edges define the flow of execution. This design makes the agent's logic transparent, testable, and easily extensible.

The agent maintains a shared state object that every node reads from and writes to. This state includes the raw IOC input, the detected IOC type, raw API results from each source, the correlation score, and the final report.

**5.2 Node-by-Node Execution Flow**

|                         |                                                                                                                                                                                                                                         |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Node**                | **Function**                                                                                                                                                                                                                            |
| **1. INPUT NODE**       | Receives the raw IOC string from the user and passes it to the classifier.                                                                                                                                                              |
| **2. CLASSIFIER NODE**  | Uses a lightweight LLM call to detect the IOC type (IP, domain, hash, URL, or CVE) and validate the format. Routes to the appropriate enrichment path.                                                                                  |
| **3. ENRICHMENT NODE**  | Executes parallel async tool calls to VirusTotal, AbuseIPDB (IP only), OTX, urlscan.io (URL and domain), NIST NVD (CVE only), OSV.dev (package only), and package registry (package only). All applicable sources queried concurrently. |
| **4. CORRELATION NODE** | Aggregates all raw intelligence data. Applies weighted scoring logic to reconcile conflicting signals and compute a composite threat score.                                                                                             |
| **5. SEVERITY NODE**    | Maps the composite score to a severity band (CLEAN / LOW / MEDIUM / HIGH / CRITICAL) and generates a justification string.                                                                                                              |
| **6. REPORT NODE**      | Formats the full structured threat report for terminal output and prepares the Arize trace payload.                                                                                                                                     |
| **7. ESCALATION GATE**  | Conditional edge: if severity is CRITICAL, routes to a human-in-the-loop escalation prompt before completing. Otherwise, outputs the final report.                                                                                      |

**5.3 Parallel Tool Execution**

The enrichment node uses Python's asyncio.gather() to execute all applicable threat intelligence tool calls as concurrent coroutines within a single node. This means a triage that would take 60+ seconds sequentially (4+ API calls × 15 seconds each) completes in roughly 15 seconds — the time of the single slowest call.

**5.4 Arize Tracing Integration**

The agent uses the OpenInference instrumentation library, which automatically wraps LangChain and LangGraph operations with trace spans. Each span captures the input, output, latency, and metadata for that operation. Spans are organized into a trace tree that mirrors the LangGraph execution graph, making it easy to visualize in Arize.

**6. Architecture**

**6.1 System Architecture Overview**

The FlowRun Streamlet: IoC Triage follows a modular, layered architecture designed for security operations environments. The system has five logical layers:

|                         |                                                                                                                                                                |
|-------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Layer**               | **Components**                                                                                                                                                 |
| **Interaction Layer**   | Command-line interface (CLI) for analyst input. Future versions may include a REST API or Slack integration.                                                   |
| **Agent Orchestration** | LangGraph StateGraph managing node execution, conditional routing, and shared state across the full triage pipeline.                                           |
| **LLM & Tool Layer**    | LangChain tool wrappers for each API. OpenAI GPT-5.2 Instant (classification) and GPT-5.2 Thinking (report synthesis) — per-task model config in agent/llm.py. |
| **Intelligence Layer**  | VirusTotal API, AbuseIPDB API, AlienVault OTX API, urlscan.io API, NIST NVD API, OSV.dev API, npm/PyPI registries.                                             |
| **Observability Layer** | Arize AI platform receiving OpenInference-formatted traces for monitoring, evaluation, and debugging.                                                          |

**6.2 Data Flow**

The data flow through the system follows a clean, unidirectional path:

11. Analyst enters IOC at the CLI

12. Input node receives the string and initializes the agent state

13. Classifier node determines IOC type via GPT-5.2 Instant (low reasoning effort)

14. Enrichment node fans out to all relevant threat intel APIs in parallel

15. API responses are collected and stored in the agent state

16. Correlation node processes all raw data and computes a composite threat score

17. Severity node assigns the verdict and writes justification to state

18. Report node formats the final output and renders it in the terminal

19. Arize exporter sends the complete trace to the Arize platform

**6.3 Technology Stack Summary**

|                             |                                                                                            |
|-----------------------------|--------------------------------------------------------------------------------------------|
| **Component**               | **Technology & Notes**                                                                     |
| **Orchestration Framework** | LangGraph 0.2+ — StateGraph with typed state, parallel fan-out, conditional edges          |
| **LLM Framework**           | LangChain 0.3+ — tool definitions, LLM wrappers, output parsers                            |
| **Language Model**          | OpenAI GPT-5.2 — Instant variant for classification, Thinking variant for report synthesis |
| **Threat Intel APIs**       | VirusTotal, AbuseIPDB, AlienVault OTX, urlscan.io, NIST NVD                                |
| **Observability**           | Arize AI — trace collection, visualization, evaluation, and alerting                       |
| **Instrumentation**         | OpenInference (arize-otel) — automatic LangChain/LangGraph tracing                         |
| **Language / Runtime**      | Python 3.11+ with asyncio for parallel API calls                                           |
| **Package Management**      | pip / requirements.txt                                                                     |

**7. Minimum Requirements for Use**

**7.1 System Requirements**

|                      |                                                                                                                                         |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| **Requirement**      | **Specification**                                                                                                                       |
| **Operating System** | macOS 12+, Ubuntu 20.04+, or Windows 10+ (via WSL2)                                                                                     |
| **Python Version**   | Python 3.11 or higher                                                                                                                   |
| **RAM**              | Minimum 4 GB (8 GB recommended)                                                                                                         |
| **Network**          | Outbound HTTPS access to api.openai.com, virustotal.com, abuseipdb.com, otx.alienvault.com, urlscan.io, nvd.nist.gov, and app.arize.com |
| **Disk Space**       | ~500 MB for Python environment and dependencies                                                                                         |

**7.2 Required API Keys & Accounts**

All of the following must be obtained and set as environment variables before running the agent:

|                          |                                                                                                             |
|--------------------------|-------------------------------------------------------------------------------------------------------------|
| **Environment Variable** | **Source & Notes**                                                                                          |
| **OPENAI_API_KEY**       | OpenAI account with GPT-5.2 API access. Paid plan required (gpt-5.2-chat-latest and gpt-5.2 model strings). |
| **VIRUSTOTAL_API_KEY**   | Free VirusTotal community account. Limit: 4 requests/min, 500/day on free tier.                             |
| **ABUSEIPDB_API_KEY**    | Free AbuseIPDB account. Limit: 1,000 requests/day on free tier.                                             |
| **OTX_API_KEY**          | Free AlienVault OTX account. Generous rate limits on free tier.                                             |
| **URLSCAN_API_KEY**      | Free urlscan.io account. Limit: 100 public scans/day on free tier. Required for URL analysis.               |
| **ARIZE_API_KEY**        | Arize AI account (free tier available). Found in Arize dashboard under Settings → API Keys.                 |
| **ARIZE_SPACE_ID**       | Your Arize Space identifier. Found alongside your API key in the Arize dashboard.                           |

**7.3 Python Dependencies**

The following Python packages must be installed via pip before running the agent:


> **Installation Command**
> pip install langchain langgraph langchain-openai openai arize-otel openinference-instrumentation-langchain requests python-dotenv


**7.4 Knowledge Prerequisites**

While no programming skills are required to use the agent in interactive mode, the following background knowledge is helpful for understanding its outputs:

- Basic understanding of network security concepts (IP addresses, domains, URLs)

- Familiarity with what threat intelligence scores mean (e.g., VirusTotal detection ratios)

- Understanding of your organization's incident response escalation process

- Access to your organization's SIEM or ticketing system to act on the agent's recommendations


> **Important Note on Free Tier Rate Limits**
> When using free API tiers, be mindful of daily rate limits. VirusTotal's free tier allows 500 lookups/day and AbuseIPDB allows 1,000/day. For high-volume production use, consider upgrading to paid tiers or implementing a request queue with rate limiting.


**8. How to Set Up Your API Keys**

The FlowRun Streamlet: IoC Triage never hardcodes API keys in source code. Keys are handled in one of two ways depending on how you run the agent: a secure interactive prompt at startup, or a .env file for repeated use. Both approaches are described below.

**8.1 Option A — Interactive Prompt at Startup (Recommended for First Run)**

When you launch the agent without a .env file present, it will automatically prompt you to enter each API key one at a time. Keys are masked as you type (like a password field) and stored only in memory for the duration of that session — they are never written to disk.


> **What You Will See at First Launch**
> Welcome to FlowRun Streamlet: IoC Triage No .env file detected. Please enter your API keys below. Keys are masked and stored in memory only for this session. OpenAI API Key: •••••••••••••••••••••••• VirusTotal API Key: •••••••••••••••••••••••• AbuseIPDB API Key: •••••••••••••••••••••••• AlienVault OTX Key: •••••••••••••••••••••••• urlscan.io API Key: •••••••••••••••••••••••• Arize API Key: •••••••••••••••••••••••• Arize Space ID: •••••••••••••••••••••••• All keys received. Starting agent...


After entering your keys, the agent starts immediately. You will need to re-enter them the next time you launch the agent unless you save a .env file (see Option B).

**8.2 Option B — .env File for Repeated Use (Recommended for Daily Use)**

For convenience, you can store your keys in a .env file in the project root directory. The agent automatically loads this file on startup and skips the interactive prompt. This file must never be committed to version control.


> **Step 1 — Create your .env file**
> In the root folder of the project, create a file named exactly: .env On macOS/Linux: touch .env On Windows: New-Item .env -ItemType File


> **Step 2 — Add your keys to the file (copy and paste this template)**
> OPENAI_API_KEY=paste_your_openai_key_here VIRUSTOTAL_API_KEY=paste_your_virustotal_key_here ABUSEIPDB_API_KEY=paste_your_abuseipdb_key_here OTX_API_KEY=paste_your_otx_key_here URLSCAN_API_KEY=paste_your_urlscan_key_here ARIZE_API_KEY=paste_your_arize_key_here ARIZE_SPACE_ID=paste_your_arize_space_id_here


> **Step 3 — Protect the file from version control**
> If using Git, add .env to your .gitignore file to prevent accidentally uploading your keys: echo ".env" >> .gitignore


> **Security Warning**
> Never share your .env file, paste its contents into a chat, email, or ticket, or commit it to any Git repository — public or private. Treat each key like a password. If a key is accidentally exposed, revoke and regenerate it immediately in the relevant service's dashboard.


**8.3 Key Summary Table**

|                          |                                     |
|--------------------------|-------------------------------------|
| **Environment Variable** | **Where to Find It**                |
| **OPENAI_API_KEY**       | platform.openai.com → API Keys      |
| **VIRUSTOTAL_API_KEY**   | virustotal.com → Profile → API Key  |
| **ABUSEIPDB_API_KEY**    | abuseipdb.com → Account → API       |
| **OTX_API_KEY**          | otx.alienvault.com → Settings       |
| **URLSCAN_API_KEY**      | urlscan.io → Settings → API Keys    |
| **ARIZE_API_KEY**        | app.arize.com → Settings → API Keys |
| **ARIZE_SPACE_ID**       | app.arize.com → Settings → API Keys |

**9. Using the Jupyter Notebook Version**

The FlowRun Streamlet: IoC Triage ships with a Jupyter Notebook version that is ideal for learning, experimentation, demos, and step-by-step walkthroughs. The notebook mirrors the full agent but makes each step visible and individually executable.

**9.1 Prerequisites**

Before opening the notebook, ensure the following are installed in your Python environment:


> **Install Jupyter and all dependencies**
> pip install notebook ipykernel langchain langgraph langchain-openai openai arize-otel openinference-instrumentation-langchain requests python-dotenv ipywidgets


> **Important: Register Your Virtual Environment as a Jupyter Kernel**
> If you are using a virtual environment (venv or conda), Jupyter will not automatically see the packages installed in it. You must register the venv as a Jupyter kernel. With your virtual environment activated, run:
> pip install ipykernel
> python -m ipykernel install --user --name=flowrun --display-name=“FlowRun (venv)”
> Then, after opening the notebook, go to Kernel → Change kernel and select “FlowRun (venv)” before running any cells.


**9.2 Launching the Notebook**

20. Open a terminal and navigate to the project folder: cd flowrun-streamlet-ioc-triage

21. Launch Jupyter: jupyter notebook

22. Your browser will open automatically. Click on flowrun_agent.ipynb to open it.

23. **If you are using a virtual environment:** Go to Kernel → Change kernel and select “FlowRun (venv)” (see Section 9.1 for setup). This ensures Jupyter uses the correct Python environment with all dependencies installed.

24. You are now in the notebook environment and ready to run cells.

**9.3 How API Keys Work in the Notebook**

The notebook uses the same two options as the CLI version, but Cell 2 is dedicated to key setup. You choose which approach to use by running that cell.


> **Option A — Secure Interactive Input (recommended for notebooks)**
> Cell 2 uses Python's getpass library so keys are never visible on screen or saved in the notebook output. Run the cell and type each key when prompted — they will appear as blank fields: from getpass import getpass import os os.environ['OPENAI_API_KEY'] = getpass('OpenAI API Key: ') os.environ['VIRUSTOTAL_API_KEY'] = getpass('VirusTotal API Key: ') os.environ['ABUSEIPDB_API_KEY'] = getpass('AbuseIPDB API Key: ') os.environ['OTX_API_KEY'] = getpass('OTX API Key: ') os.environ['URLSCAN_API_KEY'] = getpass('urlscan.io API Key: ') os.environ['ARIZE_API_KEY'] = getpass('Arize API Key: ') os.environ['ARIZE_SPACE_ID'] = getpass('Arize Space ID: ')


> **Option B — Load from .env File**
> If you have already created a .env file (see Section 8.2), you can load it in Cell 2 instead: from dotenv import load_dotenv load_dotenv() # Reads .env file from the current directory print('Keys loaded from .env file.')


> **Critical: Never paste keys directly into notebook cells**
> Jupyter notebooks save cell outputs to disk. If you type a key directly into a cell (e.g., OPENAI_API_KEY = 'sk-abc123...'), it will be saved in the .ipynb file in plain text and will be visible to anyone who opens the file. Always use getpass() or load_dotenv() instead.


**9.4 Notebook Cell Structure**

The notebook is organized into clearly labeled cells that you run in order from top to bottom:

|                                  |                                                                                                     |
|----------------------------------|-----------------------------------------------------------------------------------------------------|
| **Cell**                         | **Purpose**                                                                                         |
| **Cell 1 — Install & Import**    | Installs packages (if needed) and imports all required libraries.                                   |
| **Cell 2 — API Key Setup**       | Loads keys via getpass() prompt or from .env file. Run this before any other cell.                  |
| **Cell 3 — Arize Tracing Setup** | Configures the OpenInference tracer and connects to your Arize Space.                               |
| **Cell 4 — Tool Definitions**    | Defines the LangChain tool wrappers for each threat intelligence API.                               |
| **Cell 5 — LangGraph Agent**     | Defines the StateGraph, all nodes, edges, and the conditional escalation gate.                      |
| **Cell 6 — Run the Agent**       | Contains the interactive input widget. Enter an IOC here and run the cell to trigger a full triage. |
| **Cell 7 — View Results**        | Renders the structured threat report in a formatted display within the notebook.                    |
| **Cell 8 — Arize Link**          | Prints a direct link to the trace in your Arize dashboard for review.                               |

**9.5 Running a Triage in the Notebook**

25. Run cells 1 through 5 in order to set up the environment (you only need to do this once per session)

26. In Cell 6, locate the IOC input field — a text box will appear below the cell

27. Type or paste your IOC (IP, domain, hash, or URL) into the text box

28. Click the Analyze button or press Shift+Enter to submit

29. Watch the status indicators update in real-time as each tool completes

30. Scroll to Cell 7 to see the full formatted threat report

31. Click the Arize link in Cell 8 to review the trace in the Arize dashboard

**9.6 Resetting Between Runs**

To triage a new IOC without restarting the kernel, simply return to Cell 6, clear the input field, enter the new IOC, and run the cell again. You do not need to re-run cells 1-5 unless you have restarted the kernel or changed configuration.


> **Tip — Kernel Restart**
> If the agent behaves unexpectedly or a cell hangs, use Kernel → Restart & Clear Output from the Jupyter menu, then re-run all cells from Cell 1. You will need to re-enter your API keys in Cell 2. If you are using a virtual environment, verify the correct kernel (“FlowRun (venv)”) is still selected after restarting.


FlowRun Streamlet: IoC Triage • v1.0 • Built with LangGraph + LangChain + Arize AI
