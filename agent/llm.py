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
    # Why gpt-4o-mini: Fast, cheap, deterministic — ideal for structured output.
    # Note: Regex pre-classifier handles most cases; LLM is the fallback.
    "classifier": {
        "model":            "gpt-4o-mini",
        "temperature":      0.0,
    },

    # ── Threat Report Synthesis ───────────────────────────────────────────────
    # Task: Synthesise raw multi-source intel into a structured threat report.
    # Why gpt-4o: Quality matters for reconciling conflicting signals.
    "report": {
        "model":            "gpt-4o",
        "temperature":      0.3,
    },
}


def get_llm(task: str) -> ChatOpenAI:
    """
    Return a ChatOpenAI instance configured for the named task.

    Usage:
        classifier_llm = get_llm("classifier")   # gpt-4o-mini
        report_llm     = get_llm("report")        # gpt-4o

    To swap a model for any task, edit MODEL_CONFIG above — not this function.
    """
    if task not in MODEL_CONFIG:
        raise ValueError(f"Unknown task '{task}'. Valid tasks: {list(MODEL_CONFIG)}")
    cfg = MODEL_CONFIG[task]
    kwargs: dict = {}
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
  package     → Package identifier in ecosystem:name format (e.g., npm:lodash, pypi:requests)
  unknown     → Cannot be classified

Respond ONLY with a JSON object — no preamble, no markdown:
{ "type": "<type>", "clean": "<normalised_value>", "confidence": 0.0 }

Where "clean" is the normalised form: lowercase domains/URLs,
uppercase hex hashes, uppercase CVE identifiers,
lowercase ecosystem prefix for packages.
If confidence < 0.6, set type to "unknown".
"""
