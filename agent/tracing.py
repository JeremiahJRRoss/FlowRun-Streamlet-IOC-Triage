# agent/tracing.py
# ─────────────────────────────────────────────────────────────────────────────
# Arize AI / OpenInference tracing setup.
# Auto-instruments all LangChain and LangGraph operations.
# Called once at agent startup — before graph.compile() is invoked.
# ─────────────────────────────────────────────────────────────────────────────

import os
import sys


def init_tracing(project_name: str = "flowrun-streamlet-ioc-triage"):
    """
    Initialise the Arize OpenInference tracer.

    Returns the TracerProvider on success, or None if Arize setup fails
    (non-blocking — tracing failure must never prevent triage completion).
    """
    try:
        from arize.otel import register
        from openinference.instrumentation.langchain import LangChainInstrumentor

        tracer_provider = register(
            space_id=os.getenv("ARIZE_SPACE_ID"),
            api_key=os.getenv("ARIZE_API_KEY"),
            project_name=project_name,
        )
        LangChainInstrumentor().instrument(tracer_provider=tracer_provider)
        return tracer_provider
    except Exception as exc:
        # NFR-07: Arize trace failure must NOT block triage completion
        print(
            f"⚠️  Arize tracing initialisation failed: {exc}",
            file=sys.stderr,
        )
        return None
