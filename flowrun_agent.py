#!/usr/bin/env python3
# flowrun_agent.py
# ─────────────────────────────────────────────────────────────────────────────
# FlowRun Streamlet: IoC Triage — CLI Entry Point
# Interactive terminal loop for triaging Indicators of Compromise.
# ─────────────────────────────────────────────────────────────────────────────

import asyncio
import sys


def main() -> None:
    """CLI interactive loop for IoC triage."""
    print(
        "\n"
        "══════════════════════════════════════════════════════════\n"
        "  🛡️  FlowRun Streamlet: IoC Triage — v0.0.31\n"
        "  Built with LangGraph + LangChain + Arize AI\n"
        "══════════════════════════════════════════════════════════\n"
    )

    # Step 1: Resolve credentials
    from agent.credentials import resolve_credentials
    try:
        resolve_credentials()
        print("✅ All API keys resolved.\n")
    except EnvironmentError as exc:
        print(f"\n❌ {exc}", file=sys.stderr)
        sys.exit(1)

    # Step 2: Initialise Arize tracing
    from agent.tracing import init_tracing
    tracer_provider = init_tracing()
    if tracer_provider:
        print("✅ Arize tracing initialised. Project: flowrun-streamlet-ioc-triage\n")
    else:
        print("⚠️  Arize tracing unavailable — triage will continue without tracing.\n")

    # Step 3: Build LangGraph
    from agent.graph import build_graph
    graph = build_graph()
    print("✅ LangGraph StateGraph compiled.\n")

    # Step 4: Interactive loop
    print("Enter an IOC to triage (IP, domain, URL, file hash, or CVE).")
    print("Type 'quit' or 'exit' to stop.\n")

    while True:
        try:
            ioc = input("IOC ▶ ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\nGoodbye.")
            break

        if not ioc:
            continue
        if ioc.lower() in ("quit", "exit", "q"):
            print("\nGoodbye.")
            break

        print(f"\n🔍 Triaging: {ioc}\n")

        try:
            result = asyncio.run(graph.ainvoke({"ioc_raw": ioc}))
            print(result.get("report_text", "No report generated."))
        except SystemExit as exc:
            # Escalation gate abort
            print(f"\n{exc}\n")
        except Exception as exc:
            print(f"\n❌ Triage failed: {type(exc).__name__}: {exc}\n", file=sys.stderr)

        print()  # Blank line before next prompt


if __name__ == "__main__":
    main()
