# agent/credentials.py
# ─────────────────────────────────────────────────────────────────────────────
# Credential management: .env → os.environ → getpass() interactive prompt.
# No key ever touches source code, stdout, logs, or notebook cell output.
# ─────────────────────────────────────────────────────────────────────────────

import os
from pathlib import Path
from getpass import getpass
from dotenv import load_dotenv


REQUIRED_KEYS = [
    "OPENAI_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "OTX_API_KEY",
    "URLSCAN_API_KEY",
    "ARIZE_API_KEY",
    "ARIZE_SPACE_ID",
]


def resolve_credentials() -> None:
    """
    Resolve all required API keys using a three-step chain:

    1. Load .env file if present (override=False so existing env vars win).
    2. Check os.environ for each required key.
    3. Interactive getpass() prompt for any still-missing keys.

    Raises EnvironmentError if any key is still missing after all three steps.
    """
    # Step 1: Try .env file
    env_path = Path(".env")
    if env_path.exists():
        load_dotenv(dotenv_path=str(env_path), override=False)

    # Step 2: Identify missing keys (not yet in os.environ)
    missing = [k for k in REQUIRED_KEYS if not os.getenv(k)]

    # Step 3: Interactive prompt for missing keys only
    if missing:
        print("\nSome API keys are missing. Enter them below (input is masked):\n")
        for key in missing:
            value = getpass(f"  {key}: ")
            if value.strip():
                os.environ[key] = value.strip()

    # Final validation — raise if still missing
    still_missing = [k for k in REQUIRED_KEYS if not os.getenv(k)]
    if still_missing:
        raise EnvironmentError(
            f"Required API keys not provided: {still_missing}\n"
            "Please set them in a .env file or as environment variables."
        )
