"""
Configuration = environment defaults overlaid with DB-stored settings (the
dashboard Settings control panel writes to the DB). Secrets are read here but
never returned verbatim by the API (see routers/settings.py masking).
"""

from __future__ import annotations

import os
from pathlib import Path

WORKSPACE = Path(os.getenv("WORKSPACE", "/workspace"))
CASES_DIR = WORKSPACE / "cases"
MITM_DIR = WORKSPACE / "_mitm"
DB_PATH = WORKSPACE / "etherhawk.sqlite3"

# Internal service URLs (compose defaults).
MITM_PROXY = os.getenv("MITM_PROXY", "http://etherhawk-proxy:8095")
MITM_FLOWS_PATH = Path(os.getenv("MITM_FLOWS_PATH", str(MITM_DIR / "flows.jsonl")))
BROWSER_URL = os.getenv("BROWSER_URL", "http://etherhawk-browser:9001")
DEOBFUSCATOR_URL = os.getenv("DEOBFUSCATOR_URL", "http://etherhawk-deobf:3020/deobfuscate")
SANDBOX_URL = os.getenv("SANDBOX_URL", "http://etherhawk-sandbox:3021/run")

# Keys that live in the DB settings table (dashboard-editable).
SETTING_KEYS = {
    "misp_url", "misp_api_key", "misp_verify_tls",
    "dashboard_token", "api_key",
    "upstream_proxy", "allow_private_targets",
    "visit_timeout", "max_attempts", "post_load_dwell",
    "branding",  # JSON blob
}

# Settings that must never be returned in plaintext by the API.
SECRET_KEYS = {"misp_api_key", "dashboard_token", "api_key"}


def env_default(key: str) -> str:
    return {
        "misp_url": os.getenv("MISP_URL", ""),
        "misp_api_key": os.getenv("MISP_API_KEY", ""),
        "misp_verify_tls": os.getenv("MISP_VERIFY_TLS", "true"),
        "dashboard_token": os.getenv("ETHERHAWK_DASHBOARD_TOKEN", ""),
        "api_key": "",
        "upstream_proxy": os.getenv("UPSTREAM_PROXY", ""),
        "allow_private_targets": os.getenv("ALLOW_PRIVATE_TARGETS", "false"),
        "visit_timeout": os.getenv("VISIT_TIMEOUT", "40"),
        "max_attempts": os.getenv("MAX_ATTEMPTS", "2"),
        "post_load_dwell": os.getenv("POST_LOAD_DWELL", "6"),
        "branding": "",
    }.get(key, "")


DEFAULT_BRANDING = {
    "platformName": "ETHERHAWK",
    "heroTitle": "ETHERHIDING INVESTIGATOR",
    "tagline": "VISIT. TRIGGER. CAPTURE. CONFIRM.",
    "statusLabel": "LIVE",
    "footerText": "CyberHawk Threat Intel",
    "analystName": "",
    "organisation": "",
    "tlpDefault": "TLP:AMBER",
}
