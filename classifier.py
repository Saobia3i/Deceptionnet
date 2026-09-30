"""
classifier.py — Rule-based attack classification for DeceptionNet.

Kept deliberately simple and explainable (no ML) so you can defend every
decision in your demo: "it's flagged brute force because 5+ attempts came
from this IP in under 60 seconds", etc.
"""

import re

from db import recent_attempts_by_ip, distinct_ports_by_ip, is_ip_honeytoken_tagged

# --- Realistic Honeytoken bait keys (Stripe/AWS/Config style) ----------------
# Each key represents a unique leak location to pinpoint how the attacker discovered it.
HONEYTOKENS = {
    "dnet_honey_51Nx8fQ2eZvKYlo9A3bC7dEfGhIjKlMnOp": "html_comment_login",
    "dnet_honey_99PqRsTuVwXyZ1234567890AbCdEfGhIj": "robots_txt_disallow",
    "dnet_honey_88AaBbCcDdEeFfGgHhIiJjKkLlMmNnOo": "config_js_source",
    "dnet_honey_77ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLl": "env_file_leak",
}

# --- Signature patterns -----------------------------------------------

SQLI_PATTERNS = [
    r"'\s*or\s*'?1'?\s*=\s*'?1",   # ' OR '1'='1
    r"union\s+select",
    r"--\s",                        # SQL comment
    r";\s*drop\s+table",
    r"'\s*or\s*1\s*=\s*1",
]

XSS_PATTERNS = [
    r"<script.*?>",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript:",
]

BRUTE_FORCE_THRESHOLD = 5      # attempts
BRUTE_FORCE_WINDOW = 60        # seconds
PORT_SCAN_THRESHOLD = 4        # distinct ports
PORT_SCAN_WINDOW = 30          # seconds


def get_honeytoken_location(text):
    """Returns the location tag if a honeytoken key is present in text."""
    if not text:
        return None
    for token_key, location in HONEYTOKENS.items():
        if token_key in text:
            return location
    if "honeytoken" in text.lower():
        return "generic_honeytoken_param"
    return None


def _matches_any(patterns, text):
    if not text:
        return False
    text_lower = text.lower()
    return any(re.search(p, text_lower) for p in patterns)


def classify(service, source_ip, username=None, password=None,
             raw_payload=None, source_port=None):
    """
    Returns one of: 'honeytoken_triggered', 'honeytoken_session', 'sqli', 'xss', 'brute_force', 'port_scan', 'recon'.
    Checked in priority order:
    1. Honeytokens (highest-fidelity deception alert)
    2. Content-based signatures (SQLi / XSS)
    3. Active Honeytoken Tagged Session (subsequent requests from a honeytoken-flagged IP)
    4. Behavioral patterns (brute force, port scan)
    5. Recon fallback
    """
    combined_text = " ".join(filter(None, [username, password, raw_payload]))

    # 1. Honeytoken Key Trigger
    if get_honeytoken_location(combined_text):
        return "honeytoken_triggered"

    # 2. Content-based attack signatures
    if _matches_any(SQLI_PATTERNS, combined_text):
        return "sqli"

    if _matches_any(XSS_PATTERNS, combined_text):
        return "xss"

    # 3. Active Honeytoken Session Tagging (if IP previously triggered a honeytoken)
    if is_ip_honeytoken_tagged(source_ip):
        return "honeytoken_session"

    # 4. Behavioral checks
    if recent_attempts_by_ip(source_ip, service=service, window_seconds=BRUTE_FORCE_WINDOW) >= BRUTE_FORCE_THRESHOLD:
        return "brute_force"

    if distinct_ports_by_ip(source_ip, window_seconds=PORT_SCAN_WINDOW) >= PORT_SCAN_THRESHOLD:
        return "port_scan"

    return "recon"


