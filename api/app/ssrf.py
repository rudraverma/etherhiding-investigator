"""
SSRF guard. The appliance fetches analyst-submitted URLs, so a submission must not
be usable to reach internal infrastructure or cloud metadata. We allow only http/https,
resolve the host, and reject any resolved address in a private/loopback/link-local/
reserved range unless the operator explicitly enabled internal testing.

NOTE (documented limitation): DNS rebinding between this check and the browser's own
resolution is not fully preventable here. The browser runs in a dedicated container
that should be network-segmented from internal LAN/host management at deploy time.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from app import db

ALLOWED_SCHEMES = {"http", "https"}


class SSRFError(ValueError):
    pass


def _allow_private() -> bool:
    return str(db.get_setting("allow_private_targets")).lower() in ("1", "true", "yes", "on")


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable → block
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local or
        addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def validate_target(raw: str) -> dict:
    """Return {url, domain, ips} for a safe target, else raise SSRFError."""
    raw = (raw or "").strip()
    if not raw:
        raise SSRFError("empty URL")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urlparse(raw)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError(f"scheme not allowed: {parsed.scheme}")
    host = parsed.hostname
    if not host:
        raise SSRFError("no host in URL")

    if _allow_private():
        # Operator opted into internal testing — skip range checks.
        return {"url": raw, "domain": host, "ips": []}

    # Resolve ALL addresses and reject if any is internal.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise SSRFError(f"DNS resolution failed: {e}")

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise SSRFError("host did not resolve")
    for ip in ips:
        if _is_blocked_ip(ip):
            raise SSRFError(f"target resolves to a blocked/internal address: {ip}")

    return {"url": raw, "domain": host, "ips": ips}


def is_safe_url(url: str) -> bool:
    """Non-raising guard for secondary fetches (scripts, RPC, C2). Blocks
    internal/reserved destinations unless the operator opted into private testing."""
    try:
        validate_target(url)
        return True
    except SSRFError:
        return False
