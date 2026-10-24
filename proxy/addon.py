"""
EtherHawk MITM addon
====================================================================
Runs inside mitmweb. Observes EVERY HTTP/HTTPS/WebSocket flow the
investigated target makes and appends a structured JSON line per flow
to MITM_FLOWS_PATH. The API reads this file to (a) drive the live MITM
tab and (b) snapshot per-case network evidence.

Each flow is classified deterministically. The decisive EtherHiding
signal is a blockchain JSON-RPC call (eth_call / eth_getStorageAt / ...)
observed leaving a browser page. We do NOT guess — we record facts.

This addon never blocks or modifies traffic. Observation only.
"""

import ipaddress
import json
import os
import re
import socket
import threading
import time
from datetime import datetime, timezone

from mitmproxy import http, ctx

FLOWS_PATH = os.getenv("MITM_FLOWS_PATH", "/workspace/_mitm/flows.jsonl")
ALLOW_PRIVATE = os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() in ("1", "true", "yes", "on")

# Resolution cache so the SSRF check doesn't re-resolve every request.
_resolve_cache: dict[str, bool] = {}


def _host_is_internal(host: str) -> bool:
    """True if host resolves to a private/loopback/link-local/reserved address.
    Blocks the classic container-SSRF + cloud-metadata (169.254.169.254) reach."""
    if not host:
        return True
    if host in _resolve_cache:
        return _resolve_cache[host]
    blocked = False
    try:
        # Literal IP?
        try:
            addr = ipaddress.ip_address(host)
            ips = [str(addr)]
        except ValueError:
            ips = [i[4][0] for i in socket.getaddrinfo(host, None)]
        for ip in ips:
            a = ipaddress.ip_address(ip)
            if (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                    or a.is_reserved or a.is_unspecified):
                blocked = True
                break
    except Exception:
        blocked = True  # unresolvable → block
    _resolve_cache[host] = blocked
    return blocked

# Blockchain JSON-RPC methods that, from a browser page, indicate EtherHiding.
BLOCKCHAIN_RPC_METHODS = {
    "eth_call", "eth_getstorageat", "eth_getcode", "eth_getlogs",
    "eth_blocknumber", "eth_chainid", "net_version", "eth_sendrawtransaction",
}

# ClickFix JSONP polling callback name pattern.
JSONP_C2_RE = re.compile(r"callback=handleCmdCheck", re.IGNORECASE)
# EtherHiding payload-delivery path pattern.
JSREPO_RE = re.compile(r"/jsrepo", re.IGNORECASE)
CONTRACT_RE = re.compile(r"0x[a-fA-F0-9]{40}")

# Serialise writes — mitmproxy is single-threaded per flow but be safe.
_write_lock = threading.Lock()

# Cap how much of a body we ever persist inline (RPC bodies are tiny).
_MAX_INLINE_BODY = 8192


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_dir() -> None:
    try:
        os.makedirs(os.path.dirname(FLOWS_PATH), exist_ok=True)
    except Exception:
        pass


def _parse_rpc(body: str | None) -> list[dict]:
    """Return blockchain RPC calls found in a JSON-RPC request body."""
    if not body or "jsonrpc" not in body.lower() and "method" not in body.lower():
        return []
    try:
        data = json.loads(body)
    except Exception:
        return []
    calls = data if isinstance(data, list) else [data]
    out = []
    for c in calls:
        if not isinstance(c, dict):
            continue
        method = str(c.get("method", "")).lower()
        if method in BLOCKCHAIN_RPC_METHODS:
            params = c.get("params", [])
            contract = ""
            selector = ""
            if params and isinstance(params[0], dict):
                contract = str(params[0].get("to", "") or "")
                data_field = str(params[0].get("data", "") or "")
                selector = data_field[:10] if data_field.startswith("0x") else ""
            out.append({"method": method, "contract": contract, "selector": selector})
    return out


def _write(record: dict) -> None:
    _ensure_dir()
    line = json.dumps(record, default=str)
    with _write_lock:
        try:
            with open(FLOWS_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as e:  # never let logging crash the proxy
            ctx.log.warn(f"etherhawk addon write failed: {e}")


class EtherHawkFlowLogger:
    def request(self, flow: http.HTTPFlow) -> None:
        """SSRF guard for ALL egress (browser + API fetches route through here).
        Block requests to internal/reserved hosts and cloud metadata."""
        if ALLOW_PRIVATE:
            return
        try:
            host = flow.request.pretty_host
            if _host_is_internal(host):
                flow.metadata["eh_blocked"] = True
                flow.response = http.Response.make(
                    403, b"EtherHawk: blocked request to internal/reserved address",
                    {"Content-Type": "text/plain"})
                _write({
                    "ts": _now_iso(), "epoch": time.time(), "transport": "http",
                    "method": flow.request.method, "host": host,
                    "url": flow.request.pretty_url, "status": 403,
                    "is_blockchain_rpc": False, "rpc_calls": [],
                    "blocked_ssrf": True,
                })
        except Exception as e:
            ctx.log.warn(f"etherhawk addon request hook error: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            if flow.metadata.get("eh_blocked"):
                return  # already logged by the SSRF guard in request()
            req = flow.request
            resp = flow.response
            req_ct = req.headers.get("content-type", "")
            is_json_rpc_ct = "json" in req_ct.lower()

            body = None
            if req.method == "POST" and (is_json_rpc_ct or (req.content and len(req.content) < 65536)):
                try:
                    body = req.get_text(strict=False)
                except Exception:
                    body = None

            rpc_calls = _parse_rpc(body)

            resp_ct = resp.headers.get("content-type", "") if resp else ""
            resp_len = len(resp.content) if (resp and resp.content) else 0
            uri = req.pretty_url

            record = {
                "ts": _now_iso(),
                "epoch": time.time(),
                "transport": "http",
                "scheme": req.scheme,
                "method": req.method,
                "host": req.pretty_host,
                "path": req.path,
                "url": uri,
                "status": resp.status_code if resp else None,
                "req_content_type": req_ct,
                "resp_content_type": resp_ct,
                "resp_size": resp_len,
                # deterministic classification flags
                "is_blockchain_rpc": bool(rpc_calls),
                "rpc_calls": rpc_calls,
                "is_jsonp_c2": bool(JSONP_C2_RE.search(uri)),
                "is_jsrepo": bool(JSREPO_RE.search(req.path)),
                "looks_like_large_js": (
                    "javascript" in resp_ct.lower() and resp_len > 300_000
                ),
            }
            # Persist tiny RPC bodies inline (evidence); never large bodies.
            if rpc_calls and body and len(body) <= _MAX_INLINE_BODY:
                record["rpc_body"] = body
            _write(record)
        except Exception as e:
            ctx.log.warn(f"etherhawk addon response hook error: {e}")

    def websocket_message(self, flow) -> None:
        """Capture JSON-RPC sent over WebSocket (some providers use WS)."""
        try:
            msgs = flow.websocket.messages if flow.websocket else []
            if not msgs:
                return
            last = msgs[-1]
            if not last.from_client:
                return
            text = last.content.decode("utf-8", "replace") if isinstance(last.content, (bytes, bytearray)) else str(last.content)
            rpc_calls = _parse_rpc(text)
            if not rpc_calls:
                return
            _write({
                "ts": _now_iso(),
                "epoch": time.time(),
                "transport": "websocket",
                "host": flow.request.pretty_host if flow.request else "",
                "url": flow.request.pretty_url if flow.request else "",
                "is_blockchain_rpc": True,
                "rpc_calls": rpc_calls,
                "rpc_body": text[:_MAX_INLINE_BODY],
            })
        except Exception as e:
            ctx.log.warn(f"etherhawk addon ws hook error: {e}")


addons = [EtherHawkFlowLogger()]
