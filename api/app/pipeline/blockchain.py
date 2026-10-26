"""
Blockchain dead-drop analysis. Given the contract + RPC endpoint captured from the
live visit (or from static source), replay the exact eth_call directly, ABI-decode
the returned on-chain payload, base64-decode the loader, and extract the C2 URL array.

This is the VERIFICATION step: a non-empty on-chain payload returned by the exact
contract the page called is definitive confirmation of an EtherHiding dead drop.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import httpx

from app.ssrf import is_safe_url
from app.pipeline.verdict import payload_is_deaddrop

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")

# Common getter selectors seen across EtherHiding variants (fallback only;
# the real selector is almost always captured from the page's own call).
FALLBACK_SELECTORS = ["0x6d4ce63c", "0x2e64cec1", "0x893d20e8", "0xd46300fd"]

# Public RPC endpoints to try when the contract was captured in-page (eval/atob)
# without the network endpoint. BSC testnet is the most common EtherHiding host.
FALLBACK_RPCS = [
    "https://bsc-testnet-rpc.publicnode.com",
    "https://bsc-dataseed.bnbchain.org",
    "https://eth.llamarpc.com",
    "https://base.publicnode.com",
    "https://polygon-rpc.com",
    "https://ethereum-sepolia-rpc.publicnode.com",
]


def abi_decode_string(hex_result: str) -> str:
    h = hex_result[2:] if hex_result.lower().startswith("0x") else hex_result
    if len(h) < 128:
        raise ValueError("result too short for ABI string")
    str_len = int(h[64:128], 16)
    if str_len > 5_000_000:
        raise ValueError("implausible ABI string length")
    data_hex = h[128:128 + str_len * 2]
    return bytes.fromhex(data_hex).decode("utf-8", "replace")


def maybe_b64(s: str) -> str:
    stripped = s.strip().replace("\n", "").replace("\r", "")
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", stripped or ""):
        return s
    try:
        pad = (-len(stripped)) % 4
        return base64.b64decode(stripped + "=" * pad).decode("utf-8", "replace")
    except Exception:
        return s


def extract_c2_urls(js: str) -> list[str]:
    urls: list[str] = []
    m = re.search(r"var\s+n\s*=\s*\[([^\]]+)\]", js)
    if m:
        for b64 in re.findall(r'"([A-Za-z0-9+/=]{10,})"', m.group(1)):
            try:
                pad = (-len(b64)) % 4
                urls.append(base64.b64decode(b64 + "=" * pad).decode("utf-8", "replace"))
            except Exception:
                pass
    urls += re.findall(r"https?://[^\s'\"<>]{10,200}", js)
    # de-dup preserving order
    seen, out = set(), []
    for u in urls:
        u = u.strip().rstrip(".,;)'\"")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


async def _rpc_call(rpc_url: str, contract: str, selector: str) -> dict:
    if not is_safe_url(rpc_url):
        raise ValueError("RPC URL blocked by SSRF guard")
    payload = {"jsonrpc": "2.0", "method": "eth_call",
               "params": [{"to": contract, "data": selector}, "latest"], "id": 1}
    async with httpx.AsyncClient(timeout=20, verify=False) as c:
        r = await c.post(rpc_url, json=payload, headers={"Content-Type": "application/json", "User-Agent": UA})
        return r.json()


async def replay_and_decode(contract: str, rpc_url: str, selector: str,
                            case_path: Path, log) -> dict:
    """Replay eth_call → ABI decode → base64 → extract C2 URLs. Writes blockchain/*."""
    bc = case_path / "blockchain"
    bc.mkdir(parents=True, exist_ok=True)
    result = {"contract": contract, "rpc_url": rpc_url, "selector": selector,
              "payload_js": "", "c2_urls": [], "verified": False, "raw_result": ""}

    selectors = [selector] if selector else []
    selectors += [s for s in FALLBACK_SELECTORS if s != selector]

    # Prefer the captured endpoint; fall back to public RPCs if only the contract
    # is known (e.g. captured in-page via eval/atob with no network endpoint).
    rpc_candidates = [rpc_url] if rpc_url else list(FALLBACK_RPCS)

    found_payload = False
    done = False
    for rpc in rpc_candidates:
        if done:
            break
        for sel in selectors:
            try:
                resp = await _rpc_call(rpc, contract, sel)
            except Exception as e:
                log(f"RPC replay error ({rpc.split('//')[-1][:30]} {sel}): {e}", "warn")
                continue
            hexres = (resp or {}).get("result", "")
            if not hexres or hexres in ("0x", "0x0"):
                continue
            # Got a non-empty return from this (rpc, selector) — this is our contract.
            result["rpc_url"] = rpc
            result["selector"] = sel
            result["raw_result"] = hexres
            found_payload = True
            (bc / "blockchain_rpc_response.json").write_text(json.dumps(resp, indent=2))
            try:
                decoded = abi_decode_string(hexres)
                payload = maybe_b64(decoded)
                result["payload_js"] = payload
                (bc / "blockchain_decoded_payload.js").write_text(payload, errors="replace")
                result["c2_urls"] = extract_c2_urls(payload)
                if result["c2_urls"]:
                    (bc / "c2_urls_extracted.json").write_text(
                        json.dumps({"c2_urls": result["c2_urls"]}, indent=2))
                # VERIFIED only if the decoded payload is an executable loader — NOT
                # merely a URL string (legit dApp getters return URLs). URL-only
                # returns are corroborated later by fetching the C2 chain.
                if payload_is_deaddrop(payload):
                    result["verified"] = True
                    log(f"Blockchain DEAD DROP VERIFIED: loader payload {len(payload)} chars, "
                        f"{len(result['c2_urls'])} C2 URL(s)", "critical")
                else:
                    log(f"Contract returned {len(payload)} chars; not an executable loader. "
                        f"C2 URLs ({len(result['c2_urls'])}) will be corroborated via fetch.", "warn")
            except Exception as e:
                log(f"ABI decode failed ({sel}): {e}", "warn")
            done = True   # contract answered on this endpoint; stop probing others
            break

    if not found_payload:
        log("Blockchain replay returned no active payload (contract dormant or wrong network).", "warn")
    return result
