"""
Deterministic verdict engine. No scoring model, no AI — fixed rules only.

Design correction (post-review): a browser-context blockchain RPC call alone is NOT
sufficient for the hard verdict, because legitimate web3 / dApp / wallet sites also
issue eth_call, eth_chainId, etc. from the browser. To guarantee zero false positives
the hard COMPROMISED label requires the EtherHiding-specific behaviour that a legitimate
contract never exhibits: an on-chain **dead drop** — the contract returns a payload that
decodes to C2 URLs or an executable loader. A bare RPC capture, or a source-only
injection signature, is reported as SUSPECTED for analyst review — never silently
upgraded.

Only the *decisive* RPC methods (payload-read calls) are treated as EtherHiding-relevant.
Handshake chatter (eth_chainId / net_version / eth_blockNumber) is ignored for the verdict.
"""

from __future__ import annotations

import re

# Verdict labels
COMPROMISED = "COMPROMISED_ETHERHIDING"
SUSPECTED = "SUSPECTED_ETHERHIDING"
CLEAN = "NO_ETHERHIDING_DETECTED"
INCONCLUSIVE = "INCONCLUSIVE"

# Payload-read methods an EtherHiding dead drop uses. Deliberately excludes
# eth_chainId / net_version / eth_blockNumber / eth_getCode (legit-dApp handshake noise).
DECISIVE_RPC_METHODS = {"eth_call", "eth_getstorageat", "eth_getlogs"}

ETH_CALL_RE = re.compile(r"\beth_call\b")
CONTRACT_RE = re.compile(r"0x[a-fA-F0-9]{40}")
SYNC_XHR_RE = re.compile(r"\.open\s*\(\s*['\"]GET['\"].*?(?:!1|false)", re.DOTALL)
SCRIPT_EVAL_RE = re.compile(r"createElement\s*\(\s*['\"]script['\"]", re.IGNORECASE)
RPC_PROVIDER_RE = re.compile(r"publicnode|infura\.io|cloudflare-eth|alchemy|ankr\.com|"
                             r"sepolia|bsc-dataseed|bnbchain|base\.org|llamarpc", re.IGNORECASE)

# Signatures that mark a decoded on-chain payload as an executable loader (dead drop),
# not an ordinary contract return value (balance/state).
LOADER_SIG_RE = re.compile(
    r"createElement\s*\(\s*['\"]script['\"]|XMLHttpRequest|\batob\s*\(|\beval\s*\(|"
    r"new\s+Function|var\s+n\s*=\s*\[|document\.head|appendChild", re.IGNORECASE)


def is_decisive(methods: list[str]) -> bool:
    return any(str(m).lower() in DECISIVE_RPC_METHODS for m in methods)


def payload_is_deaddrop(payload_js: str, c2_urls: list | None = None) -> bool:
    """A contract return value is a dead drop ONLY if it is an executable loader
    (eval / new Function / script-tag injection / the base64 `var n=[...]` array).

    A bare URL string is NOT sufficient: legitimate dApp/NFT getters such as
    contractURI(), tokenURI(), baseURI() return https URLs on-chain and take no
    args, so a 4-byte getter replay hits them cleanly. Treating "returned a URL"
    as a dead drop would flag those as COMPROMISED — the exact false positive we
    forbid. URL-only returns are corroborated separately by fetching the C2 chain
    (see orchestrator.finalize_core); on their own they are at most SUSPECTED."""
    return bool(payload_js) and bool(LOADER_SIG_RE.search(payload_js))


def static_signatures(texts: list[str]) -> dict:
    """Scan page source + external scripts for EtherHiding injection signatures."""
    blob = "\n".join(t for t in texts if t)
    hits = {
        "eth_call": bool(ETH_CALL_RE.search(blob)),
        "contract": bool(CONTRACT_RE.search(blob)),
        "sync_xhr": bool(SYNC_XHR_RE.search(blob)),
        "script_tag_eval": bool(SCRIPT_EVAL_RE.search(blob)),
        "rpc_provider": bool(RPC_PROVIDER_RE.search(blob)),
    }
    m = CONTRACT_RE.search(blob)
    hits["contract_value"] = m.group(0) if m else ""
    # "Injection present" = eth_call AND a corroborating loader signature in source.
    hits["injection"] = hits["eth_call"] and (hits["sync_xhr"] or hits["script_tag_eval"])
    return hits


def decide(*, rpc_captured: bool, mitm_corroborated: bool, static: dict,
           deaddrop_verified: bool, nav_blocked: bool, clickfix: bool,
           c2_count: int) -> dict:
    injection = bool(static.get("injection"))

    signals = {
        "decisive_rpc_captured": rpc_captured,
        "mitm_corroborated": mitm_corroborated,
        "static_injection_signature": injection,
        "onchain_deaddrop_verified": deaddrop_verified,
        "clickfix_detected": clickfix,
        "c2_urls_found": c2_count,
    }

    if deaddrop_verified and (rpc_captured or injection):
        verdict, confidence, summary = (
            COMPROMISED, 100,
            "EtherHiding dead drop confirmed on-chain (the contract the page called returns "
            "an executable loader / C2 URLs) with a corroborating browser or source signal. "
            "Definitive compromise.")
    elif deaddrop_verified:
        verdict, confidence, summary = (
            COMPROMISED, 100,
            "The contract returns an executable loader / C2 URLs on-chain — an EtherHiding "
            "dead drop. No legitimate contract serves browser-executable JavaScript. Confirmed.")
    elif rpc_captured and injection:
        verdict, confidence, summary = (
            SUSPECTED, 80,
            "A decisive blockchain RPC call was observed from the browser AND the page source "
            "carries an EtherHiding injection signature, but the contract returned no decodable "
            "dead drop (likely gate-suppressed or dormant). Strong suspicion — analyst review.")
    elif rpc_captured:
        verdict, confidence, summary = (
            SUSPECTED, 55,
            "A blockchain RPC call was observed from the browser. On an ordinary business site "
            "this is a strong EtherHiding indicator, but legitimate web3/dApp sites also do this "
            "and no on-chain dead drop was verified. Analyst review required.")
    elif injection:
        verdict, confidence, summary = (
            SUSPECTED, 70,
            "EtherHiding injection signatures are present in source but no blockchain call was "
            "captured and no dead drop was verified (likely gate-suppressed or dormant). "
            "Analyst review recommended.")
    elif nav_blocked:
        verdict, confidence, summary = (
            INCONCLUSIVE, 0,
            "The page could not be loaded/rendered; no signals gathered. Re-run, ideally from a "
            "residential egress IP.")
    else:
        verdict, confidence, summary = (
            CLEAN, 0,
            "No EtherHiding dead drop, decisive blockchain RPC, or injection signature detected.")

    return {"verdict": verdict, "confidence": confidence, "summary": summary,
            "signals": signals, "is_compromised": verdict == COMPROMISED}
