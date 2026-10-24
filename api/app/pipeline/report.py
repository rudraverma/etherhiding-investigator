"""
Deterministic report generation + IOC classification. Writes report.md, report.json,
verdict.json, iocs.json into the case folder and returns a structured dict for the
dashboard Report tab. IOC classification follows the skill's MISP rules: the victim
site and blockchain RPC infra are NOT block-listed; C2/relay/payload are.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def defang(s: str) -> str:
    return (s or "").replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def _host(u: str) -> str:
    try:
        return urlparse(u if "://" in u else "http://" + u).hostname or ""
    except Exception:
        return ""


def classify_iocs(*, victim_domain: str, contract: str, selector: str, rpc_url: str,
                  c2: dict) -> list[dict]:
    iocs: list[dict] = []
    seen = set()

    def add(t, v, to_ids, note):
        key = (t, v)
        if v and key not in seen:
            seen.add(key)
            iocs.append({"type": t, "value": v, "to_ids": to_ids, "note": note})

    add("domain", victim_domain, False, "Compromised victim site — legitimate, do NOT block")
    if contract:
        add("text", contract, False, "EtherHiding contract address — monitor on-chain")
    if selector:
        add("text", selector, False, "Contract function selector")
    rpc_host = _host(rpc_url)
    if rpc_host:
        add("domain", rpc_host, False, "Blockchain RPC endpoint — legitimate infra, ALERT not block")

    for u in c2.get("relay_urls", []):
        add("url", u, True, "Relay / loader stage — BLOCK")
        add("domain", _host(u), True, "Relay / loader domain — BLOCK")
    for u in c2.get("payload_urls", []):
        add("url", u, True, "Payload server (large obfuscated JS) — BLOCK")
        add("domain", _host(u), True, "Payload server domain — BLOCK")
    return iocs


def build_report(*, case_id: str, case_path: Path, url: str, domain: str,
                 recon: dict, verdict: dict, blockchain: dict, c2: dict,
                 static: dict, visit: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    contract = blockchain.get("contract", "") or static.get("contract_value", "")
    selector = blockchain.get("selector", "")
    rpc_url = blockchain.get("rpc_url", "")

    iocs = classify_iocs(victim_domain=domain, contract=contract, selector=selector,
                         rpc_url=rpc_url, c2=c2)

    report = {
        "case_id": case_id,
        "generated_at": now,
        "target_url": url,
        "victim_domain": domain,
        "verdict": verdict["verdict"],
        "confidence": verdict["confidence"],
        "summary": verdict["summary"],
        "is_compromised": verdict["is_compromised"],
        "signals": verdict["signals"],
        "blockchain": {
            "contract": contract,
            "selector": selector,
            "rpc_url": rpc_url,
            "on_chain_verified": blockchain.get("verified", False),
            "c2_urls": blockchain.get("c2_urls", []),
        },
        "c2_chain": {
            "stages": c2.get("stages", []),
            "relay_urls": c2.get("relay_urls", []),
            "payload_urls": c2.get("payload_urls", []),
            "clickfix_detected": c2.get("clickfix", False),
        },
        "recon": {
            "dns": recon.get("dns", {}),
            "http_status": recon.get("http", {}).get("status"),
            "tls_issuer": recon.get("tls", {}).get("issuer", {}).get("organizationName", ""),
        },
        "visit": {
            "attempts": visit.get("attempts"),
            "profiles_used": visit.get("profiles_used", []),
            "rpc_seen": visit.get("rpc_seen", False),
        },
        "iocs": iocs,
    }

    (case_path / "verdict.json").write_text(json.dumps(verdict, indent=2, default=str))
    (case_path / "report.json").write_text(json.dumps(report, indent=2, default=str))
    (case_path / "iocs.json").write_text(json.dumps(iocs, indent=2, default=str))
    (case_path / "report.md").write_text(_render_md(report), encoding="utf-8")
    return report


def _render_md(r: dict) -> str:
    bc = r["blockchain"]
    c2 = r["c2_chain"]
    lines = [
        f"# EtherHiding Investigation Report — {r['victim_domain']}",
        "",
        f"- **Case:** {r['case_id']}",
        f"- **Generated:** {r['generated_at']}",
        f"- **Target:** {defang(r['target_url'])}",
        f"- **Classification:** TLP:AMBER",
        "",
        "## Verdict",
        "",
        f"**{r['verdict']}** — confidence {r['confidence']}%",
        "",
        f"{r['summary']}",
        "",
        "### Signals",
        "",
        "| Signal | Result |",
        "|---|---|",
    ]
    for k, v in r["signals"].items():
        lines.append(f"| {k.replace('_', ' ')} | {v} |")
    lines += [
        "",
        "## Blockchain Dead Drop",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Contract | `{bc['contract'] or 'n/a'}` |",
        f"| Function selector | `{bc['selector'] or 'n/a'}` |",
        f"| RPC endpoint | {defang(bc['rpc_url']) or 'n/a'} |",
        f"| On-chain verified | {bc['on_chain_verified']} |",
        f"| C2 URLs decoded | {len(bc['c2_urls'])} |",
        "",
        "## C2 / Relay / Payload Chain",
        "",
        f"- **ClickFix detected:** {c2['clickfix_detected']}",
        f"- **Relay URLs:** {len(c2['relay_urls'])}",
        f"- **Payload URLs:** {len(c2['payload_urls'])}",
        "",
    ]
    for s in c2["stages"]:
        lines.append(f"  - stage {s['stage']}: {defang(s['url'])} "
                     f"({s['size']:,}B, {s['language']}{', CLICKFIX' if s.get('clickfix') else ''})")
    lines += ["", "## IOCs (defanged)", "", "| Type | Value | to_ids | Note |", "|---|---|---|---|"]
    for i in r["iocs"]:
        val = defang(i["value"]) if i["type"] in ("url", "domain") else i["value"]
        lines.append(f"| {i['type']} | {val} | {bool(i['to_ids'])} | {i['note']} |")
    lines += [
        "",
        "## Notes",
        "",
        "- Verdict is produced by a deterministic rule set; no AI is involved.",
        "- `COMPROMISED_ETHERHIDING` is asserted only when an on-chain dead drop is verified "
        "(the contract returns browser-executable JavaScript / C2 URLs) — a bare browser `eth_call` "
        "is only `SUSPECTED`, since legitimate web3 sites also call `eth_call`. Zero false positives by design.",
        "",
        "---",
        "_EtherHawk — CyberHawk Threat Intel_",
    ]
    return "\n".join(lines)
