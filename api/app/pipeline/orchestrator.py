"""
Investigation orchestrator — the deterministic pipeline. Runs as a background task,
appends human-readable lines through the `log` callback (streamed to the dashboard
over SSE), writes every artifact into the case folder, and returns the report dict.

No AI anywhere. Every branch is a fixed rule.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import httpx

from app import db
from app.config import BROWSER_URL, MITM_FLOWS_PATH, MITM_PROXY
from app.core import misp_client
from app.pipeline import recon, blockchain, c2chain, verdict as verdict_mod, report as report_mod

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")


def _read_setting_int(key: str, default: int) -> int:
    try:
        return int(db.get_setting(key))
    except Exception:
        return default


async def _call_browser(url: str, case_path: Path, log) -> dict:
    timeout = _read_setting_int("visit_timeout", 40)
    attempts = _read_setting_int("max_attempts", 2)
    dwell = _read_setting_int("post_load_dwell", 6)
    body = {"url": url, "case_dir": str(case_path), "timeout": timeout,
            "dwell": dwell, "max_attempts": attempts}
    # Client timeout must exceed the worst-case in-browser time budget.
    client_timeout = (timeout + dwell + 15) * attempts + 30
    async with httpx.AsyncClient(timeout=client_timeout) as c:
        r = await c.post(f"{BROWSER_URL}/visit", json=body)
        r.raise_for_status()
        return r.json()


async def _fetch_scripts(ext_scripts: list[str], case_path: Path, log) -> list[str]:
    texts: list[str] = []
    scripts_dir = case_path / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    for i, su in enumerate(ext_scripts[:12]):
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                         proxy=MITM_PROXY, verify=False) as c:
                r = await c.get(su, headers={"User-Agent": UA})
                body = r.text
            name = re.sub(r"[^A-Za-z0-9._-]", "_", su.split("/")[-1].split("?")[0])[:50] or f"script{i}"
            if not name.endswith(".js"):
                name += ".js"
            (scripts_dir / name).write_text(body, errors="replace")
            texts.append(body)
        except Exception:
            pass
    if texts:
        log(f"Fetched {len(texts)} external script(s) for static analysis")
    return texts


def _tail_lines(path: Path, max_bytes: int = 4_000_000) -> list[str]:
    """Read only the tail of a possibly-large JSONL file (bounded memory)."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()  # discard partial first line
            data = f.read()
        return data.decode("utf-8", "replace").splitlines()
    except Exception:
        return []


def _snapshot_mitm(domain: str, start_epoch: float, case_path: Path,
                   browser_contracts: set[str], log) -> dict:
    """Copy flows for this target/time-window from the shared mitm log into the case.

    Cross-case safety (H3): a blockchain RPC flow is attributed to THIS case only when
    its contract matches one the per-case browser capture already saw — never merely
    because it is a blockchain RPC in the time window (concurrent investigations share
    one flows.jsonl). The verdict does not depend on this snapshot; the per-case browser
    capture is authoritative."""
    flows, flagged = [], []
    dl = domain.lower()
    bc = {c.lower() for c in browser_contracts if c}
    for line in _tail_lines(MITM_FLOWS_PATH):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("epoch", 0) < start_epoch - 2:
            continue
        host = (rec.get("host") or "").lower()
        host_match = host == dl or host.endswith("." + dl)
        rpc_match = False
        if rec.get("is_blockchain_rpc"):
            for call in rec.get("rpc_calls", []):
                if (call.get("contract") or "").lower() in bc:
                    rpc_match = True
                    break
        if host_match or rpc_match:
            flows.append(rec)
            if rpc_match:
                flagged.append(rec)
    (case_path / "network" / "mitm_flows.json").write_text(json.dumps(flows, indent=2, default=str))
    if flagged:
        (case_path / "network" / "blockchain_rpc_flows.json").write_text(json.dumps(flagged, indent=2, default=str))
    log(f"MITM: {len(flows)} flow(s) captured, {len(flagged)} case-correlated blockchain RPC")
    return {"flows": flows, "flagged": flagged}


def _browser_contracts(visit: dict) -> set[str]:
    out = set()
    for e in visit.get("rpc", []):
        for m in (e.get("methods") or []):
            if m.get("contract"):
                out.add(m["contract"])
    return out


def _pick_contract(visit: dict, mitm_flagged: list[dict], static: dict) -> dict:
    """Deterministically choose contract/rpc_url/selector from the strongest source.
    Browser capture is preferred (per-case correct); MITM is only a corroborating
    source and is already contract-correlated to this case."""
    # 1) Browser in-page capture — per-case authoritative; endpoint embedded in 'where'.
    for e in visit.get("rpc", []):
        for m in (e.get("methods") or []):
            if m.get("contract"):
                where = e.get("where", "")
                url_m = re.search(r"https?://[^\s]+", where)
                return {"contract": m["contract"],
                        "rpc_url": url_m.group(0) if url_m else "",
                        "selector": m.get("selector", "")}
    # 2) MITM flagged RPC flow (already correlated to this case's browser contracts).
    for rec in mitm_flagged:
        for call in rec.get("rpc_calls", []):
            if call.get("contract"):
                return {"contract": call["contract"], "rpc_url": rec.get("url", ""),
                        "selector": call.get("selector", "")}
    # 3) Static source — contract only, no endpoint (replay may be impossible).
    if static.get("contract_value"):
        return {"contract": static["contract_value"], "rpc_url": "", "selector": ""}
    return {"contract": "", "rpc_url": "", "selector": ""}


async def run(case_id: str, url: str, domain: str, case_path: Path, log) -> dict:
    start = time.time()
    log(f"Target: {url}")
    log(f"Case folder: {case_path}")

    # ── Recon ────────────────────────────────────────────────────────────────
    log("── Recon ──", "phase")
    dns_data = await recon.dns_records(domain, case_path, log)
    await recon.whois_lookup(domain, case_path, log)
    tls = await recon.tls_cert(domain, case_path, log)
    http = await recon.http_head(url, case_path, log)

    # ── Live visit (coherent residential-fingerprint browser via proxy) ───────
    log("── Live visit (stealth browser) ──", "phase")
    try:
        visit = await _call_browser(url, case_path, log)
    except Exception as e:
        log(f"Browser worker error: {e}", "error")
        visit = {"ok": False, "rpc_seen": False, "rpc": [], "sws": [],
                 "attempts": 0, "profiles_used": [], "nav_errors": [str(e)]}
    log(f"Visit: attempts={visit.get('attempts')} rpc_seen={visit.get('rpc_seen')} "
        f"profiles={visit.get('profiles_used')}")

    # ── Page analysis + external scripts ──────────────────────────────────────
    log("── Page analysis ──", "phase")
    page = recon.analyse_page(case_path, log)
    script_texts = await _fetch_scripts(page["meta"].get("external_scripts", []), case_path, log)

    # ── Static signatures ─────────────────────────────────────────────────────
    static = verdict_mod.static_signatures([page.get("html", "")] + script_texts)
    log(f"Static signatures: injection={static['injection']} eth_call={static['eth_call']} "
        f"contract={bool(static['contract'])}")

    # ── Per-case decisive RPC capture (authoritative; not the shared MITM log) ──
    browser_contracts = _browser_contracts(visit)
    browser_decisive = any(
        verdict_mod.is_decisive([m.get("method") for m in (e.get("methods") or [])])
        for e in visit.get("rpc", [])
    )

    # ── MITM snapshot (contract-correlated to this case) ───────────────────────
    mitm = _snapshot_mitm(domain, start, case_path, browser_contracts, log)
    mitm_corroborated = any(
        verdict_mod.is_decisive([c.get("method") for c in rec.get("rpc_calls", [])])
        for rec in mitm["flagged"]
    )

    chosen = _pick_contract(visit, mitm["flagged"], static)

    bc_result = {"contract": chosen["contract"], "rpc_url": chosen["rpc_url"],
                 "selector": chosen["selector"], "verified": False, "c2_urls": [], "payload_js": ""}
    c2_result = {"stages": [], "relay_urls": [], "payload_urls": [], "clickfix": False}
    sandbox_decisive = False

    # Escalate to on-chain verification whenever there is any EtherHiding signal.
    if browser_decisive or mitm_corroborated or static.get("injection") or chosen["contract"]:
        log("── Blockchain dead-drop verification ──", "phase")
        if chosen["contract"] and chosen["rpc_url"]:
            bc_result = await blockchain.replay_and_decode(
                chosen["contract"], chosen["rpc_url"], chosen["selector"], case_path, log)
        else:
            log("No RPC endpoint captured — cannot replay on-chain (verdict stays unverified).", "warn")

        if bc_result.get("c2_urls"):
            log("── C2 / relay / payload chain ──", "phase")
            c2_result = await c2chain.follow_chain(bc_result["c2_urls"], case_path, log)
            for s in c2_result.get("stages", []):
                sb = case_path / "sandbox" / f"stage{s['stage']}_sandbox.json"
                if sb.exists():
                    try:
                        for ec in (json.loads(sb.read_text()).get("eth_calls") or []):
                            if verdict_mod.is_decisive([m.get("method") for m in (ec.get("methods") or [])]):
                                sandbox_decisive = True
                    except Exception:
                        pass

    # ── Verdict ────────────────────────────────────────────────────────────────
    log("── Verdict ──", "phase")
    # nav_blocked only when the page never rendered AND nothing was captured (L1).
    page_rendered = (case_path / "page" / "page_source.html").exists() and bool(page.get("html"))
    rpc_captured = browser_decisive or sandbox_decisive
    nav_blocked = (not page_rendered) and (not rpc_captured) and (not static.get("injection"))
    v = verdict_mod.decide(
        rpc_captured=rpc_captured, mitm_corroborated=mitm_corroborated, static=static,
        deaddrop_verified=bool(bc_result.get("verified")),
        nav_blocked=nav_blocked, clickfix=bool(c2_result.get("clickfix")),
        c2_count=len(bc_result.get("c2_urls", [])),
    )
    level = "critical" if v["is_compromised"] else ("warn" if v["verdict"] == verdict_mod.SUSPECTED else "good")
    log(f"VERDICT: {v['verdict']} ({v['confidence']}%) — {v['summary']}", level)

    recon_bundle = {"dns": dns_data, "tls": tls, "http": http}
    report = report_mod.build_report(
        case_id=case_id, case_path=case_path, url=url, domain=domain,
        recon=recon_bundle, verdict=v, blockchain=bc_result, c2=c2_result,
        static=static, visit=visit)

    # ── Persist to DB ──────────────────────────────────────────────────────────
    from datetime import datetime, timezone
    db.update_case(case_id, status="done", verdict=v["verdict"], confidence=v["confidence"],
                   contract=bc_result.get("contract", ""), rpc_url=bc_result.get("rpc_url", ""),
                   c2_count=len(bc_result.get("c2_urls", [])))
    db.add_iocs(case_id, report["iocs"], datetime.now(timezone.utc).isoformat())

    # ── Optional MISP push (only on confirmed compromise) ──────────────────────
    if v["is_compromised"]:
        misp_url = db.get_setting("misp_url")
        misp_key = db.get_setting("misp_api_key")
        if misp_url and misp_key:
            log("── MISP push ──", "phase")
            try:
                verify = str(db.get_setting("misp_verify_tls")).lower() in ("1", "true", "yes", "on")
                res = await misp_client.push_event(misp_url=misp_url, api_key=misp_key,
                                                   verify_tls=verify, report=report)
                db.update_case(case_id, misp_event=res.get("event_url", ""))
                report["misp"] = res
                log(f"MISP event created: {res.get('event_url') or res.get('event_id')}", "good")
            except Exception as e:
                log(f"MISP push failed: {e}", "warn")

    log(f"Investigation complete in {time.time() - start:.1f}s", "good")
    return report
