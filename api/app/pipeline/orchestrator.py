"""
Investigation pipeline — deterministic, no AI. Two entry points share one core:

  run_auto()            AUTO mode: recon -> CDP-driven real-Chrome visit -> finalize
  finalize_interactive() INTERACTIVE mode: pull the analyst-driven session's capture
                         -> recon -> finalize

finalize_core() turns captured facts into a verdict + report. The browser is a
real Google Chrome (kasmweb) driven over CDP, so its genuine TLS fingerprint
reaches the target (no TLS-terminating proxy). Network flows are captured in the
browser and tagged with the case id, so there is no cross-case contamination.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app import db
from app.config import BROWSER_URL, INTERACTIVE_URL, MITM_FLOWS_PATH
from app.core import misp_client
from app.pipeline import recon, blockchain, c2chain, verdict as verdict_mod, report as report_mod


def _read_setting_int(key: str, default: int) -> int:
    try:
        return int(db.get_setting(key))
    except Exception:
        return default


# ── Browser worker calls (the interactive container exposes both) ─────────────
async def _call_visit(url: str, case_path: Path, case_id: str, log) -> dict:
    timeout = _read_setting_int("visit_timeout", 45)
    dwell = _read_setting_int("post_load_dwell", 8)
    body = {"url": url, "case_dir": str(case_path), "case_id": case_id,
            "timeout": timeout, "dwell": dwell}
    client_timeout = timeout + dwell + 60
    async with httpx.AsyncClient(timeout=client_timeout) as c:
        r = await c.post(f"{BROWSER_URL}/visit", json=body)
        r.raise_for_status()
        return r.json()


async def start_interactive_session(url: str, case_path: Path, case_id: str) -> dict:
    body = {"url": url, "case_dir": str(case_path), "case_id": case_id}
    async with httpx.AsyncClient(timeout=90) as c:
        r = await c.post(f"{INTERACTIVE_URL}/session/start", json=body)
        r.raise_for_status()
        return r.json()


async def interactive_status() -> dict:
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(f"{INTERACTIVE_URL}/session/status")
        r.raise_for_status()
        return r.json()


async def _finalize_capture() -> dict:
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(f"{INTERACTIVE_URL}/session/finalize")
        r.raise_for_status()
        return r.json()

async def abort_interactive_session() -> dict:
    """Force-clear any active session without running the pipeline (used by the Stop button).""""
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(f"{INTERACTIVE_URL}/session/abort")
        r.raise_for_status()
        return r.json()


# ── Shared helpers ────────────────────────────────────────────────────────────
async def _fetch_scripts(ext_scripts: list[str], case_path: Path, log) -> list[str]:
    from app.ssrf import is_safe_url
    texts: list[str] = []
    scripts_dir = case_path / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    for i, su in enumerate(ext_scripts[:12]):
        if not is_safe_url(su):
            continue
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=False) as c:
                r = await c.get(su, headers={"User-Agent": recon.UA})
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
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()
            return f.read().decode("utf-8", "replace").splitlines()
    except Exception:
        return []


def _snapshot_mitm(case_id: str, case_path: Path, log) -> dict:
    """Copy this case's captured flows (tagged with case_id by the browser) into
    the case folder. Per-case tagging means zero cross-case contamination."""
    flows, flagged = [], []
    for line in _tail_lines(MITM_FLOWS_PATH):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("case_id") != case_id:
            continue
        flows.append(rec)
        if rec.get("is_blockchain_rpc"):
            flagged.append(rec)
    (case_path / "network" / "mitm_flows.json").write_text(json.dumps(flows, indent=2, default=str))
    if flagged:
        (case_path / "network" / "blockchain_rpc_flows.json").write_text(json.dumps(flagged, indent=2, default=str))
    log(f"Captured flows: {len(flows)} ({len(flagged)} blockchain RPC)")
    return {"flows": flows, "flagged": flagged}


def _pick_contract(summary: dict, mitm_flagged: list[dict], static: dict) -> dict:
    # 1) Browser capture (authoritative; real-Chrome CDP).
    if summary.get("contracts"):
        return {"contract": summary["contracts"][0],
                "rpc_url": summary.get("rpc_url", ""),
                "selector": summary.get("selector", "")}
    # 2) MITM-flagged flow for this case.
    for rec in mitm_flagged:
        for call in rec.get("rpc_calls", []):
            if call.get("contract"):
                return {"contract": call["contract"], "rpc_url": rec.get("url", ""),
                        "selector": call.get("selector", "")}
    # 3) Static source (contract only).
    if static.get("contract_value"):
        return {"contract": static["contract_value"], "rpc_url": "", "selector": ""}
    return {"contract": "", "rpc_url": "", "selector": ""}


async def _recon(url: str, domain: str, case_path: Path, log) -> dict:
    log("── Recon ──", "phase")
    dns_data = await recon.dns_records(domain, case_path, log)
    await recon.whois_lookup(domain, case_path, log)
    tls = await recon.tls_cert(domain, case_path, log)
    http = await recon.http_head(url, case_path, log)
    return {"dns": dns_data, "tls": tls, "http": http}


async def finalize_core(case_id: str, url: str, domain: str, case_path: Path,
                        recon_bundle: dict, summary: dict, log) -> dict:
    # ── Page analysis + external scripts ──────────────────────────────────────
    log("── Page analysis ──", "phase")
    page = recon.analyse_page(case_path, log)
    script_texts = await _fetch_scripts(page["meta"].get("external_scripts", []), case_path, log)

    static = verdict_mod.static_signatures([page.get("html", "")] + script_texts)
    log(f"Static signatures: injection={static['injection']} eth_call={static['eth_call']} "
        f"contract={bool(static['contract'])}")

    browser_decisive = bool(summary.get("decisive_rpc"))
    mitm = _snapshot_mitm(case_id, case_path, log)
    mitm_corroborated = any(
        verdict_mod.is_decisive([c.get("method") for c in rec.get("rpc_calls", [])])
        for rec in mitm["flagged"]
    )
    chosen = _pick_contract(summary, mitm["flagged"], static)

    bc_result = {"contract": chosen["contract"], "rpc_url": chosen["rpc_url"],
                 "selector": chosen["selector"], "verified": False, "c2_urls": [], "payload_js": ""}
    c2_result = {"stages": [], "relay_urls": [], "payload_urls": [], "clickfix": False}
    sandbox_decisive = False

    if browser_decisive or mitm_corroborated or static.get("injection") or chosen["contract"]:
        log("── Blockchain dead-drop verification ──", "phase")
        if chosen["contract"]:
            # replay_and_decode falls back to public RPCs when no endpoint was captured.
            bc_result = await blockchain.replay_and_decode(
                chosen["contract"], chosen["rpc_url"], chosen["selector"], case_path, log)
        else:
            log("No contract captured — cannot replay on-chain (verdict stays unverified).", "warn")

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
    page_rendered = (case_path / "page" / "page_source.html").exists() and bool(page.get("html"))
    main_status = summary.get("main_status")
    http_status = (recon_bundle.get("http") or {}).get("status")
    # The browser's own navigation status is authoritative. Only fall back to the
    # recon-HEAD status when the browser reported none — a site that 500s a bare
    # HEAD but renders fine in the real browser must not be flipped to INCONCLUSIVE.
    if main_status is not None:
        bad_main = main_status >= 400
    else:
        bad_main = http_status is not None and http_status >= 500
    rpc_captured = browser_decisive or sandbox_decisive
    clickfix = bool(c2_result.get("clickfix")) or bool(summary.get("clickfix"))

    # A bare on-chain URL return is NOT a dead drop (legit dApp getters return URLs).
    # Corroborate: a ClickFix stage or a large obfuscated payload actually served
    # from a contract-provided URL confirms the dead drop. Otherwise the loader
    # itself (payload_is_deaddrop) must have matched for bc_result["verified"].
    c2_malicious = bool(c2_result.get("clickfix")) or bool(c2_result.get("payload_urls"))
    deaddrop_verified = bool(bc_result.get("verified")) or c2_malicious
    if c2_malicious and not bc_result.get("verified"):
        log("Dead drop corroborated by C2 chain (malicious payload / ClickFix served).", "critical")

    # nav_blocked / INCONCLUSIVE when the real page never rendered (e.g. cloaked
    # with a 5xx decoy) and we captured no signal — never report such a run CLEAN.
    nav_blocked = ((not page_rendered) or bad_main) and (not rpc_captured) \
        and (not static.get("injection")) and (not deaddrop_verified)

    v = verdict_mod.decide(
        rpc_captured=rpc_captured, mitm_corroborated=mitm_corroborated, static=static,
        deaddrop_verified=deaddrop_verified,
        nav_blocked=nav_blocked, clickfix=clickfix,
        c2_count=len(bc_result.get("c2_urls", [])),
    )
    if bad_main and v["verdict"] == verdict_mod.CLEAN:
        # Defensive: a cloaked/error main response must not read as clean.
        v = {**v, "verdict": verdict_mod.INCONCLUSIVE, "confidence": 0, "is_compromised": False,
             "summary": f"Target returned HTTP {main_status or http_status} and no page/signal was "
                        f"captured — likely cloaked or blocked. Re-run interactively from a residential IP."}
    level = "critical" if v["is_compromised"] else ("warn" if v["verdict"] == verdict_mod.SUSPECTED else "good")
    log(f"VERDICT: {v['verdict']} ({v['confidence']}%) — {v['summary']}", level)

    report = report_mod.build_report(
        case_id=case_id, case_path=case_path, url=url, domain=domain,
        recon=recon_bundle, verdict=v, blockchain=bc_result, c2=c2_result,
        static=static, visit=summary)

    db.update_case(case_id, status="done", verdict=v["verdict"], confidence=v["confidence"],
                   contract=bc_result.get("contract", ""), rpc_url=bc_result.get("rpc_url", ""),
                   c2_count=len(bc_result.get("c2_urls", [])))
    db.add_iocs(case_id, report["iocs"], datetime.now(timezone.utc).isoformat())

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
    return report


# ── AUTO mode ─────────────────────────────────────────────────────────────────
async def run_auto(case_id: str, url: str, domain: str, case_path: Path, log) -> dict:
    start = time.time()
    log(f"Target: {url}")
    log(f"Case folder: {case_path}")
    recon_bundle = await _recon(url, domain, case_path, log)

    log("── Live visit (real Chrome via CDP) ──", "phase")
    try:
        summary = await _call_visit(url, case_path, case_id, log)
    except Exception as e:
        log(f"Browser worker error: {e}", "error")
        summary = {"rpc_seen": False, "decisive_rpc": False, "rpc": [], "contracts": [],
                   "clickfix": False, "main_status": None, "nav_errors": [str(e)]}
    log(f"Visit: status={summary.get('main_status')} rpc_seen={summary.get('rpc_seen')} "
        f"contracts={summary.get('contracts')}")

    report = await finalize_core(case_id, url, domain, case_path, recon_bundle, summary, log)
    log(f"Investigation complete in {time.time() - start:.1f}s", "good")
    return report


# ── INTERACTIVE mode finalize ─────────────────────────────────────────────────
async def finalize_interactive(case_id: str, url: str, domain: str, case_path: Path, log) -> dict:
    start = time.time()
    log("── Finalizing interactive session ──", "phase")
    try:
        summary = await _finalize_capture()
    except Exception as e:
        log(f"Capture finalize error: {e}", "error")
        summary = {"rpc_seen": False, "decisive_rpc": False, "rpc": [], "contracts": [],
                   "clickfix": False, "main_status": None, "nav_errors": [str(e)]}
    log(f"Session capture: rpc_seen={summary.get('rpc_seen')} contracts={summary.get('contracts')}")
    recon_bundle = await _recon(url, domain, case_path, log)
    report = await finalize_core(case_id, url, domain, case_path, recon_bundle, summary, log)
    log(f"Analysis complete in {time.time() - start:.1f}s", "good")
    return report
