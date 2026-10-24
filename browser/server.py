"""
EtherHawk browser worker
====================================================================
HTTP service the API calls to perform the live visit. Runs a REAL headful
Chromium (under Xvfb) through the MITM proxy, wearing a coherent laptop
fingerprint, with human-like interaction and an escalation ladder. Captures
in-page runtime behaviour (eval/atob/Function/fetch/XHR/WS/serviceWorker) and
writes artifacts into the case folder.

It performs NO verdict logic — it only gathers facts. The API's deterministic
verdict engine decides. This service never executes payloads itself beyond
loading the page the analyst submitted for investigation.

Endpoints:
  GET  /health
  POST /visit   { "url", "case_dir", "timeout"?, "dwell"?, "max_attempts"? }
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

from fingerprint import get_profile, build_init_js
from behavior import humanize

try:
    from playwright.async_api import async_playwright, TimeoutError as PWTimeout
except Exception as e:  # pragma: no cover
    raise RuntimeError(f"Playwright import failed: {e}")

MITM_PROXY = os.getenv("MITM_PROXY", "http://etherhawk-proxy:8095")
HOOKS_JS = Path(__file__).with_name("hooks.js").read_text(encoding="utf-8")

app = FastAPI(title="EtherHawk Browser Worker")


class VisitBody(BaseModel):
    url: str
    case_dir: str
    timeout: int = 40
    dwell: int = 6
    max_attempts: int = 2


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.get("/health")
async def health():
    return {"ok": True, "proxy": MITM_PROXY}


async def _single_visit(url: str, case_dir: Path, profile: dict,
                        timeout: int, dwell: int, attempt: int) -> dict:
    page_dir = case_dir / "page"
    browser_dir = case_dir / "browser"
    page_dir.mkdir(parents=True, exist_ok=True)
    browser_dir.mkdir(parents=True, exist_ok=True)

    capture: dict = {
        "attempt": attempt,
        "profile": profile["id"],
        "url": url,
        "started": _now(),
        "evals": [], "atobs": [], "rpc": [], "sws": [], "net": [],
        "nav_error": None,
    }

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=False,                       # real headful Chromium under Xvfb
            proxy={"server": MITM_PROXY},
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--disable-features=IsolateOrigins,site-per-process",
                f'--window-size={profile["screen"]["width"]},{profile["screen"]["height"]}',
                f'--lang={profile["locale"]}',
            ],
        )
        context = await browser.new_context(
            user_agent=profile["ua"],
            locale=profile["locale"],
            timezone_id=profile["timezone"],
            viewport=profile["viewport"],
            screen={"width": profile["screen"]["width"], "height": profile["screen"]["height"]},
            device_scale_factor=1,
            is_mobile=False,
            has_touch=False,
            color_scheme="light",
            ignore_https_errors=True,                     # accept mitm CA so proxy can decrypt
            extra_http_headers={"Accept-Language": f'{profile["locale"]},en;q=0.9'},
        )

        # Fingerprint coherence + in-page instrumentation, before any page JS.
        await context.add_init_script(build_init_js(profile))
        await context.add_init_script(HOOKS_JS)

        page = await context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
        except PWTimeout:
            capture["nav_error"] = "timeout"
        except Exception as e:
            capture["nav_error"] = str(e)[:300]

        # Screenshot (safe visual evidence)
        try:
            await page.screenshot(path=str(page_dir / f"screenshot_a{attempt}_initial.png"))
        except Exception:
            pass

        # Human-like interaction — some gates require a real user gesture before firing.
        try:
            await humanize(page, profile)
        except Exception:
            pass

        # Let gated / deferred chains execute.
        try:
            await page.wait_for_load_state("networkidle", timeout=timeout * 1000)
        except Exception:
            pass
        await asyncio.sleep(max(0, dwell))

        # Persist page source + final screenshot
        try:
            html = await page.content()
            (page_dir / "page_source.html").write_text(html, encoding="utf-8", errors="replace")
        except Exception:
            pass
        try:
            await page.screenshot(path=str(page_dir / f"screenshot_a{attempt}_final.png"), full_page=True)
        except Exception:
            pass

        # Pull in-page capture object
        try:
            eh = await page.evaluate("window.__eh || {}")
            if isinstance(eh, dict):
                for k in ("evals", "atobs", "rpc", "sws", "net"):
                    capture[k] = eh.get(k, []) or []
        except Exception:
            pass

        try:
            await context.close()
            await browser.close()
        except Exception:
            pass

    capture["finished"] = _now()
    # Deterministic: did we parse a real blockchain JSON-RPC call in-page this attempt?
    # (Only parsed RPC entries count — NOT an eval whose body merely contains the
    # substring "eth_call"; the verdict engine further filters to decisive methods.)
    capture["rpc_seen"] = bool(capture["rpc"])
    (browser_dir / f"captured_attempt{attempt}.json").write_text(
        json.dumps(capture, indent=2, default=str)
    )
    return capture


@app.post("/visit")
async def visit(body: VisitBody):
    case_dir = Path(body.case_dir)
    attempts: list[dict] = []
    rpc_seen = False

    for attempt in range(1, max(1, body.max_attempts) + 1):
        profile = get_profile(attempt - 1)
        # Escalate dwell/interaction on later attempts.
        dwell = body.dwell + (attempt - 1) * 4
        cap = await _single_visit(
            body.url, case_dir, profile, body.timeout, dwell, attempt
        )
        attempts.append(cap)
        if cap["rpc_seen"]:
            rpc_seen = True
            break  # chain fired — no need to escalate

    # Merge captures across attempts
    merged = {"evals": [], "atobs": [], "rpc": [], "sws": [], "net": []}
    for cap in attempts:
        for k in merged:
            merged[k].extend(cap.get(k, []))

    summary = {
        "ok": True,
        "url": body.url,
        "attempts": len(attempts),
        "rpc_seen": rpc_seen,
        "rpc": merged["rpc"],
        "sws": merged["sws"],
        "eval_count": len(merged["evals"]),
        "atob_count": len(merged["atobs"]),
        "net_count": len(merged["net"]),
        "profiles_used": [c["profile"] for c in attempts],
        "nav_errors": [c.get("nav_error") for c in attempts],
    }
    (case_dir / "browser" / "visit_summary.json").write_text(
        json.dumps(summary, indent=2, default=str)
    )
    return summary
