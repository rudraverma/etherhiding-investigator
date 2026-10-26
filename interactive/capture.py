"""
EtherHawk interactive browser — capture & control service
====================================================================
Runs INSIDE the kasmweb/chrome container next to a REAL Google Chrome that the
analyst can see and drive via noVNC. We attach to that same Chrome over the
DevTools Protocol (Playwright connect_over_cdp) — so the browser talks to the
target with its own genuine Chrome TLS/HTTP2 fingerprint (no TLS-terminating
proxy). This is what defeats the server-side cloaking that served our old
proxy-based visit a decoy "WordPress Error" page.

Capture is browser-native: every request/response the page makes (including the
eth_call POST to the blockchain RPC provider) is recorded via CDP, with the
decrypted body available because we are inside the browser. Flows are written in
the same JSONL schema the dashboard already reads, tagged with the case id.

Two modes, same Chrome:
  - POST /visit          AUTO: navigate + simulate human behavior + dwell, return summary
  - POST /session/start  INTERACTIVE: navigate; the analyst drives via noVNC
  - GET  /session/status live signal summary (eth_call / contract / clickfix)
  - POST /session/finalize capture DOM + stop; return summary

No verdict logic here — facts only. The API's deterministic engine decides.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from playwright.async_api import async_playwright

CDP_URL = os.getenv("CDP_URL", "http://127.0.0.1:9222")
FLOWS_PATH = Path(os.getenv("MITM_FLOWS_PATH", "/workspace/_mitm/flows.jsonl"))
HOOKS_JS = Path(__file__).with_name("hooks.js").read_text(encoding="utf-8")

# Minimal, consistency-safe init for a REAL Chrome running headless-in-container:
# only fix the things a container gets wrong (SwiftShader WebGL = instant bot tell).
# We deliberately do NOT spoof UA / UA-CH / platform here — real Chrome already
# reports those correctly, and overriding them would create contradictions.
WEBGL_FIX_JS = r"""
(function(){
  try {
    var patch = function(proto){
      if(!proto) return;
      var orig = proto.getParameter;
      proto.getParameter = function(p){
        if(p===37445) return 'Google Inc. (NVIDIA)';
        if(p===37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
        return orig.call(this,p);
      };
    };
    if(window.WebGLRenderingContext)  patch(WebGLRenderingContext.prototype);
    if(window.WebGL2RenderingContext) patch(WebGL2RenderingContext.prototype);
    Object.defineProperty(navigator,'webdriver',{get:function(){return undefined;}});
  } catch(e){}
})();
"""

BLOCKCHAIN_RPC_METHODS = {"eth_call", "eth_getstorageat", "eth_getcode", "eth_getlogs",
                          "eth_blocknumber", "eth_chainid", "net_version", "eth_sendrawtransaction"}
DECISIVE = {"eth_call", "eth_getstorageat", "eth_getlogs"}
CLICKFIX_RE = re.compile(r"handleCmdCheck|Win\s*\+\s*R|Ctrl\s*\+\s*V|powershell|clipboard", re.I)

app = FastAPI(title="EtherHawk Interactive Browser")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_rpc(body: str | None) -> list[dict]:
    if not body:
        return []
    low = body.lower()
    if "method" not in low:
        return []
    try:
        data = json.loads(body)
    except Exception:
        return []
    calls = data if isinstance(data, list) else [data]
    out = []
    for c in calls:
        if isinstance(c, dict) and str(c.get("method", "")).lower() in BLOCKCHAIN_RPC_METHODS:
            p = c.get("params", [])
            contract = selector = ""
            if p and isinstance(p[0], dict):
                contract = str(p[0].get("to", "") or "")
                d = str(p[0].get("data", "") or "")
                selector = d[:10] if d.startswith("0x") else ""
            out.append({"method": str(c.get("method")).lower(), "contract": contract, "selector": selector})
    return out


class Session:
    def __init__(self):
        self.pw = None
        self.browser = None
        self.context = None
        self.lock = asyncio.Lock()
        self.reset()

    def reset(self):
        self.case_id = ""
        self.case_dir: Path | None = None
        self.url = ""
        self.flows: list[dict] = []
        self.rpc: list[dict] = []
        self.sws: list[str] = []
        self.clickfix = False
        self.started = None
        self.active = False

    async def ensure_browser(self):
        """Attach to the analyst's real Chrome over CDP, retrying until it's up."""
        if self.browser is not None:
            try:
                _ = self.browser.contexts  # cheap liveness probe
                return
            except Exception:
                self.browser = None
        if self.pw is None:
            self.pw = await async_playwright().start()
        last = None
        for _ in range(60):
            try:
                self.browser = await self.pw.chromium.connect_over_cdp(CDP_URL)
                self.context = self.browser.contexts[0] if self.browser.contexts else await self.browser.new_context()
                await self.context.add_init_script(WEBGL_FIX_JS)
                await self.context.add_init_script(HOOKS_JS)
                self.context.on("page", self._wire_page)
                for pg in self.context.pages:
                    self._wire_page(pg)
                return
            except Exception as e:
                last = e
                await asyncio.sleep(1)
        raise RuntimeError(f"could not attach to Chrome at {CDP_URL}: {last}")

    def _wire_page(self, page):
        try:
            page.on("response", lambda resp: self._on_response(resp))
            page.on("websocket", lambda ws: self._on_ws(ws))
        except Exception:
            pass

    def _record(self, rec: dict):
        if not self.case_id:
            return
        rec["case_id"] = self.case_id
        self.flows.append(rec)
        try:
            FLOWS_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(FLOWS_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, default=str) + "\n")
        except Exception:
            pass

    def _on_response(self, resp):
        try:
            req = resp.request
            body = None
            if req.method == "POST":
                try:
                    body = req.post_data
                except Exception:
                    body = None
            rpc = _parse_rpc(body)
            url = req.url
            host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
            rec = {
                "ts": _now(), "epoch": time.time(), "transport": "http",
                "method": req.method, "host": host, "url": url,
                "path": "/" + url.split("/", 3)[-1] if url.count("/") >= 3 else "/",
                "status": resp.status,
                "resp_content_type": (resp.headers or {}).get("content-type", ""),
                "is_blockchain_rpc": bool(rpc), "rpc_calls": rpc,
                "is_jsonp_c2": bool(re.search(r"callback=handleCmdCheck", url, re.I)),
                "is_jsrepo": "/jsrepo" in url.lower(),
            }
            if rpc and body and len(body) < 8192:
                rec["rpc_body"] = body
            if rpc:
                for c in rpc:
                    self.rpc.append({"methods": [c], "where": "network:" + url})
            self._record(rec)
        except Exception:
            pass

    def _on_ws(self, ws):
        try:
            ws.on("framesent", lambda payload: self._on_ws_frame(ws, payload))
        except Exception:
            pass

    def _on_ws_frame(self, ws, payload):
        try:
            text = payload if isinstance(payload, str) else ""
            rpc = _parse_rpc(text)
            if rpc:
                for c in rpc:
                    self.rpc.append({"methods": [c], "where": "ws:" + ws.url})
                self._record({"ts": _now(), "epoch": time.time(), "transport": "websocket",
                              "host": re.sub(r"^wss?://", "", ws.url).split("/")[0], "url": ws.url,
                              "is_blockchain_rpc": True, "rpc_calls": rpc, "case_id": self.case_id})
        except Exception:
            pass

    async def active_page(self):
        await self.ensure_browser()
        pages = [p for p in self.context.pages if not p.is_closed()]
        if pages:
            return pages[-1]
        return await self.context.new_page()

    def summary(self) -> dict:
        contracts, rpc_url, selector = [], "", ""
        for e in self.rpc:
            for m in e.get("methods", []):
                if m.get("contract"):
                    contracts.append(m["contract"])
                    if not rpc_url:
                        mm = re.search(r"https?://[^\s]+", e.get("where", ""))
                        rpc_url = mm.group(0) if mm else ""
                        selector = m.get("selector", "")
        decisive = any(m.get("method") in DECISIVE for e in self.rpc for m in e.get("methods", []))
        return {
            "case_id": self.case_id, "url": self.url,
            "rpc_seen": bool(self.rpc), "decisive_rpc": decisive,
            "rpc": self.rpc, "contracts": sorted(set(contracts)),
            "rpc_url": rpc_url, "selector": selector,
            "flow_count": len(self.flows), "clickfix": self.clickfix,
            "sws": self.sws,
        }


S = Session()
_timeout_task: asyncio.Task | None = None
SESSION_TIMEOUT_S = int(os.getenv("SESSION_TIMEOUT_S", "120"))


class VisitBody(BaseModel):
    url: str
    case_dir: str
    case_id: str
    timeout: int = 45
    dwell: int = 8


class StartBody(BaseModel):
    url: str
    case_dir: str
    case_id: str


@app.get("/health")
async def health():
    try:
        await S.ensure_browser()
        return {"ok": True, "cdp": CDP_URL, "attached": True}
    except Exception as e:
        return {"ok": False, "cdp": CDP_URL, "attached": False, "error": str(e)[:200]}


async def _begin(url: str, case_dir: str, case_id: str):
    async with S.lock:
        await S.ensure_browser()
        S.reset()
        S.case_id = case_id
        S.case_dir = Path(case_dir)
        S.url = url
        S.started = time.time()
        S.active = True
        (S.case_dir / "browser").mkdir(parents=True, exist_ok=True)
        page = await S.active_page()
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            return page, (resp.status if resp else None)
        except Exception as e:
            return page, None


async def _simulate_human(page, dwell: int):
    import random
    try:
        for _ in range(random.randint(6, 12)):
            await page.mouse.move(random.randint(40, 1200), random.randint(40, 700), steps=random.randint(5, 20))
            await asyncio.sleep(random.uniform(0.1, 0.3))
        for _ in range(random.randint(3, 6)):
            await page.mouse.wheel(0, random.randint(200, 600))
            await asyncio.sleep(random.uniform(0.2, 0.5))
        await page.mouse.click(random.randint(100, 1000), random.randint(100, 500))
    except Exception:
        pass
    await asyncio.sleep(max(0, dwell))


async def _capture_dom(page):
    try:
        html = await page.content()
        if S.case_dir:
            (S.case_dir / "page").mkdir(parents=True, exist_ok=True)
            (S.case_dir / "page" / "page_source.html").write_text(html, encoding="utf-8", errors="replace")
        if CLICKFIX_RE.search(html or ""):
            S.clickfix = True
        return html
    except Exception:
        return ""


async def _capture_hooks(page):
    try:
        eh = await page.evaluate("window.__eh || {}")
        if isinstance(eh, dict):
            for e in (eh.get("rpc") or []):
                S.rpc.append(e)
            for s in (eh.get("sws") or []):
                if isinstance(s, dict) and s.get("url"):
                    S.sws.append(s["url"])
            if S.case_dir:
                (S.case_dir / "browser" / "inpage_capture.json").write_text(json.dumps(eh, default=str, indent=2))
    except Exception:
        pass


@app.post("/visit")
async def visit(body: VisitBody):
    """AUTO mode: navigate + simulate + dwell + capture, return summary."""
    if S.active:
        raise HTTPException(status_code=409, detail="A browser session is already active (single-session appliance)")
    try:
        page, main_status = await _begin(body.url, body.case_dir, body.case_id)
        await _simulate_human(page, body.dwell)
        try:
            await page.wait_for_load_state("networkidle", timeout=body.timeout * 1000)
        except Exception:
            pass
        await _capture_dom(page)
        await _capture_hooks(page)
    finally:
        S.active = False
    summ = S.summary()
    summ["main_status"] = main_status
    summ["attempts"] = 1
    summ["profiles_used"] = ["real-chrome-cdp"]
    summ["nav_errors"] = [None if main_status and main_status < 400 else f"status {main_status}"]
    if S.case_dir:
        (S.case_dir / "browser" / "visit_summary.json").write_text(json.dumps(summ, default=str, indent=2))
    return summ


@app.post("/session/start")
async def session_start(body: StartBody):
    """INTERACTIVE mode: navigate; the analyst drives via noVNC."""
    global _timeout_task
    if S.active:
        raise HTTPException(status_code=409, detail="A browser session is already active; finalize it first")
    page, main_status = await _begin(body.url, body.case_dir, body.case_id)
    if _timeout_task and not _timeout_task.done():
        _timeout_task.cancel()
    _timeout_task = asyncio.create_task(_auto_finalize())
    return {"ok": True, "main_status": main_status, "case_id": body.case_id}


@app.get("/session/status")
async def session_status():
    summ = S.summary()
    return {"ok": True, **summ}


async def _auto_finalize():
    """Auto-end the session after SESSION_TIMEOUT_S seconds so stale sessions never block new scans."""
    await asyncio.sleep(SESSION_TIMEOUT_S)
    if not S.active:
        return
    try:
        page = await S.active_page()
        await _capture_dom(page)
        await _capture_hooks(page)
    except Exception:
        pass
    if S.case_dir:
        try:
            summ = S.summary()
            (S.case_dir / "browser" / "visit_summary.json").write_text(json.dumps(summ, default=str, indent=2))
        except Exception:
            pass
    S.active = False


@app.post("/session/finalize")
async def session_finalize():
    """Capture the current DOM + in-page hooks and return the final summary."""
    global _timeout_task
    if _timeout_task and not _timeout_task.done():
        _timeout_task.cancel()
    try:
        page = await S.active_page()
        await _capture_dom(page)
        await _capture_hooks(page)
    except Exception:
        pass
    summ = S.summary()
    if S.case_dir:
        (S.case_dir / "browser" / "visit_summary.json").write_text(json.dumps(summ, default=str, indent=2))
    S.active = False  # session finalized; a new one may start
    return {"ok": True, **summ}


@app.post("/session/abort")
async def session_abort():
    """Force-clear the active session without running the pipeline."""
    global _timeout_task
    if _timeout_task and not _timeout_task.done():
        _timeout_task.cancel()
    S.active = False
    S.case_id = ""
    try:
        page = await asyncio.wait_for(S.active_page(), timeout=3)
        await asyncio.wait_for(page.goto("about:blank"), timeout=5)
    except Exception:
        pass
    return {"ok": True, "msg": "session cleared"}
