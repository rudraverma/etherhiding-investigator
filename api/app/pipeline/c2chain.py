"""
C2 / relay / payload chain follower. Given the C2 URLs from the blockchain payload,
fetch each stage through the MITM proxy, deobfuscate it, run runtime-only layers in
the isolated sandbox, extract next-stage URLs, and classify ClickFix. Bounded depth.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

from app.config import MITM_PROXY, DEOBFUSCATOR_URL, SANDBOX_URL

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")

MAX_STAGES = 6

CLICKFIX_RE = re.compile(
    r"handleCmdCheck|Win\s*\+\s*R|Ctrl\s*\+\s*V|powershell|clipboard|navigator\.clipboard|\.writeText",
    re.IGNORECASE)

RPC_NOISE = ("polygon", "infura", "alchemy", "ankr", "tenderly", "publicnode",
             "blastapi", "bsc-dataseed", "llamarpc", "cloudflare-eth",
             "jquery", "bootstrap", "googleapis", "gstatic", "cdnjs", "jsdelivr",
             "unpkg", "fontawesome")


def _next_urls(code: str) -> list[str]:
    found = []
    for m in re.finditer(r"(?:irm|iwr|DownloadString|DownloadFile)\s*\(?\s*['\"]?(https?://\S+?)['\"\) ]", code, re.I):
        found.append(m.group(1))
    for m in re.finditer(r"https?://[\w./:?=&%#~+-]{12,200}", code):
        found.append(m.group(0).rstrip(".,;)'\""))
    seen, out = set(), []
    for u in found:
        if u not in seen and not any(s in u.lower() for s in RPC_NOISE):
            seen.add(u)
            out.append(u)
    return out


async def _deobfuscate(code: str, label: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.post(DEOBFUSCATOR_URL, json={"code": code, "label": label})
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return {"beautified": code, "language": "javascript", "iocs": {}, "needs_sandbox": False}


async def _sandbox(code: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(SANDBOX_URL, json={"code": code, "timeout_ms": 8000})
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return {}


async def follow_chain(c2_urls: list[str], case_path: Path, log) -> dict:
    c2_dir = case_path / "c2"
    sb_dir = case_path / "sandbox"
    c2_dir.mkdir(parents=True, exist_ok=True)
    sb_dir.mkdir(parents=True, exist_ok=True)

    result = {"stages": [], "relay_urls": [], "payload_urls": [], "clickfix": False, "iocs": []}
    queue = list(dict.fromkeys(c2_urls))[:3]
    fetched: set[str] = set()
    stage = 1

    while queue and stage <= MAX_STAGES:
        url = queue.pop(0)
        if url in fetched:
            continue
        fetched.add(url)
        try:
            async with httpx.AsyncClient(timeout=25, follow_redirects=True,
                                         proxy=MITM_PROXY, verify=False) as c:
                resp = await c.get(url, headers={"User-Agent": UA})
                raw = resp.text
        except Exception as e:
            log(f"C2 stage {stage} fetch failed ({url[:60]}): {e}", "warn")
            stage += 1
            continue

        is_ps = bool(re.search(r"iex|invoke-expression|downloadstring|\$env:|-bxor", raw, re.I))
        ext = "ps1" if is_ps else "js"
        (c2_dir / f"stage{stage}_raw.{ext}").write_text(raw, errors="replace")

        deob = await _deobfuscate(raw, f"c2-stage{stage}")
        beautified = deob.get("beautified", raw)
        lang = deob.get("language", "javascript")
        out_ext = "ps1" if lang == "powershell" else ext
        (c2_dir / f"stage{stage}_beautified.{out_ext}").write_text(beautified, errors="replace")

        sandbox_out = {}
        if deob.get("needs_sandbox") and not is_ps:
            sandbox_out = await _sandbox(raw)
            if sandbox_out:
                (sb_dir / f"stage{stage}_sandbox.json").write_text(json.dumps(sandbox_out, indent=2))

        size = len(raw)
        is_clickfix = bool(CLICKFIX_RE.search(raw) or CLICKFIX_RE.search(beautified))
        if is_clickfix:
            result["clickfix"] = True

        stage_rec = {
            "stage": stage, "url": url, "size": size, "language": lang,
            "clickfix": is_clickfix, "is_large_payload": size > 300_000,
            "iocs": deob.get("iocs", {}),
            "sandbox_network": (sandbox_out or {}).get("network_requests", []),
            "sandbox_clipboard": (sandbox_out or {}).get("clipboard", []),
        }
        result["stages"].append(stage_rec)
        if size > 300_000:
            result["payload_urls"].append(url)
        else:
            result["relay_urls"].append(url)

        log(f"C2 stage {stage}: {url[:60]} ({size:,}B, {lang}{', CLICKFIX' if is_clickfix else ''})",
            "critical" if is_clickfix else "warn")

        # enqueue next stages (from beautified + sandbox-captured network targets)
        nxt = _next_urls(beautified)
        for n in (sandbox_out or {}).get("network_requests", []):
            u = n.get("url") if isinstance(n, dict) else n
            if u and u.startswith("http"):
                nxt.append(u)
        for n in nxt:
            if n not in fetched and not any(s in n.lower() for s in RPC_NOISE):
                queue.append(n)
        stage += 1

    (c2_dir / "chain_summary.json").write_text(json.dumps(result, indent=2, default=str))
    return result
