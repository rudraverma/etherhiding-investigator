"""Passive recon: DNS, WHOIS, TLS, HTTP headers + page analysis. All artifacts
written under the case folder. No verdict logic here — facts only."""

from __future__ import annotations

import asyncio
import json
import re
import socket
import ssl
import subprocess
from pathlib import Path

import dns.resolver
import httpx
from bs4 import BeautifulSoup

from app.config import MITM_PROXY

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")


async def dns_records(domain: str, case_path: Path, log) -> dict:
    data: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME"):
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, domain, rtype, lifetime=8)
            data[rtype] = [str(r) for r in answers]
        except Exception:
            data[rtype] = []
    (case_path / "recon" / "dns_records.json").write_text(json.dumps(data, indent=2))
    log(f"DNS: A={len(data['A'])} MX={len(data['MX'])} NS={len(data['NS'])}")
    return data


async def whois_lookup(domain: str, case_path: Path, log) -> str:
    if not _DOMAIN_RE.match(domain):
        return ""
    try:
        # List args (no shell); domain validated above — no injection surface.
        proc = await asyncio.create_subprocess_exec(
            "whois", domain,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=25)
        text = out.decode("utf-8", "replace")
        if text.strip():
            (case_path / "recon" / "whois.txt").write_text(text)
        log(f"WHOIS: {len(text)} bytes")
        return text
    except Exception as e:
        log(f"WHOIS failed: {e}", "warn")
        return ""


async def tls_cert(domain: str, case_path: Path, log) -> dict:
    def _get():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as s:
                return s.getpeercert()
    try:
        cert = await asyncio.to_thread(_get)
        data = {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "not_before": cert.get("notBefore", ""),
            "not_after": cert.get("notAfter", ""),
            "san": [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
        }
        (case_path / "recon" / "tls_cert.json").write_text(json.dumps(data, indent=2))
        log(f"TLS: issuer={data['issuer'].get('organizationName','?')} SANs={len(data['san'])}")
        return data
    except Exception as e:
        log(f"TLS check skipped: {e}", "warn")
        return {}


async def http_head(url: str, case_path: Path, log) -> dict:
    out: dict = {"status": None, "headers": {}, "redirects": [], "final_url": url}
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=20, verify=False,
                                     proxy=MITM_PROXY, headers={"User-Agent": UA}) as client:
            resp = await client.get(url)
            out["status"] = resp.status_code
            out["final_url"] = str(resp.url)
            out["headers"] = dict(resp.headers)
            out["redirects"] = [str(r.url) for r in resp.history]
        (case_path / "recon" / "http_response.json").write_text(json.dumps(out, indent=2))
        log(f"HTTP: {out['status']} redirects={len(out['redirects'])}")
    except Exception as e:
        log(f"HTTP head failed: {e}", "warn")
    return out


def analyse_page(case_path: Path, log) -> dict:
    """Parse the browser-rendered page_source.html for scripts/forms/iframes/IOCs."""
    html_path = case_path / "page" / "page_source.html"
    meta = {"external_scripts": [], "iframe_count": 0, "form_count": 0, "title": ""}
    iocs = {"urls": [], "domains": [], "ips": [], "emails": []}
    if not html_path.exists():
        return {"meta": meta, "iocs": iocs, "html": ""}

    html = html_path.read_text(errors="replace")
    soup = BeautifulSoup(html, "lxml")
    meta["title"] = (soup.title.string or "").strip() if soup.title else ""
    meta["external_scripts"] = [t.get("src", "") for t in soup.find_all("script")
                                if (t.get("src") or "").startswith("http")]
    meta["iframe_count"] = len(soup.find_all("iframe"))
    meta["form_count"] = len(soup.find_all("form"))

    for u in set(re.findall(r"https?://[^\s'\"<>]{6,200}", html)):
        iocs["urls"].append(u.rstrip(".,;)"))
        if len(iocs["urls"]) >= 60:
            break
    (case_path / "page" / "page_analysis.json").write_text(json.dumps(meta, indent=2))
    log(f"Page: title={meta['title'][:40]!r} ext_scripts={len(meta['external_scripts'])} iframes={meta['iframe_count']}")
    return {"meta": meta, "iocs": iocs, "html": html}
