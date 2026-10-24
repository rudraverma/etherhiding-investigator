"""
Minimal deterministic MISP push over the REST API. No external MISP SDK — a single
POST /events/add with correctly-typed attributes and a TLP:AMBER tag. Runs only when
a MISP URL + key are configured and the verdict is COMPROMISED. Never routed through
the investigation proxy (MISP is internal infrastructure).
"""

from __future__ import annotations

import httpx

# EtherHawk IOC type → MISP attribute type
_TYPE_MAP = {"domain": "domain", "url": "url", "ip-dst": "ip-dst",
             "ip": "ip-dst", "text": "text"}


def _attr(ioc: dict) -> dict:
    return {
        "type": _TYPE_MAP.get(ioc.get("type", "text"), "text"),
        "value": ioc.get("value", ""),
        "to_ids": bool(ioc.get("to_ids")),
        "comment": ioc.get("note", ""),
        "category": "Network activity" if ioc.get("type") in ("domain", "url", "ip-dst", "ip") else "Other",
    }


async def push_event(*, misp_url: str, api_key: str, verify_tls: bool,
                     report: dict) -> dict:
    base = misp_url.rstrip("/")
    info = (f"EtherHiding — {report.get('victim_domain', '')} "
            f"[{report.get('verdict', '')}] {report.get('case_id', '')}")
    event = {
        "Event": {
            "info": info,
            "distribution": "0",
            "analysis": "2",
            "threat_level_id": "2",
            "Attribute": [_attr(i) for i in report.get("iocs", []) if i.get("value")],
            "Tag": [{"name": "tlp:amber"}, {"name": "etherhiding"}, {"name": "blockchain-c2"}],
        }
    }
    headers = {"Authorization": api_key, "Accept": "application/json",
               "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30, verify=verify_tls) as c:
        r = await c.post(f"{base}/events/add", json=event, headers=headers)
        r.raise_for_status()
        data = r.json()
    eid = (((data or {}).get("Event") or {}).get("id")) or ""
    return {"event_id": eid, "event_url": f"{base}/events/view/{eid}" if eid else ""}
