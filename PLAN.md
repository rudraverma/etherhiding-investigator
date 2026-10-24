# EtherHawk — Build Plan & Project State

> Standalone, **fully deterministic** EtherHiding detection appliance.
> No AI/agent at runtime. CyberHawk-branded dashboard. Residential-IP egress.

## Mission

Detect EtherHiding-compromised websites that use a **stage-1 fingerprint gate** to
suppress the `eth_call` chain for sandboxes/analysts. The appliance visits as a
real residential-IP laptop, forces the chain to fire, captures the blockchain RPC
call via MITM + CDP hooks, and renders a deterministic verdict.

## Hard constraints (locked with the user)

1. **No AI at runtime.** Every stage is plain code. The verdict is a hard rule,
   not a model/score. The `analyzing-etherhiding-blockchain-c2` skill ships only
   as human-reference docs under `skills/`.
2. **Detection correctness = 100% when the chain fires**: a browser-context
   blockchain RPC call, re-verified on-chain, means COMPROMISED. Zero false
   positives by design; zero false negatives on captured traffic.
3. **TP maximized** via residential egress + coherent fingerprint + human
   interaction + 3 independent confirmation paths (live capture, isolated
   sandbox execution, direct contract replay).
4. **Egress = host public IP** (residential). Optional upstream proxy, off by default.
5. Auth = single shared token + generatable appliance API key.
6. Storage = SQLite + artifacts on volume.
7. MISP push optional, configured in Settings.

## Architecture (docker-compose)

| Service | Role | Net |
|---|---|---|
| etherhawk-ui | React/nginx dashboard (CyberHawk brand kit), 6 tabs | net |
| etherhawk-api | FastAPI orchestrator, verdict engine, SQLite, SSE, MISP | net + internal |
| etherhawk-proxy | mitmproxy addon (RPC/C2 flagger) + mitmweb live view | net |
| etherhawk-browser | Playwright full-Chromium coherent-fingerprint worker + CDP hooks | net |
| etherhawk-deobf | JS/PS beautifier + IOC extractor | net |
| etherhawk-sandbox | isolated Node VM, **no egress** (internal net), cap_drop ALL | internal |

`etherhawk-internal` is `internal: true` → the sandbox cannot reach the internet.

## Dashboard tabs

1. Submit URL  2. Live Investigation (SSE)  3. MITM Proxy (live flows)
4. Report (verdict/contract/relay/C2/payload)  5. Evidence (case tree + safe HTML viewer)
6. Settings (control panel: MISP, API key, token, egress, fingerprint, branding)

## Case layout

`/workspace/cases/YYYY/MM/DD/<case-name>/` with
`recon/ page/ network/ scripts/ blockchain/ c2/ sandbox/` +
`notes.md report.md report.json verdict.json iocs.json commands.log decode_chain.md`.

## Pipeline stages (all deterministic)

0. SSRF-validate URL, create case.
1. Recon: DNS, WHOIS, TLS, HTTP headers.
2. Live visit (browser worker via proxy) — coherent fingerprint, human behavior,
   CDP hooks capture eval/atob/Function/fetch/XHR/serviceWorker + network RPC.
3. Proxy snapshot: flows for target domain/time-window → `network/`.
4. Verdict engine: blockchain RPC captured? → candidate COMPROMISED.
5. Fallbacks when no capture: static script grep + sandbox forced execution.
6. Blockchain: extract contract/selector/RPC → direct replay → ABI decode →
   base64 decode → C2 URL array (VERIFICATION step).
7. C2 chain: fetch each stage through proxy → deobfuscate → sandbox-unwrap →
   detect ClickFix → extract relay/C2/payload IOCs.
8. Report + IOC store + optional MISP push.

## Verdict rule (zero FP)

`COMPROMISED = EtherHiding` iff an on-chain **dead drop** is verified (the contract
returns browser-executable JS / C2 URLs — `payload_is_deaddrop`). A bare browser
`eth_call` or a source-only injection signature → `SUSPECTED` (legit dApps also call
`eth_call`). Only decisive methods (`eth_call`/`eth_getStorageAt`/`eth_getLogs`) count;
handshake chatter ignored. Verdict uses per-case browser capture, not the shared MITM log.

## Security (OWASP)

SSRF guard on submit + egress SSRF block in the proxy (covers browser + all API
fetches + redirects; browser has no direct internet route); untrusted JS only in
no-egress sandbox; token auth + constant-time compare (placeholder token rejected);
secrets never baked in images or logged; mitmweb not exposed; malware HTML never
auto-executed (screenshot + inert source + sandboxed iframe, scripts off);
parameterized SQL; path-traversal-safe artifact reads.

## Status

- [x] Phase 1 — scaffold (compose, env, gitignore, license, skill, docs)
- [x] Phase 2 — etherhawk-proxy (+ egress SSRF block)
- [x] Phase 3 — etherhawk-browser (coherent fingerprint, no direct egress)
- [x] Phase 4 — etherhawk-deobf + etherhawk-sandbox
- [x] Phase 5 — etherhawk-api (deterministic pipeline, dead-drop verdict)
- [x] Phase 6 — etherhawk-ui (6 tabs)
- [x] Phase 7 — README/DESIGN + independent security/architecture review
- [x] Phase 8 — addressed all CRITICAL/HIGH + MEDIUM/LOW review findings

## Review findings addressed (independent audit)

- **C1** verdict no longer treats bare browser RPC as COMPROMISED; requires verified
  on-chain dead drop; decisive-method filter excludes dApp handshake calls.
- **H1** egress SSRF block in the proxy (all browser + API fetches + redirects);
  browser container has no direct internet route.
- **H2** removed the unauthenticated `/mitmweb/` route + host exposure.
- **H3** verdict uses per-case browser capture; MITM flagged flows contract-correlated.
- **M1** seek-based bounded tail of `flows.jsonl`.
- **M2** browser `no-new-privileges` + internal-only network; sandbox cap_drop/read_only.
- **M3** `verified` requires a real dead drop (C2 URLs / loader), not any decoded string.
- **L1** `nav_blocked` only when the page never rendered and nothing captured.
- **L2** removed the non-existent webhook claim.
- **L3** placeholder token rejected; API/mitmweb bound to localhost/internal.
- **L4** case-name resolution rejects `..`.
