# EtherHawk — Design & Threat Model

## Goal

Deterministically detect EtherHiding-compromised websites that use a **stage-1 fingerprint
gate** to suppress the `eth_call` chain for sandboxes and analysts. No AI in the detection loop.

## Threat being detected

1. A legitimate site (usually WordPress) is injected with JS that calls a blockchain smart
   contract (`eth_call`) to retrieve its next stage — the C2 URL lives only on-chain.
2. Current variants run a **fingerprint/automation gate first**; only "real" residential
   visitors get the chain. Sandboxes see a silent no-op.
3. The chain delivers an obfuscated loader → relay → large payload and a **ClickFix** overlay.

Definitive rule (CyberHawk `analyzing-etherhiding-blockchain-c2`): *a blockchain RPC call from a
browser page = COMPROMISED.* EtherHawk's job is to make that call fire for us and capture it.

## Data flow

Two modes share one deterministic core. The browser is a **real Google Chrome** (kasmweb) driven
over CDP — no TLS-terminating proxy — so its genuine TLS/HTTP2 fingerprint reaches the target.

```
INTERACTIVE
  start URL → API SSRF-validate → create case → interactive /session/start (navigate real Chrome)
  analyst drives Chrome via noVNC (mouse/click/CAPTCHA/QR/ClickFix); CDP capture records flows
  (tagged case_id) + in-page hooks, live
  Analyze → /session/finalize (capture DOM) → finalize_core

AUTO
  submit URL → API SSRF-validate → create case → /visit (CDP-drive: navigate + simulate + dwell)
  → finalize_core

finalize_core (both):
  recon          dns / whois / tls / http  (direct httpx)
  page analysis  parse captured DOM; fetch external scripts (each SSRF-checked)
  flows snapshot copy this case's CDP-captured flows (tagged case_id) into the case
  static scan    page source + scripts → injection signatures
  blockchain     pick contract+RPC (browser capture first) → replay eth_call → ABI+base64 decode
                 → extract C2 URLs   (VERIFICATION: dead drop must yield a loader / C2)
  C2 chain       fetch each stage (SSRF-checked) → deobfuscate → sandbox-unwrap → classify ClickFix
  verdict        deterministic rules; cloaked / 5xx / no-render ⇒ INCONCLUSIVE, never CLEAN
  report         report.md/json + verdict.json + iocs.json + SQLite + optional MISP push
```

## Why each anti-gate measure exists

- **Real Chrome, real TLS (no proxy):** the decisive fix. An intercepting MITM proxy swaps Chrome's
  TLS/JA3/HTTP2 fingerprint for the tool's, which WAFs / cloaking backdoors flag — they served our
  old proxy-based visit a 5xx decoy. Capturing in-browser over CDP keeps the genuine handshake.
- **Residential egress (host public IP):** the gate only fires for residential IPs; Docker bridge
  NAT egresses via the host IP.
- **Interactive human drive:** real cursor physics / clicks / CAPTCHA / QR / ClickFix clear
  behavioral gates that simulated movement cannot (the ANY.RUN model).
- **WebGL/webdriver CDP fixes:** a container Chrome reports SwiftShader (a bot tell); spoofed to a
  consistent GPU without touching UA/UA-CH (which real Chrome already reports correctly).
- **INCONCLUSIVE fail-safe + static/on-chain/sandbox fallbacks:** a cloaked/blocked visit is never
  reported CLEAN, and reachable source is still checked.

## Components

| Service | Language | Notes |
|---|---|---|
| etherhawk-api | Python/FastAPI | orchestrator (auto+interactive), verdict, SQLite (WAL), SSE, MISP; non-root (gosu) |
| etherhawk-interactive | kasmweb/chrome + Python | real Google Chrome (noVNC :6901) + CDP capture/control (:9001); genuine TLS |
| etherhawk-deobf | Node | js-beautify + regex IOC extraction; never executes input |
| etherhawk-sandbox | Node (no deps) | `vm` with instrumented globals; container is the real boundary |
| etherhawk-ui | React/Vite + nginx | brand kit; nginx same-origin proxy to API |

## Verdict engine

`COMPROMISED_ETHERHIDING` is asserted only when an on-chain **dead drop** is verified — the
contract returns browser-executable JavaScript / C2 URLs (`verdict.payload_is_deaddrop`). A bare
browser `eth_call`, or a source-only injection signature, is `SUSPECTED` (never silently upgraded),
because legitimate web3/dApp sites also issue browser RPC. Only *decisive* methods (`eth_call`,
`eth_getStorageAt`, `eth_getLogs`) count — handshake chatter (`eth_chainId`/`net_version`/
`eth_blockNumber`) is ignored. Flows are tagged per-case by the capture service, so the verdict
uses this case's own captured RPC — no cross-case contamination. A cloaked / 5xx / no-render visit
yields `INCONCLUSIVE`, never `CLEAN`. See `api/app/pipeline/verdict.py` + `orchestrator.py`.

## Security / OWASP

- **SSRF:** `api/app/ssrf.py` — scheme allowlist; reject private/loopback/link-local/reserved/
  metadata; `ALLOW_PRIVATE_TARGETS` opt-in. The submitted URL is validated, and every secondary API
  fetch (external scripts, RPC replay, C2 chain) is re-checked with `is_safe_url()` before the
  request. *Known limitations:* DNS rebinding between check and fetch is not fully preventable
  in-process; and the interactive real Chrome needs direct egress (that is what preserves its TLS
  fingerprint), so it is not behind an egress choke point — segment the appliance from internal
  LAN/management at deploy time and never expose port 6901. MISP push is intentionally direct.
- **Untrusted code execution:** only in `etherhawk-sandbox` on an `internal: true` network (no
  egress), `cap_drop: ALL`, `read_only`, `no-new-privileges`, non-root, tmpfs `/tmp`. `vm` is not a
  security boundary — the container is.
- **Malware HTML:** never served as live HTML; rendered only in a sandboxed `<iframe sandbox="">`
  (no scripts) or shown inert. Artifact endpoint sets `nosniff` + CSP `sandbox` and serves code/HTML
  as text/plain.
- **AuthN:** shared dashboard token or generated appliance API key, `hmac.compare_digest`; every
  API route except `/api/health` is guarded; the `.env.example` placeholder token never grants
  access. The noVNC desktop (:6901) has its own password (`KASM_PASSWORD`, user `kasm_user`).
- **Secrets:** runtime `.env` / SQLite only; masked on read; never logged or baked into images.
- **Injection:** parameterized SQL everywhere; `whois` invoked with list args on a regex-validated
  domain (no shell); path-traversal-safe artifact resolution (rejects `..`).

## Non-goals / limitations

- Not a generic malware sandbox; focused on the EtherHiding/blockchain-C2 family.
- Cannot guarantee a gate that residential-allowlists a *specific* subnet or needs an unsolvable
  human CAPTCHA will fire from an unattended run — interactive mode (a human driving a real browser)
  is the answer for those; a blocked visit is reported INCONCLUSIVE, never CLEAN.
- The interactive browser holds one live session at a time (single-analyst appliance).
- `flows.jsonl` grows over time; rotate/prune in long-running deployments.
- The kasmweb integration (custom Chrome launch flags, noVNC embedding) should be verified on the
  deployment host; `docker logs etherhawk-interactive` + `/tmp/eh-capture.log` show attach status.
