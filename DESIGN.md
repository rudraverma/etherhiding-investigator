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

```
submit URL
  → API: SSRF validate → create case (YYYY/MM/DD/name) → background pipeline (SSE log)
      1 recon           dns / whois / tls / http  (httpx via proxy)
      2 live visit      browser worker: headful Chromium + coherent fingerprint + human behavior,
                        egress via host residential IP THROUGH mitmproxy; CDP hooks capture
                        eval/atob/Function/fetch/XHR/WS/serviceWorker + in-page JSON-RPC
      3 page analysis   parse rendered DOM; fetch external scripts (via proxy)
      4 MITM snapshot   copy flows for this domain/time-window from the proxy JSONL into the case;
                        flag blockchain RPC / jsrepo / JSONP
      5 static scan     page source + scripts → injection signatures (eth_call + sync-XHR/script-eval)
      6 blockchain      pick contract+RPC from strongest source → replay eth_call → ABI decode →
                        base64 decode → extract C2 URL array   (VERIFICATION)
      7 C2 chain        fetch each stage via proxy → deobfuscate → sandbox-unwrap → next stages →
                        classify ClickFix / relay / payload
      8 verdict         deterministic rule engine
      9 report          report.md/json + verdict.json + iocs.json + SQLite + optional MISP push
```

## Why each anti-gate measure exists

- **Residential egress (host public IP):** the operator's finding — the gate only fires for
  residential IPs. Docker's default bridge NAT already egresses via the host IP; no DC proxy.
- **Headful Chromium under Xvfb:** headless-shell is trivially fingerprinted; a real browser is not.
- **Coherent fingerprint:** contradictions (UA vs platform vs WebGL) are the primary sandbox tell,
  so every field is made mutually consistent per profile.
- **Human behavior:** gates increasingly require a genuine gesture before releasing the chain.
- **Escalation ladder + static/on-chain/sandbox fallbacks:** redundancy so a single refused visit
  does not become a false negative.

## Components

| Service | Language | Notes |
|---|---|---|
| etherhawk-api | Python/FastAPI | orchestrator, verdict, SQLite (WAL), SSE, MISP; runs non-root (gosu) |
| etherhawk-browser | Python/Playwright | headful Chromium under Xvfb; HTTP worker `/visit` |
| etherhawk-proxy | mitmproxy addon | per-flow JSONL + classification; mitmweb on 8081 |
| etherhawk-deobf | Node | js-beautify + regex IOC extraction; never executes input |
| etherhawk-sandbox | Node (no deps) | `vm` with instrumented globals; container is the real boundary |
| etherhawk-ui | React/Vite + nginx | brand kit; nginx same-origin proxy to API + mitmweb |

## Verdict engine

`COMPROMISED_ETHERHIDING` is asserted only when an on-chain **dead drop** is verified — the
contract returns browser-executable JavaScript / C2 URLs (`verdict.payload_is_deaddrop`). A bare
browser `eth_call`, or a source-only injection signature, is `SUSPECTED` (never silently upgraded),
because legitimate web3/dApp sites also issue browser RPC. Only *decisive* methods (`eth_call`,
`eth_getStorageAt`, `eth_getLogs`) count — handshake chatter (`eth_chainId`/`net_version`/
`eth_blockNumber`) is ignored. The verdict uses the per-case **browser capture** as authoritative,
not the shared MITM log (which is contract-correlated to the case to avoid cross-case contamination
under concurrent investigations). See `api/app/pipeline/verdict.py` + `orchestrator.py`.

## Security / OWASP

- **SSRF:** `api/app/ssrf.py` — scheme allowlist; reject private/loopback/link-local/reserved/
  metadata; `ALLOW_PRIVATE_TARGETS` opt-in for internal testing. *Known limitation:* DNS rebinding
  between check and fetch is not fully preventable in-process — segment the browser container from
  internal LAN/management at deploy time.
- **Egress SSRF block (all paths):** every investigative fetch — the browser's own requests AND the
  API's httpx calls (recon, external scripts, RPC replay, C2 chain, redirects) — routes through
  `etherhawk-proxy`, whose addon resolves each target host and refuses private/loopback/link-local/
  reserved/metadata addresses (`ALLOW_PRIVATE_TARGETS` opt-in). The browser container is on an
  `internal: true` network with **no direct internet route**, so it can only egress via the proxy.
  MISP push is intentionally direct (internal infra), not proxied.
- **Untrusted code execution:** only in `etherhawk-sandbox` on an `internal: true` network (no
  egress), `cap_drop: ALL`, `read_only`, `no-new-privileges`, non-root, tmpfs `/tmp`. `vm` is not a
  security boundary — the container is.
- **Malware HTML:** never served as live HTML; rendered only in a sandboxed `<iframe sandbox="">`
  (no scripts) or shown inert. Artifact endpoint sets `nosniff` + CSP `sandbox` and serves code/HTML
  as text/plain.
- **AuthN:** shared dashboard token or generated appliance API key, `hmac.compare_digest`; every
  route except `/api/health` is guarded; the `.env.example` placeholder token never grants access.
  mitmweb is not exposed to the host or proxied by nginx — the MITM tab uses the token-guarded API.
- **Secrets:** runtime `.env` / SQLite only; masked on read; never logged or baked into images.
- **Injection:** parameterized SQL everywhere; `whois` invoked with list args on a regex-validated
  domain (no shell); path-traversal-safe artifact resolution (rejects `..`).

## Non-goals / limitations

- Not a generic malware sandbox; focused on the EtherHiding/blockchain-C2 family.
- Cannot guarantee a gate that residential-allowlists a *specific* subnet or needs an unsolvable
  human CAPTCHA will fire — fallbacks reduce but cannot eliminate that case.
- `flows.jsonl` grows over time; rotate/prune in long-running deployments.
