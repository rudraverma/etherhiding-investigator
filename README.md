<p align="center">
  <img src="https://media.cyberhawkthreatintel.com/general/1771234479938-y9566.png" alt="CyberHawk Threat Intel" width="150"/>
</p>

<h1 align="center">EtherHawk — EtherHiding Investigator</h1>
<p align="center">
  <strong>By <a href="https://www.cyberhawkthreatintel.com">CyberHawk Threat Intel</a></strong> · Rudra Verma | Senior Cyber Security Architect &amp; Researcher
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Deployment-Docker%20Compose-0066cc?style=flat-square"/>
  <img src="https://img.shields.io/badge/Engine-Deterministic%20(no%20AI)-00aa44?style=flat-square"/>
  <img src="https://img.shields.io/badge/Technique-EtherHiding%20%2F%20Blockchain%20C2-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-Apache--2.0-green?style=flat-square"/>
</p>

---

## What this is

**EtherHawk** is a self-contained Docker appliance that detects **EtherHiding**-compromised
websites — including the current generation that hides behind a **stage-1 fingerprint gate**.

An analyst submits a URL on the dashboard. The appliance visits it from the host's own
**residential public IP**, wearing a **coherent real-laptop fingerprint**, with human-like
interaction — so the attacker's gate releases the `eth_call` chain it would suppress for a
sandbox. A **MITM proxy** and **in-browser hooks** capture the blockchain RPC call, and a
**deterministic rule engine** renders the verdict. There is **no AI in the detection loop** —
the appliance decides on its own, every time, the same way.

> Authorized security research &amp; incident response only. Unauthorized use is illegal.

---

## Why normal sandboxes miss it

Modern EtherHiding loaders fingerprint the visitor **before** making any blockchain call.
If the visitor looks automated — a datacenter IP, a headless browser, a `SwiftShader` GPU,
`navigator.webdriver` set, no plugins, no human cursor — the loader **silently does nothing**.
The `eth_call` never fires, so Suricata/sandbox signatures never trigger and the site looks clean.

EtherHawk defeats this deterministically:

| Gate check | EtherHawk's answer |
|---|---|
| Datacenter / proxy IP | Egresses via the **host's residential public IP** (your homelab/server). No DC proxy. |
| **TLS / HTTP2 fingerprint** | A **real Google Chrome** (kasmweb) is driven over CDP — **no TLS-terminating proxy** — so Chrome's genuine TLS/JA3/HTTP2 handshake reaches the server. This is the single biggest fix: an intercepting MITM proxy's TLS fingerprint gets you cloaked. |
| Behavioral / human gate | **Interactive mode:** the analyst drives the real browser live (noVNC) — real cursor physics, clicks, CAPTCHA/QR, ClickFix — exactly like ANY.RUN. Auto mode simulates interaction for fast triage. |
| GPU = SwiftShader | WebGL vendor/renderer spoofed to a consistent GPU via a CDP init script. |
| `navigator.webdriver` | Removed via CDP init script. |
| Still blocked / cloaked | Never reported "clean": a 5xx/decoy/blocked visit returns **`INCONCLUSIVE`**. Plus **static + on-chain** fallbacks when source is reachable. |

**Two modes, one real browser:**
- **Interactive** (primary for hardened targets) — you drive a real Chrome in the dashboard; capture runs live; hit *Analyze* when the chain fires.
- **Auto** — unattended triage: the API drives the same browser over CDP (navigate + simulate + dwell).

---

## Detection guarantee — stated honestly

- **Zero false positives, by design.** The hard verdict `COMPROMISED_ETHERHIDING` is asserted
  **only** when an on-chain **dead drop** is verified — the contract the page called returns
  browser-executable JavaScript / C2 URLs. No legitimate contract does this, so legitimate
  web3/dApp sites (which also issue `eth_call`) are never labelled compromised — a bare RPC call
  is reported as `SUSPECTED` for analyst review, not as a confirmed compromise.
- **True-positive rate is maximised.** The one variable is whether the attacker's gate lets us
  execute. Residential egress + coherent fingerprint + human interaction + **three independent
  confirmation paths** (live MITM/CDP capture, isolated-sandbox forced execution, direct on-chain
  replay) drive the fire-rate toward 100% on real EtherHiding sites. When any path fires, the
  verdict is certain.
- **100% correct when it fires; engineered so it fires.** No scanner can promise a gate always
  releases to it — EtherHawk is built to maximise that and to fall back to static + on-chain proof
  when the live visit is refused.

---

## Architecture

```
                         ┌──────────────── Docker host (RESIDENTIAL public IP) ───────────────┐
  analyst browser ──►  etherhawk-ui (8080)  ──nginx /api──►  etherhawk-api (8094)              │
       │   (noVNC view)                                         │  deterministic pipeline      │
       │                                                        │  SQLite · SSE · verdict      │
       └────────────► etherhawk-interactive (6901 noVNC) ◄──────┤                              │
                      REAL Google Chrome + CDP capture (:9001)   │                              │
                      genuine TLS fingerprint, no proxy          ▼               ▼              │
                                     │                     etherhawk-deobf   (CDP capture       │
                                     │                     (beautify+IOCs)    writes flows)     │
                                     └─── egress via host public IP ───► the internet ──────────┘
                                                                ▲
                       etherhawk-sandbox (internal net, NO egress) ── unwraps runtime obfuscation
```

| Service | Role |
|---|---|
| `etherhawk-ui` | React/nginx dashboard (CyberHawk brand kit): Interactive, Submit(auto), MITM, Report, Evidence, Settings |
| `etherhawk-api` | Deterministic orchestrator, verdict engine, SQLite, SSE, MISP push |
| `etherhawk-interactive` | **Real Google Chrome** (kasmweb/chrome, noVNC) + CDP capture service — genuine TLS fingerprint, analyst-drivable *and* API-drivable |
| `etherhawk-deobf` | JS/PowerShell beautifier + IOC extractor (never executes) |
| `etherhawk-sandbox` | Isolated Node runtime — **no network egress**, `cap_drop ALL`, read-only |

> Capture is **browser-native over CDP** — no TLS-terminating proxy — so the target sees Chrome's
> real TLS/HTTP2 fingerprint. Flows are tagged per-case (no cross-case contamination) and still
> shown live in the MITM tab.

---

## Install

**Requirements:** a Linux host (homelab/server) with Docker + Docker Compose, egressing via a
**residential public IP**. Datacenter/VPS IPs will usually suppress the `eth_call` — run it where
your public IP is residential.

```bash
git clone https://github.com/rudraverma/etherhiding-investigator.git
cd etherhiding-investigator

cp .env.example .env
# Set these in .env:
#   ETHERHAWK_DASHBOARD_TOKEN   openssl rand -hex 32   (appliance refuses access until set)
#   KASM_PASSWORD               password for the interactive browser desktop (user: kasm_user)
nano .env

docker compose build        # first build pulls kasmweb/chrome (~2 GB) — be patient
docker compose up -d
```

Open **http://&lt;host-ip&gt;:8080**, log in with `ETHERHAWK_DASHBOARD_TOKEN`, and finish
configuration (MISP, branding, API key) in the **Settings** tab.

**First use of the Interactive tab:** the analyst browser is served on
`https://<host-ip>:6901` with a self-signed certificate. Click *“open browser in new tab”*
once to accept the cert (then it embeds in the dashboard), and log into the desktop with
`kasm_user` / `KASM_PASSWORD`.

> The dashboard and the noVNC desktop can both reach attacker infrastructure — never expose ports
> 8080 or 6901 to the public internet. Put them behind a VPN / Cloudflare Tunnel / firewall and
> bind only to your LAN.

---

## Usage

- **Interactive** (primary, for hardened/cloaking targets) — enter the URL, click *Open in browser*,
  then **drive the real Chrome yourself** in the embedded noVNC view (move the mouse, click through
  the CAPTCHA/QR, trigger the ClickFix lure). Live signals (blockchain RPC / contract / ClickFix)
  update as the chain fires; click **Analyze** to decode and generate the report.
- **Submit (auto)** — unattended triage: the API drives the same real browser over CDP and runs the
  full pipeline (recon → visit → capture → verdict) with live SSE logs.
- **MITM** — every HTTP/HTTPS/WS call the target makes, live (captured in-browser), blockchain RPC highlighted.
- **Report** — verdict, confidence, contract, RPC endpoint, decoded C2/relay/payload chain, ClickFix, classified IOCs.
- **Evidence** — the full case tree; view any artifact, including the captured page rendered in a
  **sandboxed frame with scripts disabled**.
- **Settings** — control panel: MISP URL + key, timeouts, dashboard token, generated API key, branding.

### What you get per case

```
/workspace/cases/YYYY/MM/DD/<case-name>/
├── report.md  report.json  verdict.json  iocs.json  notes.md
├── recon/        dns / whois / tls / http headers
├── page/         page_source.html + screenshots
├── network/      MITM flows (+ flagged blockchain RPC)
├── scripts/      every external script fetched
├── blockchain/   eth_call response, ABI-decoded payload, decoded C2 URLs
├── c2/           each relay/payload stage (raw + beautified)
└── sandbox/      isolated-execution captures
```

Every artifact is written automatically by the pipeline.

---

## Verdict rules (deterministic)

| Condition | Verdict | Confidence |
|---|---|---|
| On-chain **dead drop** verified (contract returns an executable loader / C2 URLs) + a browser or source signal | `COMPROMISED_ETHERHIDING` | 100% |
| On-chain **dead drop** verified (dead drop alone is definitive — no legit contract serves JS) | `COMPROMISED_ETHERHIDING` | 100% |
| Decisive browser RPC **and** source injection signature, but no dead drop verified | `SUSPECTED_ETHERHIDING` | 80% |
| Source injection signature only | `SUSPECTED_ETHERHIDING` | 70% |
| Decisive browser RPC only (no dead drop, no injection signature) | `SUSPECTED_ETHERHIDING` | 55% |
| Page could not be loaded / no signals | `INCONCLUSIVE` | 0% |
| No dead drop, no decisive RPC, no injection signature | `NO_ETHERHIDING_DETECTED` | 0% |

> **Why a bare `eth_call` is only SUSPECTED, not COMPROMISED:** legitimate web3 / dApp / wallet
> sites also issue browser `eth_call`. The hard `COMPROMISED` label is reserved for the behaviour
> no legitimate contract exhibits — an on-chain **dead drop** that returns browser-executable
> JavaScript / C2 URLs. This is what keeps false positives at zero. Only *decisive* RPC methods
> (`eth_call`, `eth_getStorageAt`, `eth_getLogs`) count toward the verdict; handshake chatter
> (`eth_chainId`, `net_version`, `eth_blockNumber`) is ignored.

A legitimate-looking site is **not** evidence of clean — compromised sites *are* legitimate sites.

---

## MISP

Set **MISP URL + API key** in Settings. On a confirmed compromise, EtherHawk auto-creates a
TLP:AMBER event with correctly-classified, defanged attributes: the victim domain and blockchain
RPC infra are added **without** `to_ids` (do not block), while relay/payload C2 are flagged to block.

---

## Security model

- **SSRF guards:** the submitted URL is validated (scheme allowlist; private/loopback/link-local/
  metadata blocked), and every *secondary* API fetch (external scripts, on-chain RPC replay, C2 chain)
  is re-validated before the request. `ALLOW_PRIVATE_TARGETS=true` opts into internal testing.
- **Untrusted JS executes only** in `etherhawk-sandbox`, which sits on an `internal: true` network
  with **no route to the internet**, `cap_drop: ALL`, `read_only`, `no-new-privileges`, non-root.
- **Captured malware HTML is never auto-executed** — rendered only in a sandboxed `<iframe>` with
  scripts disabled, or shown as inert source.
- **Token/API-key auth** (constant-time) on every route except `/api/health`; the default
  placeholder token never grants access; secrets never baked into images or returned in plaintext;
  parameterized SQL; path-traversal-safe artifact reads.
- **Interactive browser caveat:** the real Chrome needs direct egress (that's what preserves its TLS
  fingerprint), so it is not behind an egress choke point. Keep the appliance on a network segment
  that cannot reach host management / internal LAN, and never expose port 6901 publicly.

See [`DESIGN.md`](DESIGN.md) for the full threat model and data flow.

---

## The embedded methodology

The deterministic logic encodes the CyberHawk **`analyzing-etherhiding-blockchain-c2`** skill
(shipped as reference docs under [`skills/`](skills/analyzing-etherhiding-blockchain-c2)). The skill
is documentation for humans — the appliance does not call an LLM to reach a verdict.

---

## Connect with CyberHawk Threat Intel

<p align="center">
  <strong>🦅 <a href="https://www.cyberhawkthreatintel.com">cyberhawkthreatintel.com</a></strong><br/>
  <em>Rudra Verma | Senior Cyber Security Architect &amp; Researcher</em><br/>
  <em>Authorized security research &amp; incident response only. Unauthorized use is illegal.</em>
</p>
