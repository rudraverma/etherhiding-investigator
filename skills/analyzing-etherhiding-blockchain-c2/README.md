<p align="center">
  <img src="https://media.cyberhawkthreatintel.com/general/1771234479938-y9566.png" alt="CyberHawk Threat Intel" width="160"/>
</p>

<h1 align="center">analyzing-etherhiding-blockchain-c2</h1>
<p align="center">
  <strong>By <a href="https://www.cyberhawkthreatintel.com">CyberHawk Threat Intel</a></strong> · Rudra Verma | Senior Cyber Security Architect & Researcher
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Claude%20Code-Skill-0066cc?style=flat-square"/>
  <img src="https://img.shields.io/badge/Domain-Threat%20Intelligence-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/Technique-Blockchain%20C2%20Analysis-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-Apache--2.0-green?style=flat-square"/>
</p>

---

## Overview

**analyzing-etherhiding-blockchain-c2** is a Claude Code skill providing a complete 13-phase investigation methodology for EtherHiding and all blockchain-based C2 JavaScript injection attacks — applicable globally, across any target sector or geography.

EtherHiding is a watering-hole technique where compromised WordPress sites call a blockchain smart contract at runtime to retrieve encoded C2 URLs, entirely bypassing traditional URL-based detection. Without this skill, Claude misses the attack completely — the malicious code never appears in page source and evades every automated scanner.

> Authorized security research & penetration testing only. Unauthorized use is illegal.

---

## What This Skill Covers

| Area | Description |
|---|---|
| WordPress Compromise Detection | Identifying injected scripts in theme `custom.js`, `functions.php`, plugin files, and `wp_options` database |
| Blockchain Dead Drop Analysis | Extracting `eth_call` POST bodies, contract addresses, function selectors, and RPC endpoints |
| ABI Payload Decode | Full Python decode pipeline: ABI string → base64 → JavaScript loader |
| Loader JavaScript Analysis | Bot evasion blocks, double-base64 C2 URL arrays, synchronous XHR eval pattern |
| C2 Payload Analysis | 1–2MB `_0x` obfuscated payload: Service Worker persistence, ClickFix overlay logic |
| ClickFix C2 Identification | JSONP polling pattern (`handleCmdCheck_`), session ID format, live/dead status |
| PCAP Kill-Chain Mapping | Full tshark command library for decrypted PCAP analysis across all 8 kill-chain stages |
| IOC Extraction & Classification | Correct MISP attribute types, `to_ids` flags, victim vs. C2 vs. RPC distinction |
| MISP Push | Event creation, attribute classification, TLP:AMBER tagging, publish workflow |
| Report Writing | Mandatory 13-section `report.md` with full kill-chain narrative and defanged IOCs |

---

## Installation

### Claude Code — global (all projects)

```bash
# macOS / Linux
cp -r analyzing-etherhiding-blockchain-c2/ ~/.claude/skills/

# Windows
xcopy /E /I analyzing-etherhiding-blockchain-c2 "%USERPROFILE%\.claude\skills\analyzing-etherhiding-blockchain-c2"
```

### Claude Code — project only

```bash
mkdir -p .claude/skills/analyzing-etherhiding-blockchain-c2/references
cp SKILL.md .claude/skills/analyzing-etherhiding-blockchain-c2/
cp scripts/abi_decode.py .claude/skills/analyzing-etherhiding-blockchain-c2/scripts/
cp references/*.md .claude/skills/analyzing-etherhiding-blockchain-c2/references/
```

---

## Usage

Auto-triggers when your conversation mentions:

```
eth_call  blockchain  web3  smart-contract  etherhiding  clickfix
jsrepo  publicnode  infura  alchemy  ankr  watering-hole  0x[a-fA-F]{40}
```

Or trigger explicitly:

```
Use the analyzing-etherhiding-blockchain-c2 skill to investigate this URL
```

---

## Example Use Cases

**1. Compromised WordPress site investigation:**
```
This WP site is sending eth_call requests in browser DevTools.
Walk me through the full EtherHiding investigation methodology.
```

**2. PCAP analysis:**
```
I have a decrypted PCAP from a suspected watering-hole incident.
Extract the blockchain dead drop, decode the payload, and map the kill chain.
```

**3. IOC extraction and MISP push:**
```
I've decoded the blockchain payload and confirmed the C2 domains.
Extract all IOCs, classify them correctly for MISP, and push TLP:AMBER.
```

**4. Detection rule writing:**
```
I need KQL and Sigma rules to detect EtherHiding in Sentinel and on endpoints.
Use the investigation findings to build production-ready detection logic.
```

**5. Threat intelligence report:**
```
The investigation is complete. Write the mandatory report.md covering
kill chain, C2 infrastructure, IOCs, MITRE mapping, and detection recommendations.
```

---

## Skill Structure

```
analyzing-etherhiding-blockchain-c2/
├── SKILL.md                          ← Main skill instructions (13 phases)
├── README.md                         ← This file
├── scripts/
│   └── abi_decode.py                 ← ABI decode script (copy to case folder)
└── references/
    ├── attack-patterns.md            ← Full kill chain, annotated loader JS,
    │                                    variant detection, WP injection points,
    │                                    infrastructure patterns, detection rules
    ├── pcap-commands.md              ← Full tshark command library with Python
    │                                    decoders for every kill chain stage
    └── abi-decode.md                 ← ABI string structure, decode script usage,
                                         one-liners, edge cases, worked example
```

---

## Investigation Methodology — 13 Phases

| Phase | What Happens |
|---|---|
| **Phase 1** | Read ALL automated pipeline output before running any manual commands |
| **Phase 2** | Grep `page_source.html` for 12 specific EtherHiding indicators |
| **Phase 3** | Fetch and inspect EVERY external script from `page_analysis.json` |
| **Phase 4** | Identify the blockchain contract (address, selector, network, RPC IP) |
| **Phase 5** | Decode the ABI-encoded blockchain payload using `abi_decode.py` |
| **Phase 6** | Annotate the loader JavaScript (bot evasion, URL array, sync XHR, eval) |
| **Phase 7** | Fetch and analyse the 1–2MB obfuscated jsrepo C2 payload |
| **Phase 8** | Identify and test the ClickFix C2 (JSONP polling, session ID format) |
| **Phase 9** | PCAP analysis — full tshark kill chain extraction (if PCAP available) |
| **Phase 10** | Document kill chain table with timing and network evidence |
| **Phase 11** | Extract and classify all IOCs with correct MISP attribute types |
| **Phase 12** | Push to MISP, tag TLP:AMBER, publish (never leave as draft) |
| **Phase 13** | Write `report.md` — mandatory closing step |

---

## What Is EtherHiding?

EtherHiding is a watering-hole attack technique first documented in the wild in 2023 and continuing to evolve. It targets WordPress sites globally across all verticals.

**Attack chain:**

```
1. Threat actor compromises a WordPress site (typically via stolen FTP/SFTP credentials)
2. Injects JavaScript into the site's theme custom.js or functions.php
3. The JavaScript calls a blockchain smart contract via JSON-RPC (eth_call)
4. The contract stores a Base64-encoded JavaScript loader as its on-chain state
5. The loader decodes → eval'd via synchronous XHR + script tag injection
6. The loader fetches a 1–2MB obfuscated payload from a C2 server (/jsrepo endpoint)
7. The payload displays a ClickFix overlay: "Your browser needs updating — press Win+R, then Ctrl+V"
8. Victim runs a PowerShell credential harvester
9. Browser passwords, cookies, and screenshots exfiltrated to operator C2
```

**Why blockchain makes this hard to stop:**
- The C2 URL is never in the compromised site's source — only retrievable at runtime via `eth_call`
- The blockchain RPC endpoint is legitimate public infrastructure — cannot be blocked
- The threat actor updates the payload by changing contract state — all victims receive the new payload in seconds
- Every automated scanner that checks the User-Agent gets silently rejected before malicious code executes

---

## MITRE ATT&CK Mapping

| Technique ID | Name | How Used |
|---|---|---|
| T1189 | Drive-by Compromise | Victim visits compromised WP site |
| T1059.007 | JavaScript Execution | Loader JS + obfuscated payload execution |
| T1102.002 | Web Service — Bidirectional Communication | Blockchain smart contract as dead drop |
| T1027 | Obfuscated Files or Information | Double-base64 URLs, javascript-obfuscator payload |
| T1204.001 | User Execution: Malicious Link | ClickFix overlay convinces victim to run PowerShell |
| T1219 | Remote Access Software | JSONP polling C2 for operator commands |
| T1555.003 | Credentials from Web Browsers | Chrome/Edge/Brave DPAPI password dump |

---

## Key Detection Signatures

### In Page Source / External Scripts

```bash
grep -n "eth_call"                            # definitive — any hit = COMPROMISED
grep -n "0x[a-fA-F0-9]\{40\}"                # Ethereum contract address
grep -n "publicnode\|infura\.io\|alchemy\|ankr"
grep -n "atob("                               # base64 decode → URL construction
grep -n "\.open.*!1\|\.open.*false"           # synchronous XHR
grep -n "createElement.*script.*responseText" # eval via script tag
grep -n "_0x[a-z0-9]\{4,\}"                  # javascript-obfuscator pattern
grep -n "handleCmdCheck"                      # ClickFix C2 JSONP callback
```

### In Network Traffic

```
POST *.publicnode.com | *.infura.io | cloudflare-eth.com
  body: {"method":"eth_call","params":[{"to":"0x...","data":"0x6d4ce63c"}]}
→ ALERT HIGH: Blockchain dead drop

GET /jsrepo?rnd=FLOAT&ts=UNIX_MS  (response >500KB)
→ ALERT HIGH: EtherHiding payload delivery

GET /index.php?callback=handleCmdCheck_TIMESTAMP&id=SESSION_ID
→ ALERT HIGH: ClickFix C2 active polling
```

---

## ABI Decode Quick Reference

The `eth_call` result is ABI-encoded. The `result` hex field decodes as:

```
[0x] [00...0020] [00...LENGTH] [STRING_BYTES...]
         offset      str_len      utf-8 data
```

**One-liner:**
```python
python3 -c "
import json,base64,re
r=json.load(open('blockchain_rpc_response.json'))
h=r['result'][2:]
n=int(h[64:128],16)
s=bytes.fromhex(h[128:128+n*2]).decode('utf-8','replace')
try: s=base64.b64decode(s+'==').decode('utf-8','replace')
except: pass
print(s[:500])
m=re.search(r'var n\s*=\s*\[([^\]]+)\]',s)
if m:
  [print('C2:',base64.b64decode(u+'==').decode()) for u in re.findall(r'\"([A-Za-z0-9+/=]+)\"',m.group(1))]
"
```

**Or use the provided script:**
```bash
python3 scripts/abi_decode.py [blockchain_rpc_response.json]
```

---

## Verdict Rules

| Condition | Verdict |
|---|---|
| `eth_call` in ANY script loaded by the page | **COMPROMISED** |
| Blockchain RPC POST in network traffic | **COMPROMISED** |
| `atob(` → sync XHR → script tag inject chain | **COMPROMISED** |
| JSONP `handleCmdCheck_` polling detected | **ClickFix C2 ACTIVE** |
| 1MB+ `_0x` obfuscated JS from unknown domain | **MALICIOUS PAYLOAD** |
| Contract confirmed returning JavaScript | **DEAD DROP CONFIRMED** |
| All scripts verified clean, MISP clean | **FALSE POSITIVE** |

> **A site that looks legitimate is NOT evidence that it is clean. Compromised sites ARE legitimate sites.**

---

## IOC Classification for MISP

| IOC | `attr_type` | `to_ids` | Action |
|---|---|---|---|
| Compromised victim domain | `domain` | `false` | Do NOT block — legitimate site |
| C2 payload server domain | `domain` | `true` | BLOCK |
| ClickFix C2 domain | `domain` | `true` | BLOCK |
| Blockchain RPC domain | `domain` | `false` | ALERT only — legitimate infra |
| C2 server IP | `ip-dst` | `true` | BLOCK |
| ClickFix C2 IP | `ip-dst` | `true` | BLOCK |
| jsrepo payload URL | `url` | `true` | BLOCK |
| Contract address | `text` | `false` | Monitor on-chain |
| Function selector | `text` | `false` | Detection context |

> Use `attr_type` in `misp_add_attribute` — NOT `type`. This is the correct MISP MCP parameter name.

---

## Related Skills

| Skill | When to Combine |
|---|---|
| `analyzing-malicious-url-with-urlscan` | Initial URL triage before blockchain patterns confirmed |
| `threat-detection` | Writing Sigma/KQL detection rules from investigation findings |
| `misp-admin` | Advanced MISP event management and correlation |
| `incident-response` | If active credential exfiltration is detected |

---

## References

- [EtherHiding original research — CheckPoint (2023)](https://research.checkpoint.com/2023/etherhiding-hiding-web2-malicious-code-in-web3-smart-contracts/)
- [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator) — the `_0x` obfuscator used in payloads
- [4byte.directory](https://www.4byte.directory/) — function selector lookup
- [BSC testnet RPC](https://bsc-testnet-rpc.publicnode.com) — most common EtherHiding RPC endpoint

---

## Connect with CyberHawk Threat Intel

<p align="center">
  <a href="https://www.cyberhawkthreatintel.com">
    <img src="https://media.cyberhawkthreatintel.com/general/1771234479938-y9566.png" alt="CyberHawk Threat Intel" width="120"/>
  </a>
</p>

<p align="center">
  <strong>🦅 Sign up FREE → <a href="https://www.cyberhawkthreatintel.com">cyberhawkthreatintel.com</a></strong>
</p>

<p align="center">
  <a href="https://youtube.com/@cyberhawkconsultancy">YouTube @cyberhawkconsultancy</a> ·
  <a href="https://youtube.com/@cyberhawkk">YouTube @cyberhawkk</a> ·
  <a href="https://tiktok.com/@cyberhawkthreatintel">TikTok</a> ·
  <a href="https://x.com/cyberhawkintel">X @cyberhawkintel</a> ·
  <a href="https://t.me/cyberhawkthreatintel">Telegram</a>
</p>

<p align="center">
  <em>Rudra Verma | Senior Cyber Security Architect & Researcher | CyberHawk Threat Intel</em><br/>
  <em>Authorized security research & penetration testing only. Unauthorized use is illegal.</em>
</p>

<p align="center">
  #cyberhawkthreatintel &nbsp;#cyberhawkconsultancy &nbsp;#cyberhawkk &nbsp;#cybersecurity &nbsp;#ethicalhacking &nbsp;#pentesting &nbsp;#redteam &nbsp;#threatintel &nbsp;#etherhiding &nbsp;#blockchainc2 &nbsp;#infosec
</p>
