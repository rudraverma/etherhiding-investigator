# EtherHiding — tshark PCAP Command Library

Complete tshark command reference for analyzing decrypted EtherHiding kill-chain PCAPs.
Replace IP placeholders below with the actual IPs extracted from your investigation's pipeline output.
All output must be saved to commands.log per Rule 0.

## Setup

```bash
tshark --version     # need v4+
PCAP="/workspace/investigations/YYYY-MM-DD/<slug>/FILENAME.decrypted.pcap"
CASE="/workspace/investigations/YYYY-MM-DD/<slug>"

# Set these from your investigation's iocs.json / pipeline output
RPC_IP="<RPC-SERVER-IP>"        # resolved IP of the blockchain RPC endpoint
C2_IP="<C2-SERVER-IP>"          # resolved IP of the jsrepo payload server
CLICKFIX_IP="<CLICKFIX-C2-IP>"  # resolved IP of the ClickFix C2 server
```

---

## 1. File Overview

```bash
# Capture summary — packets, duration, size
capinfos "$PCAP" | tee -a "$CASE/commands.log"

# Protocol hierarchy
tshark -r "$PCAP" -q -z io,phs 2>/dev/null | tee "$CASE/pcap_protocol_hierarchy.txt"
```

---

## 2. HTTP Host Map — The Full Kill Chain at a Glance

```bash
# All HTTP requests: timing, IPs, method, URI
tshark -r "$PCAP" -Y "http.request" \
  -T fields \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e http.host \
  -e http.request.method \
  -e http.request.uri \
  | sort -u \
  | tee "$CASE/pcap_http_hosts.txt"

# Request count per host (high count = polling)
tshark -r "$PCAP" -Y "http.request" \
  -T fields -e http.host \
  | sort | uniq -c | sort -rn \
  | tee -a "$CASE/pcap_http_hosts.txt"
```

---

## 3. TCP Conversations (Volume by Host)

```bash
tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null \
  | sort -k6 -rn \
  | head -30 \
  | tee "$CASE/pcap_tcp_conversations.txt"
```

---

## 4. Blockchain RPC — eth_call Extraction

```bash
# Extract POST body hex from blockchain RPC calls
tshark -r "$PCAP" \
  -Y "ip.addr==$RPC_IP && http.request.method==POST" \
  -T fields \
  -e frame.time_relative \
  -e http.host \
  -e http.file_data \
  | tee "$CASE/pcap_rpc_requests_raw.txt"

# Decode hex to readable JSON
python3 << 'EOF'
with open("pcap_rpc_requests_raw.txt") as f:
    for line in f:
        parts = line.strip().split('\t')
        if len(parts) >= 3 and parts[2]:
            try:
                decoded = bytes.fromhex(parts[2]).decode('utf-8', errors='replace')
                print(f"[T+{parts[0]}] {parts[1]}:\n  {decoded}\n")
            except: pass
EOF
```

---

## 5. Blockchain RPC Response — ABI Payload Extraction

```bash
# Get hex of the eth_call response body
tshark -r "$PCAP" \
  -Y "ip.src==$RPC_IP && http.response.code==200" \
  -T fields \
  -e frame.time_relative \
  -e http.file_data \
  | head -3 \
  | tee "$CASE/pcap_rpc_responses_raw.txt"

# Decode the ABI-encoded response to extract the JavaScript payload
python3 << 'EOF'
import json, base64, re

# Paste hex from the file_data field above
hex_data_line = "PASTE_HEX_HERE"

# Hex → JSON → ABI decode
raw  = bytes.fromhex(hex_data_line.strip()).decode('utf-8', errors='replace')
resp = json.loads(raw)
h    = resp['result'][2:]   # strip 0x

offset  = int(h[0:64],   16)
str_len = int(h[64:128], 16)
str_hex = h[128 : 128 + str_len * 2]
payload = bytes.fromhex(str_hex).decode('utf-8', errors='replace')

print(f"ABI decoded ({str_len} bytes):\n{payload[:300]}")

# Double decode if base64
try:
    decoded2 = base64.b64decode(payload + "==").decode('utf-8', errors='replace')
    print(f"\nDouble decoded ({len(decoded2)} chars):\n{decoded2[:500]}")
    payload = decoded2
except Exception as e:
    print(f"\nNot double-base64: {e}")

# Extract C2 URLs from JS array
m = re.search(r'var n\s*=\s*\[([^\]]+)\]', payload)
if m:
    print(f"\nC2 URLs found:")
    for i, u in enumerate(re.findall(r'"([A-Za-z0-9+/=]+)"', m.group(1))):
        url = base64.b64decode(u + "==").decode('utf-8', errors='replace')
        print(f"  [{i+1}] {url}")

with open('blockchain_decoded_payload.js', 'w') as f:
    f.write(payload)
print("\nSaved blockchain_decoded_payload.js")
EOF
```

---

## 6. jsrepo Payload Extraction from PCAP

```bash
# Get response body hex from C2 server
tshark -r "$PCAP" \
  -Y "ip.src==$C2_IP && http.response.code==200" \
  -T fields \
  -e frame.time_relative \
  -e http.file_data \
  | head -3 \
  | tee "$CASE/pcap_jsrepo_raw.txt"

# Decode and save to file
python3 << 'PYEOF'
# Paste hex from pcap_jsrepo_raw.txt
hex_data = "PASTE_HEX_HERE"
decoded  = bytes.fromhex(hex_data.strip()).decode('utf-8', errors='replace')

print(f"Payload size: {len(decoded):,} chars")
print(f"First 1000:\n{decoded[:1000]}")

with open('jsrepo_payload_sample.js', 'w') as f:
    f.write(decoded[:5000])
print("\nSaved jsrepo_payload_sample.js (first 5000 chars)")

with open('jsrepo_payload_full.js', 'w') as f:
    f.write(decoded)
print(f"Saved jsrepo_payload_full.js ({len(decoded):,} chars)")
PYEOF
```

---

## 7. ClickFix C2 Polling Extraction

```bash
# All JSONP polling requests
tshark -r "$PCAP" \
  -Y "ip.addr==$CLICKFIX_IP && http.request" \
  -T fields \
  -e frame.time_relative \
  -e http.host \
  -e http.request.uri \
  | head -20 \
  | tee "$CASE/pcap_c2_requests.txt"

# JSONP responses ({"executed":bool,...})
tshark -r "$PCAP" \
  -Y "ip.src==$CLICKFIX_IP && http.response.code==200" \
  -T fields \
  -e frame.time_relative \
  -e http.file_data \
  | head -20 \
  | python3 -c "
import sys
for line in sys.stdin:
    parts = line.strip().split('\t')
    if len(parts) >= 2 and parts[1]:
        try:
            decoded = bytes.fromhex(parts[1]).decode('utf-8', errors='replace')
            print(f'[T+{parts[0]}] {decoded[:200]}')
        except: pass
" | tee "$CASE/pcap_c2_responses.txt"
```

---

## 8. Kill Chain Timing

```bash
echo "=== KILL CHAIN TIMING ===" | tee "$CASE/pcap_timing.txt"

echo "[T+0] First HTTP request (victim browsing):" | tee -a "$CASE/pcap_timing.txt"
tshark -r "$PCAP" -Y "http.request" \
  -T fields -e frame.time_relative -e http.host | head -1 \
  | tee -a "$CASE/pcap_timing.txt"

echo "[Stage 2] Blockchain RPC call:" | tee -a "$CASE/pcap_timing.txt"
tshark -r "$PCAP" -Y "ip.addr==$RPC_IP && http.request.method==POST" \
  -T fields -e frame.time_relative | head -1 \
  | tee -a "$CASE/pcap_timing.txt"

echo "[Stage 4] First jsrepo beacon:" | tee -a "$CASE/pcap_timing.txt"
tshark -r "$PCAP" -Y "ip.addr==$C2_IP && http.request" \
  -T fields -e frame.time_relative | head -1 \
  | tee -a "$CASE/pcap_timing.txt"

echo "[Stage 5] First ClickFix poll:" | tee -a "$CASE/pcap_timing.txt"
tshark -r "$PCAP" -Y "ip.addr==$CLICKFIX_IP && http.request" \
  -T fields -e frame.time_relative | head -1 \
  | tee -a "$CASE/pcap_timing.txt"

echo "[Stage 5] ClickFix poll count:" | tee -a "$CASE/pcap_timing.txt"
tshark -r "$PCAP" -Y "ip.addr==$CLICKFIX_IP && http.request" 2>/dev/null \
  | wc -l | tee -a "$CASE/pcap_timing.txt"
```

---

## 9. Victim IP Identification

```bash
# Most frequent source IP in HTTP requests = victim
tshark -r "$PCAP" -Y "http.request" \
  -T fields -e ip.src \
  | sort | uniq -c | sort -rn | head -5
```

---

## 10. Troubleshooting Large PCAPs

**Timeouts on >50MB PCAPs:**
- Always filter by specific IP: `-Y "ip.addr==SPECIFIC_IP"`
- Use `| head -1` or `| head -3` to limit output rows
- For body content: extract first packet only
- Split if needed: `editcap -i 60 file.pcap split_output.pcap`

**Hex decode fails (colon format):**
```bash
echo "$HEX" | tr -d ':' | python3 -c "
import sys; d=sys.stdin.read().strip()
print(bytes.fromhex(d).decode('utf-8', errors='replace'))
"
```

**Empty http.file_data (chunked or compressed):**
```bash
# Check encoding first
tshark -r "$PCAP" -Y "ip.src==TARGET" \
  -T fields -e http.response.code -e http.content_length -e http.content_encoding
# Then use tcp.payload and handle chunked encoding manually
```

**HTTPS not decrypted:**
- Need TLS key log file or pre-master secrets
- Without decryption: IP/domain visible but payload invisible
- Filename ending `.decrypted.pcap` means TLS was already stripped
