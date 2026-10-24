# EtherHiding — ABI Decode Reference

The blockchain eth_call returns an ABI-encoded string. This documents every decode
step with Python scripts and edge cases from real investigations.

---

## ABI String Encoding — How It Works

Solidity ABI-encodes a `string` return as:

```
[offset_32_bytes][length_32_bytes][data_padded_to_32_byte_boundary]
```

Example — the string `"hello"`:
```
0000000000000000000000000000000000000000000000000000000000000020  ← offset = 32 (0x20)
0000000000000000000000000000000000000000000000000000000000000005  ← string length = 5 bytes
68656c6c6f000000000000000000000000000000000000000000000000000000  ← "hello" + zero padding
```

The `result` field in the eth_call JSON response has a `0x` prefix — strip it first.

---

## Standalone Decode Script

Use `scripts/abi_decode.py` — it handles:
- ABI string decode
- Double base64 decode (if outer layer is base64)
- C2 URL extraction from the JavaScript URL array
- Evasion technique detection
- Saving `blockchain_decoded_payload.js`

```bash
# Standard usage — reads blockchain_rpc_response.json in CWD
python3 /path/to/skill/scripts/abi_decode.py

# Specify a file
python3 /path/to/skill/scripts/abi_decode.py /case/folder/blockchain_rpc_response.json

# Pipe from curl
curl -s -X POST "https://bsc-testnet-rpc.publicnode.com" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xCONTRACT","data":"0x6d4ce63c"},"latest"],"id":1}' \
  | python3 /path/to/skill/scripts/abi_decode.py
```

---

## Quick One-Liner (for field work without copying scripts)

```python
python3 << 'EOF'
import json, base64, re

with open('blockchain_rpc_response.json') as f:
    r = json.load(f)

h = r['result'][2:]           # strip 0x
n = int(h[64:128], 16)        # string length
s = bytes.fromhex(h[128:128+n*2]).decode('utf-8', errors='replace')

# Double decode if base64
try:
    s2 = base64.b64decode(s + "==").decode('utf-8', errors='replace')
    s = s2
except: pass

print(s[:500])

# Extract C2 URLs
m = re.search(r'var n\s*=\s*\[([^\]]+)\]', s)
if m:
    for i, u in enumerate(re.findall(r'"([A-Za-z0-9+/=]+)"', m.group(1))):
        print(f"C2 [{i+1}]:", base64.b64decode(u + "==").decode('utf-8', errors='replace'))
EOF
```

---

## ABI Decode — Manual (no Python)

```bash
RESULT="0000000000000000000000000000000000000000000000000000000000000020..."

# Length is bytes 65–128 of result (hex chars 64–127)
LENGTH_HEX="${RESULT:64:64}"
LENGTH=$((16#$LENGTH_HEX))

# Data starts at char 128
STRING_HEX="${RESULT:128:$((LENGTH * 2))}"

# Decode hex to text
echo "$STRING_HEX" | xxd -r -p

# If base64, decode again
echo "$STRING_HEX" | xxd -r -p | base64 -d
```

---

## Edge Cases

### Edge Case 1: Result is a plain URL (not JavaScript)

Some campaigns skip the JS loader and store the C2 URL directly:
```
ABI decoded: https://malicious.com/payload.js
```
Action: The URL IS the C2. Fetch it directly — no base64 decode needed.

### Edge Case 2: Empty result (`"result":"0x"`)

Means the contract has no stored value:
- Campaign not yet active
- Contract was wiped after previous campaign
- Wrong contract address or wrong network

Action: Verify network and contract address. Try `eth_getStorageAt` on slot 0.

### Edge Case 3: Non-standard ABI encoding

Some contracts don't use standard string ABI. Try:
```python
# Raw decode (no ABI offset/length)
raw = bytes.fromhex(hex_result[2:]).decode('utf-8', errors='replace')
print("Raw decode:", raw[:200])
```

### Edge Case 4: Hex-encoded JavaScript (not base64)

```python
if re.match(r'^[0-9a-fA-F]+$', payload.strip()):
    decoded_hex = bytes.fromhex(payload.strip()).decode('utf-8', errors='replace')
    print("Hex-decoded:", decoded_hex[:200])
```

### Edge Case 5: Unknown function selector

Look up any 4-byte selector to find the function name:
```bash
curl -s "https://www.4byte.directory/api/v1/signatures/?hex_signature=0x2e64cec1"
# {"results": [{"text_signature": "retrieve()"}]}

# Common selectors:
# 0x6d4ce63c = get()       ← most common EtherHiding
# 0x2e64cec1 = retrieve()  ← variation
# 0x893d20e8 = getOwner()  ← rare variant
# 0xd46300fd = getMessage() ← seen in newer variants
```

---

## Worked Example — EtherHiding Investigation (BSC Testnet)

**eth_call POST body (replace CONTRACT-ADDRESS with your extracted value):**
```json
{"jsonrpc":"2.0","method":"eth_call","params":[
  {"to":"<CONTRACT-ADDRESS>","data":"0x6d4ce63c"},
  "latest"],"id":1}
```

**ABI structure of the result:**
```
Bytes 0-63:    offset = 32
Bytes 64-127:  string length = N bytes (varies per campaign, typically 1000–2000)
Bytes 128+:    N bytes of UTF-8 content (base64 string)
```

**Step 1 — ABI decode:** base64 string of ~N chars
**Step 2 — Base64 decode:** JavaScript function (the loader)
**Step 3 — C2 URL extraction:**
```
var n = [
  "<BASE64_PRIMARY_C2_URL>"    → https://<primary-c2-domain>/jsrepo?rnd=
  "<BASE64_BACKUP_C2_URL>"     → https://<backup-c2-domain>/jsrepo?rnd= (fallback)
  "<BASE64_BACKUP_C2_URL>"     → https://<backup-c2-domain>/jsrepo?rnd= (duplicate)
];
```

The script prints decoded C2 URLs automatically — record them as `domain` IOCs in MISP with `to_ids: true`.
