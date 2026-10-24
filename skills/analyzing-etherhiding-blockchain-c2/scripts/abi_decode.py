#!/usr/bin/env python3
"""
EtherHiding ABI Decode Script
CyberHawk Threat Intelligence — Rudra Verma

Decodes the eth_call result from an EtherHiding blockchain dead drop.
The contract stores a Base64-encoded JavaScript loader as an ABI-encoded string.

Usage:
    python3 abi_decode.py                          # reads blockchain_rpc_response.json
    python3 abi_decode.py <path/to/response.json>  # specify file path
    echo '{"result":"0x..."}' | python3 abi_decode.py  # from stdin (pipe)

Output:
    blockchain_decoded_payload.js  — full decoded loader JavaScript
    Prints: payload type, length, C2 URLs extracted
"""

import json
import base64
import re
import sys
import os


def abi_decode_string(hex_result: str) -> str:
    """Decode ABI-encoded string from eth_call result hex."""
    if hex_result.startswith(('0x', '0X')):
        hex_result = hex_result[2:]

    if len(hex_result) < 128:
        raise ValueError(
            f"Result too short ({len(hex_result)} hex chars) — "
            "expected at least 128 hex chars for ABI string"
        )

    # ABI string layout:
    # bytes 0-63:   offset pointer (always 32 = 0x20)
    # bytes 64-127: string byte length
    # bytes 128+:   UTF-8 string data
    offset   = int(hex_result[0:64],   16)
    str_len  = int(hex_result[64:128], 16)
    if str_len > 500_000:
        raise ValueError(f"str_len implausibly large ({str_len}) — likely malformed input")
    data_hex = hex_result[128 : 128 + str_len * 2]

    if len(data_hex) < str_len * 2:
        raise ValueError(
            f"Data truncated: expected {str_len * 2} hex chars, "
            f"got {len(data_hex)}"
        )

    return bytes.fromhex(data_hex).decode('utf-8', errors='replace')


def maybe_base64_decode(payload: str) -> tuple[str, bool]:
    """Try base64 decoding the payload. Returns (decoded, was_base64)."""
    stripped = payload.strip().replace('\n', '').replace('\r', '')
    if not re.match(r'^[A-Za-z0-9+/=]+$', stripped):
        return payload, False

    try:
        padding = 4 - len(stripped) % 4
        if padding != 4:
            stripped += '=' * padding
        decoded = base64.b64decode(stripped).decode('utf-8', errors='replace')
        return decoded, True
    except Exception:
        return payload, False


def extract_c2_urls(js_payload: str) -> list[dict]:
    """Extract and decode C2 URLs from EtherHiding JavaScript loader."""
    c2_urls = []

    # Match: var n=["BASE64_1","BASE64_2",...]
    n_match = re.search(r'var\s+n\s*=\s*\[([^\]]+)\]', js_payload)
    if not n_match:
        return c2_urls

    for i, b64 in enumerate(re.findall(r'"([A-Za-z0-9+/=]{10,})"', n_match.group(1))):
        try:
            padding = 4 - len(b64) % 4
            if padding != 4:
                b64 += '=' * padding
            url = base64.b64decode(b64).decode('utf-8', errors='replace')
            c2_urls.append({'index': i + 1, 'url': url, 'encoded': b64})
        except Exception as e:
            c2_urls.append({'index': i + 1, 'error': str(e), 'encoded': b64[:50]})

    return c2_urls


def main():
    # Determine input source
    if not sys.stdin.isatty():
        raw = sys.stdin.read()
        try:
            resp = json.loads(raw)
        except json.JSONDecodeError:
            # Raw hex passed directly
            hex_result = raw.strip()
            resp = {'result': hex_result}
    else:
        json_file = sys.argv[1] if len(sys.argv) > 1 else 'blockchain_rpc_response.json'
        if not os.path.exists(json_file):
            print(f"[-] File not found: {json_file}", file=sys.stderr)
            print("    Usage: python3 abi_decode.py [response.json]", file=sys.stderr)
            sys.exit(1)
        with open(json_file) as f:
            resp = json.load(f)

    hex_result = resp.get('result', '')
    if not hex_result:
        print("[-] No 'result' field in JSON", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Raw result: {len(hex_result)} hex chars")

    # Step 1: ABI decode
    try:
        payload = abi_decode_string(hex_result)
    except ValueError as e:
        print(f"[-] ABI decode failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] ABI decoded: {len(payload)} chars")
    print(f"    Preview: {payload[:200]!r}")

    # Step 2: Double decode if base64
    payload, was_b64 = maybe_base64_decode(payload)
    if was_b64:
        print(f"[+] Double decoded (was base64): {len(payload)} chars")
        print(f"    Preview: {payload[:300]!r}")

    # Step 3: Identify payload type
    is_js = any(kw in payload for kw in
                ['function', 'var ', 'XMLHttpRequest', 'document.', 'navigator.', 'atob('])
    print(f"[+] Payload type: {'JavaScript' if is_js else 'Unknown'}")

    # Step 4: Extract C2 URLs
    c2_urls = extract_c2_urls(payload)
    if c2_urls:
        print(f"[+] C2 URLs extracted: {len(c2_urls)}")
        for item in c2_urls:
            if 'url' in item:
                print(f"    [{item['index']}] {item['url']}")
            else:
                print(f"    [{item['index']}] DECODE ERROR: {item.get('error')} | {item['encoded']}")
    else:
        print("[-] No C2 URL array (var n=[...]) found")

    # Step 5: Check for evasion patterns
    evasion = []
    if re.search(r'bot|crawl|phantomjs|curl|wget|python', payload):
        evasion.append('bot-UA-evasion')
    if re.search(r'wp-admin|wp-login|xmlrpc', payload):
        evasion.append('WP-path-blocklist')
    if '.open(' in payload and ('!1' in payload or 'false' in payload):
        evasion.append('synchronous-XHR')
    if 'createElement' in payload and 'responseText' in payload:
        evasion.append('script-tag-eval')
    if evasion:
        print(f"[+] Evasion techniques detected: {', '.join(evasion)}")

    # Step 6: Save decoded payload — content is live malware JavaScript, handle accordingly
    out_file = 'blockchain_decoded_payload.js'
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(payload)
    print(f"[+] Saved: {out_file}")


if __name__ == '__main__':
    main()
