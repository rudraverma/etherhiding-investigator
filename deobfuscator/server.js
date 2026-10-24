/*
 * EtherHawk deobfuscator
 * ============================================================================
 * Stateless HTTP service. POST /deobfuscate { code, label } returns a beautified
 * copy of a captured payload, a best-effort language guess, extracted IOCs, and a
 * `needs_sandbox` flag when the payload uses runtime-only obfuscation that static
 * beautification cannot unwrap (atob + xor + new Function chains).
 *
 * This service NEVER executes the input. It only reformats text and runs regexes.
 * Dynamic unwrapping is delegated to the network-isolated etherhawk-sandbox.
 */
'use strict';

const http = require('http');
const beautify = require('js-beautify');

const PORT = 3020;
const MAX_BODY = 12 * 1024 * 1024; // 12 MB cap on a single payload

// ── IOC extraction (deterministic regex) ────────────────────────────────────
const RE_URL = /https?:\/\/[^\s"'`<>\\]{6,500}/g;
const RE_IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const RE_CONTRACT = /0x[a-fA-F0-9]{40}\b/g;
const RE_SELECTOR = /\b0x[a-fA-F0-9]{8}\b/g;
const RE_DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|ru|cn|xyz|online|info|biz|app|dev|site|shop|top|live|click|fun)\b/gi;

// RPC/CDN noise we don't want to flag as attacker infrastructure.
const BENIGN = ['jquery', 'bootstrap', 'googleapis', 'gstatic', 'cdnjs', 'cloudflare-eth',
  'jsdelivr', 'unpkg', 'fontawesome', 'google-analytics', 'w3.org', 'schema.org',
  'publicnode', 'infura', 'alchemy', 'ankr', 'polygon-rpc', 'bsc-dataseed', 'llamarpc'];

function uniq(arr) { return Array.from(new Set(arr)); }

function extractIocs(code) {
  const urls = uniq((code.match(RE_URL) || []).map((u) => u.replace(/[.,;)'"]+$/, '')));
  const ips = uniq(code.match(RE_IPV4) || []).filter((ip) => {
    return !(ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('0.') ||
             ip.startsWith('192.168.') || ip.startsWith('169.254.') ||
             /^172\.(1[6-9]|2\d|3[01])\./.test(ip));
  });
  const contracts = uniq(code.match(RE_CONTRACT) || []);
  const selectors = uniq(code.match(RE_SELECTOR) || []).filter((s) => !contracts.includes(s));
  const domains = uniq((code.match(RE_DOMAIN) || []).map((d) => d.toLowerCase()))
    .filter((d) => !BENIGN.some((b) => d.includes(b)));
  return { urls, ips, contracts, selectors, domains };
}

function guessLanguage(code) {
  const ps = /\b(iex|invoke-expression|downloadstring|downloadfile|\$env:|\[char\]|-bxor|frombase64string|start-process|new-object\s+net\.webclient)\b/i;
  if (ps.test(code)) return 'powershell';
  return 'javascript';
}

function needsSandbox(code) {
  // Runtime-only layers: base64 + xor/charcode + dynamic code construction.
  const dynExec = /\bnew\s+Function\s*\(|\beval\s*\(|\[['"]constructor['"]\]|\bFunction\s*\(['"`]/.test(code);
  const decode = /\batob\s*\(|fromCharCode|\bunescape\s*\(|String\.fromCharCode|TextDecoder/.test(code);
  const transform = /\^|\bxor\b|>>>|<<|\.reduce\(/.test(code);
  return (dynExec && decode) || (decode && transform && dynExec);
}

function deobfuscate(code, language) {
  try {
    if (language === 'powershell') {
      // Light normalisation only — js-beautify would corrupt PowerShell.
      return code.replace(/;\s*/g, ';\n').replace(/\s*\|\s*/g, ' |\n  ');
    }
    return beautify.js(code, { indent_size: 2, max_preserve_newlines: 2, wrap_line_length: 0 });
  } catch (e) {
    return code;
  }
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  if (req.method !== 'POST' || !req.url.startsWith('/deobfuscate')) {
    res.writeHead(404); res.end('not found'); return;
  }

  let size = 0;
  const chunks = [];
  req.on('data', (c) => {
    size += c.length;
    if (size > MAX_BODY) { res.writeHead(413); res.end('payload too large'); req.destroy(); return; }
    chunks.push(c);
  });
  req.on('end', () => {
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch (e) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'invalid json' })); return; }

    const code = typeof body.code === 'string' ? body.code : '';
    const language = guessLanguage(code);
    const result = {
      label: body.label || '',
      language,
      beautified: deobfuscate(code, language),
      iocs: extractIocs(code),
      needs_sandbox: needsSandbox(code),
      input_bytes: code.length,
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  });
  req.on('error', () => { try { res.writeHead(400); res.end('bad request'); } catch (e) {} });
});

server.listen(PORT, '0.0.0.0', () => console.log(`etherhawk-deobf listening on ${PORT}`));
