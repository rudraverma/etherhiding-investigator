/*
 * EtherHawk isolated sandbox
 * ============================================================================
 * POST /run { code, timeout_ms } executes a captured JS payload with INSTRUMENTED
 * globals to unwrap runtime-only obfuscation (atob + xor + new Function + script-tag
 * eval) that static beautification cannot reach, and records the facts that matter:
 *   - eth_calls            blockchain RPC the payload tries to issue
 *   - network_requests     fetch / XHR / WebSocket / script-src targets (C2 URLs)
 *   - clipboard            navigator.clipboard.writeText (ClickFix commands)
 *   - captured_code        inner eval / Function / script-tag bodies it constructs
 *
 * SECURITY MODEL — read carefully:
 *   node:vm is NOT a security boundary. The real isolation is the CONTAINER:
 *   this service runs on an `internal: true` Docker network (no route to the
 *   internet), read_only root fs, cap_drop ALL, no-new-privileges, non-root user.
 *   So even if hostile code escapes the vm context, it has nothing to reach and
 *   no capability to abuse. The instrumented fetch/XHR/WS NEVER actually send —
 *   they only record the URL the malware wanted to contact.
 */
'use strict';

const http = require('http');
const vm = require('vm');

const PORT = 3021;
const MAX_BODY = 12 * 1024 * 1024;
const HARD_CAP_MS = 8000;

const RPC_METHODS = ['eth_call', 'eth_getstorageat', 'eth_getcode', 'eth_getlogs',
  'eth_blocknumber', 'eth_chainid', 'net_version', 'eth_sendrawtransaction'];

function runPayload(code, timeoutMs) {
  const cap = {
    eth_calls: [], network_requests: [], clipboard: [],
    captured_code: [], service_workers: [], errors: [],
  };
  const push = (arr, v) => { if (arr.length < 300) arr.push(v); };

  const scanRpc = (text, where) => {
    try {
      if (typeof text !== 'string') return;
      const low = text.toLowerCase();
      if (!RPC_METHODS.some((m) => low.includes(m))) return;
      let methods;
      try {
        const parsed = JSON.parse(text);
        const calls = Array.isArray(parsed) ? parsed : [parsed];
        methods = calls.filter((c) => c && c.method).map((c) => ({
          method: c.method,
          contract: (c.params && c.params[0] && c.params[0].to) || '',
          selector: String((c.params && c.params[0] && c.params[0].data) || '').slice(0, 10),
        }));
      } catch (e) { methods = []; }
      push(cap.eth_calls, { where, methods, body: text.slice(0, 2000) });
    } catch (e) {}
  };

  const recordNet = (kind, url, body) => {
    push(cap.network_requests, { kind, url: String(url).slice(0, 500) });
    if (body) scanRpc(typeof body === 'string' ? body : '', kind + ':' + String(url).slice(0, 120));
    scanRpc(String(url), kind + '-url');
  };

  // Instrumented globals
  const sandbox = {};
  const ctx = vm.createContext(sandbox);
  const runInner = (c) => { try { return vm.runInContext(c, ctx, { timeout: 1000 }); } catch (e) { push(cap.errors, 'inner:' + String(e).slice(0, 200)); } };

  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  sandbox.window = sandbox;
  sandbox.atob = (s) => Buffer.from(String(s), 'base64').toString('binary');
  sandbox.btoa = (s) => Buffer.from(String(s), 'binary').toString('base64');
  sandbox.TextDecoder = TextDecoder;
  sandbox.TextEncoder = TextEncoder;
  sandbox.console = { log() {}, warn() {}, error() {}, info() {}, debug() {} };

  sandbox.eval = (c) => { push(cap.captured_code, String(c).slice(0, 4000)); scanRpc(String(c), 'eval'); return runInner(String(c)); };
  const FunctionProxy = function (...args) {
    const bodyStr = args.length ? String(args[args.length - 1]) : '';
    push(cap.captured_code, bodyStr.slice(0, 4000));
    scanRpc(bodyStr, 'Function');
    return function () { return runInner(bodyStr); };
  };
  FunctionProxy.prototype = Function.prototype;
  sandbox.Function = FunctionProxy;

  sandbox.fetch = (url, init) => { recordNet('fetch', url, init && init.body); return Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve(''), json: () => Promise.resolve({}) }); };

  sandbox.XMLHttpRequest = function () {
    return {
      open(m, u) { this._u = u; }, setRequestHeader() {},
      send(b) { recordNet('xhr', this._u, b); if (typeof this.onload === 'function') { try { this.onload(); } catch (e) {} } },
      get responseText() { return ''; }, get status() { return 200; },
    };
  };
  sandbox.WebSocket = function (url) {
    recordNet('ws', url);
    return { send: (d) => scanRpc(String(d), 'ws-send'), close() {}, addEventListener() {} };
  };

  const makeEl = (tag) => {
    const el = { tagName: String(tag).toUpperCase(), _attrs: {},
      setAttribute(k, v) { this._attrs[k] = v; if (k === 'src') recordNet('script-src', v); },
      set src(v) { recordNet('script-src', v); }, get src() { return this._attrs.src || ''; },
      set text(v) { push(cap.captured_code, String(v).slice(0, 4000)); scanRpc(String(v), 'script.text'); runInner(String(v)); },
      set textContent(v) { this.text = v; },
      set innerHTML(v) {}, appendChild() {}, setAttributeNS() {}, addEventListener() {} };
    return el;
  };
  sandbox.document = {
    createElement: makeEl, createElementNS: (_ns, t) => makeEl(t),
    head: { appendChild(el) { if (el && el._attrs && el._attrs.src) recordNet('script-src', el._attrs.src); } },
    body: { appendChild() {} }, getElementsByTagName: () => [], querySelector: () => null,
    querySelectorAll: () => [], addEventListener() {}, cookie: '', referrer: '',
    location: { href: 'https://victim.example/', hostname: 'victim.example' },
  };
  sandbox.location = sandbox.document.location;
  sandbox.navigator = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    platform: 'Win32', webdriver: undefined, language: 'en-US', languages: ['en-US', 'en'],
    clipboard: { writeText: (t) => { push(cap.clipboard, String(t).slice(0, 2000)); return Promise.resolve(); } },
    serviceWorker: { register: (u) => { push(cap.service_workers, String(u).slice(0, 500)); return Promise.resolve({}); } },
  };
  const store = () => { const m = {}; return { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; }, clear: () => {} }; };
  sandbox.localStorage = store();
  sandbox.sessionStorage = store();
  sandbox.screen = { width: 1920, height: 1080, colorDepth: 24 };
  sandbox.setTimeout = (fn) => { if (typeof fn === 'function') { try { fn(); } catch (e) {} } return 0; };
  sandbox.setInterval = () => 0;
  sandbox.clearTimeout = () => {}; sandbox.clearInterval = () => {};
  sandbox.addEventListener = () => {};

  try {
    vm.runInContext(code, ctx, { timeout: Math.min(timeoutMs || HARD_CAP_MS, HARD_CAP_MS) });
  } catch (e) {
    push(cap.errors, 'top:' + String(e).slice(0, 300));
  }
  return cap;
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ ok: true })); return;
  }
  if (req.method !== 'POST' || !req.url.startsWith('/run')) { res.writeHead(404); res.end('not found'); return; }

  let size = 0; const chunks = [];
  req.on('data', (c) => { size += c.length; if (size > MAX_BODY) { res.writeHead(413); res.end('too large'); req.destroy(); return; } chunks.push(c); });
  req.on('end', () => {
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch (e) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'invalid json' })); return; }
    const result = runPayload(typeof body.code === 'string' ? body.code : '', Number(body.timeout_ms) || HARD_CAP_MS);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  });
  req.on('error', () => { try { res.writeHead(400); res.end('bad'); } catch (e) {} });
});

server.listen(PORT, '0.0.0.0', () => console.log(`etherhawk-sandbox listening on ${PORT}`));
