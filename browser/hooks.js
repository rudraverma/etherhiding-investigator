/*
 * EtherHawk in-page instrumentation.
 * Injected via add_init_script BEFORE any page script runs, on every frame.
 * Captures the runtime behaviours that static analysis and network capture miss:
 *   - eval() / Function() bodies         (eval'd blockchain loaders)
 *   - atob() decodes                     (base64 C2 arrays)
 *   - fetch / XHR / WebSocket payloads   (JSON-RPC eth_call that rides a provider SDK)
 *   - navigator.serviceWorker.register   (EtherHiding persistence)
 * Everything is recorded into window.__eh. Observation only — nothing is blocked.
 * Wrappers spoof their own toString() so the page cannot trivially detect the hook.
 */
(function () {
  try {
    if (window.__eh_installed) return;
    window.__eh_installed = true;
    window.__eh = {
      evals: [],
      atobs: [],
      rpc: [],         // blockchain JSON-RPC observed in-page
      sws: [],         // service worker registrations
      net: [],         // fetch/xhr/ws targets (capped)
      errors: [],
    };

    var RPC_METHODS = ["eth_call", "eth_getstorageat", "eth_getcode", "eth_getlogs",
                       "eth_blocknumber", "eth_chainid", "net_version", "eth_sendrawtransaction"];
    var CONTRACT_RE = /0x[a-fA-F0-9]{40}/;

    function cap(s, n) {
      try { s = String(s); } catch (e) { return ""; }
      return s.length > n ? s.slice(0, n) : s;
    }

    function scanRpc(text, where) {
      try {
        if (!text || typeof text !== "string") return;
        var low = text.toLowerCase();
        var hit = false;
        for (var i = 0; i < RPC_METHODS.length; i++) {
          if (low.indexOf(RPC_METHODS[i]) !== -1) { hit = true; break; }
        }
        if (!hit) return;
        var entry = { where: where, ts: Date.now(), body: cap(text, 4000) };
        try {
          var parsed = JSON.parse(text);
          var calls = Array.isArray(parsed) ? parsed : [parsed];
          entry.methods = [];
          for (var j = 0; j < calls.length; j++) {
            var c = calls[j];
            if (c && c.method && RPC_METHODS.indexOf(String(c.method).toLowerCase()) !== -1) {
              var to = (c.params && c.params[0] && c.params[0].to) || "";
              var data = (c.params && c.params[0] && c.params[0].data) || "";
              entry.methods.push({ method: c.method, contract: to, selector: String(data).slice(0, 10) });
            }
          }
        } catch (e) {}
        window.__eh.rpc.push(entry);
      } catch (e) {}
    }

    function spoofToString(fn, original) {
      try {
        fn.toString = function () { return original; };
      } catch (e) {}
    }

    // ── eval ──────────────────────────────────────────────────────────────────
    var _eval = window.eval;
    window.eval = function (code) {
      try {
        var s = String(code);
        window.__eh.evals.push({
          code: cap(s, 4000), ts: Date.now(),
          eth_call: s.indexOf("eth_call") !== -1,
          has_atob: s.indexOf("atob") !== -1,
          has_web3: s.toLowerCase().indexOf("web3") !== -1,
          contract_like: CONTRACT_RE.test(s),
        });
        scanRpc(s, "eval");
      } catch (e) {}
      return _eval.apply(this, arguments);
    };
    spoofToString(window.eval, "function eval() { [native code] }");

    // ── Function constructor ──────────────────────────────────────────────────
    try {
      var _Function = window.Function;
      var FunctionProxy = function () {
        try {
          var body = arguments.length ? arguments[arguments.length - 1] : "";
          var s = String(body);
          window.__eh.evals.push({
            code: cap(s, 4000), ts: Date.now(), via: "Function",
            eth_call: s.indexOf("eth_call") !== -1,
            has_web3: s.toLowerCase().indexOf("web3") !== -1,
            contract_like: CONTRACT_RE.test(s),
          });
          scanRpc(s, "Function");
        } catch (e) {}
        return _Function.apply(this, arguments);
      };
      FunctionProxy.prototype = _Function.prototype;
      window.Function = FunctionProxy;
    } catch (e) {}

    // ── atob ──────────────────────────────────────────────────────────────────
    var _atob = window.atob;
    window.atob = function (str) {
      var result = _atob.call(this, str);
      try {
        if (result && result.length > 16) {
          var rs = result.toLowerCase();
          if (rs.indexOf("eth_call") !== -1 || rs.indexOf("web3") !== -1 ||
              rs.indexOf("http") !== -1 || rs.indexOf("0x") !== -1 ||
              rs.indexOf("jsrepo") !== -1) {
            window.__eh.atobs.push({
              in: cap(str, 200), out: cap(result, 4000), ts: Date.now(),
              eth_call: rs.indexOf("eth_call") !== -1,
            });
            scanRpc(result, "atob");
          }
        }
      } catch (e) {}
      return result;
    };
    spoofToString(window.atob, "function atob() { [native code] }");

    // ── fetch ─────────────────────────────────────────────────────────────────
    try {
      var _fetch = window.fetch;
      window.fetch = function (input, init) {
        try {
          var url = (typeof input === "string") ? input : (input && input.url) || "";
          if (window.__eh.net.length < 500) window.__eh.net.push({ k: "fetch", url: cap(url, 500), ts: Date.now() });
          var body = init && init.body;
          if (body && typeof body === "string") scanRpc(body, "fetch:" + cap(url, 200));
        } catch (e) {}
        return _fetch.apply(this, arguments);
      };
      spoofToString(window.fetch, "function fetch() { [native code] }");
    } catch (e) {}

    // ── XMLHttpRequest ────────────────────────────────────────────────────────
    try {
      var _open = XMLHttpRequest.prototype.open;
      var _send = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function (method, url) {
        try { this.__eh_url = url; } catch (e) {}
        return _open.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function (body) {
        try {
          if (window.__eh.net.length < 500) window.__eh.net.push({ k: "xhr", url: cap(this.__eh_url, 500), ts: Date.now() });
          if (body && typeof body === "string") scanRpc(body, "xhr:" + cap(this.__eh_url, 200));
        } catch (e) {}
        return _send.apply(this, arguments);
      };
    } catch (e) {}

    // ── WebSocket ─────────────────────────────────────────────────────────────
    try {
      var _WS = window.WebSocket;
      var WSProxy = function (url, protocols) {
        var ws = protocols ? new _WS(url, protocols) : new _WS(url);
        try {
          if (window.__eh.net.length < 500) window.__eh.net.push({ k: "ws", url: cap(url, 500), ts: Date.now() });
          var _wsend = ws.send;
          ws.send = function (data) {
            try { if (typeof data === "string") scanRpc(data, "ws:" + cap(url, 200)); } catch (e) {}
            return _wsend.apply(ws, arguments);
          };
        } catch (e) {}
        return ws;
      };
      WSProxy.prototype = _WS.prototype;
      WSProxy.CONNECTING = 0; WSProxy.OPEN = 1; WSProxy.CLOSING = 2; WSProxy.CLOSED = 3;
      window.WebSocket = WSProxy;
    } catch (e) {}

    // ── serviceWorker.register ────────────────────────────────────────────────
    try {
      if (navigator.serviceWorker && navigator.serviceWorker.register) {
        var _reg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
        navigator.serviceWorker.register = function (url, opts) {
          try { window.__eh.sws.push({ url: cap(url, 500), ts: Date.now() }); } catch (e) {}
          return _reg(url, opts);
        };
      }
    } catch (e) {}
  } catch (outer) {
    try { window.__eh && window.__eh.errors.push(String(outer)); } catch (e) {}
  }
})();
