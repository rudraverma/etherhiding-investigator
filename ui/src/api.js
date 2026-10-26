// EtherHawk API client. Same-origin (nginx proxies /api). The dashboard token is
// kept in localStorage and sent as a Bearer header on every request â€” including the
// SSE stream, which we consume via fetch + ReadableStream so the header is preserved
// (EventSource cannot set headers, and we refuse to put the token in a URL).

const TOKEN_KEY = 'eh_token';

export const getToken = () => { try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; } };
export const setToken = (t) => { try { localStorage.setItem(TOKEN_KEY, t || ''); } catch {} };
export const clearToken = () => { try { localStorage.removeItem(TOKEN_KEY); } catch {} };

function authHeaders(extra = {}) {
  const h = { ...extra };
  const t = getToken();
  if (t) h['Authorization'] = `Bearer ${t}`;
  return h;
}

export class AuthError extends Error {}

async function req(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: authHeaders(opts.headers || {}) });
  if (res.status === 401) throw new AuthError('unauthorized');
  if (!res.ok) {
    let msg = `${res.status}`;
    try { const j = await res.json(); msg = j.detail || j.error || msg; } catch {}
    throw new Error(msg);
  }
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

export const api = {
  health: () => req('/api/health'),
  checkAuth: () => req('/api/settings'),
  submit: (url, case_name) => req('/api/investigate', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, case_name }),
  }),
  status: (id) => req(`/api/investigate/status?id=${encodeURIComponent(id)}`),
  interactiveStart: (url, case_name) => req('/api/interactive/start', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, case_name }),
  }),
  interactiveStatus: (id) => req(`/api/interactive/status?id=${encodeURIComponent(id)}`),
  interactiveFinalize: (id) => req(`/api/interactive/finalize?id=${encodeURIComponent(id)}`, { method: 'POST' }),
  interactiveAbort: () => req('/api/interactive/abort', { method: 'POST' }),
  cases: () => req('/api/cases'),
  case: (id) => req(`/api/case?id=${encodeURIComponent(id)}`),
  tree: (id) => req(`/api/case/tree?id=${encodeURIComponent(id)}`),
  mitmFlows: (id) => req(`/api/mitm/flows?id=${encodeURIComponent(id)}`),
  settings: () => req('/api/settings'),
  saveSettings: (values) => req('/api/settings', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ values }),
  }),
  genApiKey: () => req('/api/settings/apikey', { method: 'POST' }),
  config: () => req('/api/config'),
  saveConfig: (branding) => req('/api/config', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ branding }),
  }),
};

// Fetch an artifact's bytes (authed) â€” caller decides text vs blob.
export async function fetchArtifactText(id, path) {
  const res = await fetch(`/api/case/artifact?id=${encodeURIComponent(id)}&path=${encodeURIComponent(path)}`, { headers: authHeaders() });
  if (res.status === 401) throw new AuthError('unauthorized');
  if (!res.ok) throw new Error(`${res.status}`);
  return res.text();
}
export async function fetchArtifactBlobUrl(id, path) {
  const res = await fetch(`/api/case/artifact?id=${encodeURIComponent(id)}&path=${encodeURIComponent(path)}`, { headers: authHeaders() });
  if (res.status === 401) throw new AuthError('unauthorized');
  if (!res.ok) throw new Error(`${res.status}`);
  const blob = await res.blob();
  return URL.createObjectURL(blob);
}

// Stream the live investigation log via fetch + reader (keeps the auth header).
export async function streamLogs(id, onEvent, onDone, signal) {
  const res = await fetch(`/api/investigate/stream?id=${encodeURIComponent(id)}`, { headers: authHeaders(), signal });
  if (res.status === 401) throw new AuthError('unauthorized');
  if (!res.ok || !res.body) throw new Error(`stream ${res.status}`);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const parts = buf.split('\n\n');
    buf = parts.pop() || '';
    for (const part of parts) {
      const line = part.trim();
      if (!line.startsWith('data:')) continue;
      try {
        const obj = JSON.parse(line.slice(5).trim());
        if (obj.type === 'done') { onDone && onDone(obj); return; }
        onEvent && onEvent(obj);
      } catch {}
    }
  }
  onDone && onDone({ status: 'closed' });
}
