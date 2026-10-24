import { useEffect, useState } from 'react';
import { KeyRound, Save } from 'lucide-react';
import { C, HudFrame, ExecButton, CopyBtn, IndicatorBadge } from '../components/CyberHawkUI.jsx';
import { api } from '../api.js';

export default function SettingsPage() {
  const [s, setS] = useState(null);
  const [secretSet, setSecretSet] = useState({});
  const [branding, setBranding] = useState({});
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [newKey, setNewKey] = useState('');
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const r = await api.settings();
      const cfg = await api.config();
      const st = r.settings || {};
      setSecretSet(st.secret_set || {});
      delete st.secret_set;
      // Secrets come back masked; clear them so empty = "leave unchanged".
      ['misp_api_key', 'dashboard_token', 'api_key'].forEach((k) => { st[k] = ''; });
      setS(st);
      setBranding(cfg.branding || {});
    } catch (e) { setErr(String(e.message || e)); }
  };
  useEffect(() => { load(); }, []);

  const set = (k, v) => setS((p) => ({ ...p, [k]: v }));
  const setB = (k, v) => setBranding((p) => ({ ...p, [k]: v }));

  const save = async () => {
    setBusy(true); setMsg(''); setErr('');
    try {
      const values = { ...s };
      // Do not send empty secret fields (keeps existing value).
      ['misp_api_key', 'dashboard_token', 'api_key'].forEach((k) => { if (!values[k]) delete values[k]; });
      await api.saveSettings(values);
      await api.saveConfig(branding);
      setMsg('Settings saved.');
      await load();
    } catch (e) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  };

  const genKey = async () => {
    try { const r = await api.genApiKey(); setNewKey(r.api_key); setSecretSet((p) => ({ ...p, api_key: true })); }
    catch (e) { setErr(String(e.message || e)); }
  };

  if (!s) return <HudFrame title="Settings"><div style={muted}>Loading…</div></HudFrame>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxWidth: 820 }}>
      {msg && <IndicatorBadge type="pass" message={msg} />}
      {err && <IndicatorBadge type="warning" message={err} />}

      <HudFrame title="MISP Integration" subtitle="optional">
        <Field label="MISP Base URL"><Input v={s.misp_url} onChange={(v) => set('misp_url', v)} placeholder="https://misp.example.org" /></Field>
        <Field label={`MISP API Key ${secretSet.misp_api_key ? '(set — leave blank to keep)' : ''}`}>
          <Input type="password" v={s.misp_api_key} onChange={(v) => set('misp_api_key', v)} placeholder={secretSet.misp_api_key ? '••••••••' : 'paste key'} />
        </Field>
        <Field label="Verify MISP TLS"><Select v={s.misp_verify_tls} onChange={(v) => set('misp_verify_tls', v)} opts={['true', 'false']} /></Field>
      </HudFrame>

      <HudFrame title="Egress & Investigation">
        <Field label="Upstream proxy (blank = host residential IP — recommended)">
          <Input v={s.upstream_proxy} onChange={(v) => set('upstream_proxy', v)} placeholder="(blank)" />
        </Field>
        <Field label="Allow private/internal targets (SSRF guard)"><Select v={s.allow_private_targets} onChange={(v) => set('allow_private_targets', v)} opts={['false', 'true']} /></Field>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <Field label="Visit timeout (s)" w={160}><Input v={s.visit_timeout} onChange={(v) => set('visit_timeout', v)} /></Field>
          <Field label="Max attempts" w={160}><Input v={s.max_attempts} onChange={(v) => set('max_attempts', v)} /></Field>
          <Field label="Post-load dwell (s)" w={160}><Input v={s.post_load_dwell} onChange={(v) => set('post_load_dwell', v)} /></Field>
        </div>
      </HudFrame>

      <HudFrame title="Access Control">
        <Field label={`Dashboard token ${secretSet.dashboard_token ? '(set — blank to keep)' : ''}`}>
          <Input type="password" v={s.dashboard_token} onChange={(v) => set('dashboard_token', v)} placeholder={secretSet.dashboard_token ? '••••••••' : 'set a token'} />
        </Field>
        <Field label={`Appliance API key ${secretSet.api_key ? '(generated)' : '(none)'}`}>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <button onClick={genKey} style={btn}><KeyRound size={13} /> GENERATE NEW KEY</button>
            {newKey && <><code style={{ color: C.green, fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem' }}>{newKey}</code><CopyBtn text={newKey} /></>}
          </div>
          {newKey && <div style={{ color: C.orange, fontSize: '0.62rem', marginTop: '0.3rem', fontFamily: "'Share Tech Mono', monospace" }}>Copy now — it will not be shown again. Send it as the X-API-Key header.</div>}
        </Field>
      </HudFrame>

      <HudFrame title="Branding">
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <Field label="Platform name" w={240}><Input v={branding.platformName || ''} onChange={(v) => setB('platformName', v)} /></Field>
          <Field label="Tagline" w={300}><Input v={branding.tagline || ''} onChange={(v) => setB('tagline', v)} /></Field>
          <Field label="Status label" w={160}><Input v={branding.statusLabel || ''} onChange={(v) => setB('statusLabel', v)} /></Field>
          <Field label="Footer text" w={300}><Input v={branding.footerText || ''} onChange={(v) => setB('footerText', v)} /></Field>
        </div>
      </HudFrame>

      <div><ExecButton onClick={save} loading={busy} label="SAVE SETTINGS" loadingLabel="SAVING..." icon={Save} /></div>
    </div>
  );
}

const Field = ({ label, children, w }) => (
  <div style={{ marginBottom: '0.75rem', width: w || '100%' }}>
    <label style={{ display: 'block', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.64rem', color: '#557755', letterSpacing: '0.08em', marginBottom: '0.3rem' }}>{label}</label>
    {children}
  </div>
);
const Input = ({ v, onChange, type = 'text', placeholder }) => (
  <input className="cyber-input" type={type} value={v ?? ''} placeholder={placeholder} onChange={(e) => onChange(e.target.value)}
    style={{ width: '100%', padding: '0.5rem', background: '#000', border: `1px solid ${C.border}`, borderRadius: '0.35rem', color: C.green, fontFamily: "'Share Tech Mono', monospace", fontSize: '0.78rem' }} />
);
const Select = ({ v, onChange, opts }) => (
  <select value={v ?? ''} onChange={(e) => onChange(e.target.value)}
    style={{ width: '100%', padding: '0.5rem', background: '#000', border: `1px solid ${C.border}`, borderRadius: '0.35rem', color: C.green, fontFamily: "'Share Tech Mono', monospace", fontSize: '0.78rem' }}>
    {opts.map((o) => <option key={o} value={o}>{o}</option>)}
  </select>
);
const btn = { display: 'inline-flex', gap: '0.4rem', alignItems: 'center', background: 'transparent', border: `1px solid ${C.border}`, color: C.cyan, borderRadius: '0.35rem', padding: '0.4rem 0.8rem', cursor: 'pointer', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem' };
const muted = { color: '#557755', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.78rem' };
