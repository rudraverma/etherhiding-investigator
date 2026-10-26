import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Crosshair, ExternalLink, Activity } from 'lucide-react';
import { C, HudFrame, ExecButton, IndicatorBadge } from '../components/CyberHawkUI.jsx';
import { api } from '../api.js';

export default function Interactive() {
  const nav = useNavigate();
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [caseId, setCaseId] = useState('');
  const [kasmPort, setKasmPort] = useState('6901');
  const [live, setLive] = useState(null);
  const [busy, setBusy] = useState(false);
  const [finalizing, setFinalizing] = useState(false);
  const [err, setErr] = useState('');
  const timer = useRef(null);

  useEffect(() => { api.config().then((r) => setKasmPort(r.kasm_port || '6901')).catch(() => {}); }, []);
  useEffect(() => () => timer.current && clearTimeout(timer.current), []);

  const kasmUrl = `https://${window.location.hostname}:${kasmPort}/`;

  const start = async () => {
    if (!url.trim()) return;
    setBusy(true); setErr(''); setLive(null);
    try {
      const r = await api.interactiveStart(url.trim(), name.trim());
      setCaseId(r.case_id);
      poll(r.case_id);
    } catch (e) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  };

  const poll = async (id) => {
    try { const r = await api.interactiveStatus(id); setLive(r.live || null); } catch {}
    timer.current = setTimeout(() => poll(id), 2500);
  };

  const finalize = async () => {
    if (!caseId) return;
    setFinalizing(true); setErr('');
    try {
      await api.interactiveFinalize(caseId);
      nav(`/live?id=${encodeURIComponent(caseId)}`);
    } catch (e) { setErr(String(e.message || e)); setFinalizing(false); }
  };

  const sig = (k) => (live && live[k]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <HudFrame title="Interactive Detonation" subtitle="REAL CHROME · REAL TLS">
        <p style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.74rem', color: '#88aa88', lineHeight: 1.6, marginBottom: '0.9rem' }}>
          Open the target in a real analyst-driven Chrome (below). Browse it like a normal user —
          move the mouse, click, solve any CAPTCHA/QR, trigger the ClickFix lure. The browser keeps
          its genuine TLS fingerprint, so server-side cloaking can't tell it from a victim. Capture
          runs live; hit <b>Analyze</b> when the chain has fired.
        </p>
        <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: 1, minWidth: 260 }}>
            <label style={lbl}>TARGET URL</label>
            <input className="cyber-input" value={url} placeholder="https://suspected-site.example/"
              onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && start()} style={inp} />
          </div>
          <div style={{ width: 200 }}>
            <label style={lbl}>CASE NAME (optional)</label>
            <input className="cyber-input" value={name} onChange={(e) => setName(e.target.value)} style={inp} />
          </div>
          <ExecButton onClick={start} loading={busy} label="OPEN IN BROWSER" loadingLabel="OPENING..." icon={Crosshair} />
        </div>
        {err && <div style={{ marginTop: '0.75rem' }}><IndicatorBadge type="warning" message={err} /></div>}
      </HudFrame>

      {/* Live signals + controls */}
      {caseId && (
        <HudFrame title="Live Capture" subtitle={caseId} accentColor={C.cyan}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(180px,1fr))', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <Sig label="blockchain RPC seen" on={sig('rpc_seen')} />
            <Sig label="decisive RPC" on={sig('decisive_rpc')} />
            <Sig label="contract found" on={(live?.contracts || []).length > 0} />
            <Sig label="clickfix" on={sig('clickfix')} />
            <Sig label="flows" value={live?.flow_count ?? 0} />
          </div>
          {(live?.contracts || []).map((c, i) => (
            <div key={i} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem', color: C.red }}>contract: {c}</div>
          ))}
          <div style={{ marginTop: '0.9rem' }}>
            <ExecButton onClick={finalize} loading={finalizing} label="ANALYZE & GENERATE REPORT" loadingLabel="ANALYZING..." icon={Activity} color={C.red} />
          </div>
        </HudFrame>
      )}

      {/* noVNC desktop */}
      <HudFrame title="Analyst Browser (noVNC)" subtitle="login: kasm_user">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.66rem', color: '#88aa88' }}>
          <span>First time: open in a new tab once to accept the self-signed certificate, then it embeds here.</span>
          <a href={kasmUrl} target="_blank" rel="noopener" style={{ marginLeft: 'auto', display: 'inline-flex', gap: '0.3rem', alignItems: 'center', color: C.cyan }}>
            open browser in new tab <ExternalLink size={11} />
          </a>
        </div>
        <iframe title="analyst-browser" src={kasmUrl}
          style={{ width: '100%', height: '62vh', border: `1px solid ${C.border}`, borderRadius: '0.4rem', background: '#000' }} />
      </HudFrame>
    </div>
  );
}

function Sig({ label, on, value }) {
  const active = value !== undefined ? value > 0 : on;
  const col = value !== undefined ? C.cyan : (on ? C.red : '#446644');
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem', padding: '0.4rem 0.6rem', border: `1px solid ${active ? col : C.border}`, borderRadius: '0.35rem' }}>
      <span style={{ color: '#88aa88' }}>{label}</span>
      <span style={{ color: col, fontWeight: 700 }}>{value !== undefined ? value : String(!!on)}</span>
    </div>
  );
}

const lbl = { display: 'block', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.62rem', color: '#557755', letterSpacing: '0.1em', marginBottom: '0.3rem' };
const inp = { width: '100%', padding: '0.6rem', background: '#000', border: `1px solid ${C.border}`, borderRadius: '0.375rem', color: C.green, fontFamily: "'Share Tech Mono', monospace", fontSize: '0.82rem' };
