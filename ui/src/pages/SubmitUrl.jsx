import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Crosshair } from 'lucide-react';
import { C, HudFrame, ExecButton, IndicatorBadge } from '../components/CyberHawkUI.jsx';
import { api } from '../api.js';

export default function SubmitUrl() {
  const nav = useNavigate();
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const go = async () => {
    if (!url.trim()) return;
    setBusy(true); setErr('');
    try {
      const r = await api.submit(url.trim(), name.trim());
      nav(`/live?id=${encodeURIComponent(r.case_id)}`);
    } catch (e) {
      setErr(String(e.message || e));
    } finally { setBusy(false); }
  };

  return (
    <div style={{ maxWidth: 820 }}>
      <HudFrame title="Submit URL for Investigation" subtitle="DETERMINISTIC PIPELINE">
        <p style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.75rem', color: '#88aa88', lineHeight: 1.6, marginBottom: '1rem' }}>
          The appliance visits the target from this host's residential public IP wearing a coherent
          laptop fingerprint, forces the EtherHiding chain to fire past the stage-1 gate, and captures
          any blockchain RPC call via MITM + in-page hooks. Verdict is rule-based — no AI.
        </p>
        <label style={lbl}>TARGET URL</label>
        <input className="cyber-input" value={url} autoFocus placeholder="https://suspected-compromised-site.example/"
          onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && go()} style={inp} />
        <label style={lbl}>CASE NAME <span style={{ opacity: 0.5 }}>(optional)</span></label>
        <input className="cyber-input" value={name} placeholder="auto from domain"
          onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && go()} style={inp} />
        <div style={{ marginTop: '1.1rem' }}>
          <ExecButton onClick={go} loading={busy} label="LAUNCH INVESTIGATION" loadingLabel="LAUNCHING..." icon={Crosshair} />
        </div>
        {err && <div style={{ marginTop: '1rem' }}><IndicatorBadge type="warning" message={err} /></div>}
      </HudFrame>
    </div>
  );
}

const lbl = { display: 'block', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.65rem', color: '#557755', letterSpacing: '0.1em', marginTop: '0.9rem', marginBottom: '0.35rem' };
const inp = { width: '100%', padding: '0.65rem', background: '#000', border: `1px solid ${C.border}`, borderRadius: '0.375rem', color: C.green, fontFamily: "'Share Tech Mono', monospace", fontSize: '0.85rem' };
