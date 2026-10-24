import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw } from 'lucide-react';
import { C, HudFrame } from '../components/CyberHawkUI.jsx';
import { api } from '../api.js';

const VERDICT_COLOR = {
  COMPROMISED_ETHERHIDING: C.red,
  SUSPECTED_ETHERHIDING: C.orange,
  NO_ETHERHIDING_DETECTED: C.green,
  INCONCLUSIVE: C.yellow,
};

export default function Investigations() {
  const nav = useNavigate();
  const [rows, setRows] = useState([]);
  const [busy, setBusy] = useState(true);

  const load = async () => {
    setBusy(true);
    try { const r = await api.cases(); setRows(r.cases || []); } catch {} finally { setBusy(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <HudFrame title="Investigations" subtitle={`${rows.length} CASE(S)`}>
      <button onClick={load} style={{ marginBottom: '0.75rem', display: 'inline-flex', gap: '0.4rem', alignItems: 'center', background: 'transparent', border: `1px solid ${C.border}`, color: '#88aa88', borderRadius: '0.35rem', padding: '0.35rem 0.7rem', cursor: 'pointer', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem' }}>
        <RefreshCw size={12} className={busy ? 'spin-fast' : ''} /> REFRESH
      </button>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.72rem' }}>
          <thead>
            <tr style={{ color: C.gold, textAlign: 'left' }}>
              {['Case', 'Domain', 'Status', 'Verdict', 'Conf', 'C2', ''].map((h) => (
                <th key={h} style={{ padding: '0.4rem 0.6rem', borderBottom: `1px solid ${C.border}`, letterSpacing: '0.1em' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} style={{ color: '#aaccaa' }}>
                <td style={td}>{r.id}</td>
                <td style={td}>{r.domain}</td>
                <td style={td}>{r.status}</td>
                <td style={{ ...td, color: VERDICT_COLOR[r.verdict] || '#aaccaa', fontWeight: 700 }}>{r.verdict || '—'}</td>
                <td style={td}>{r.confidence != null ? `${r.confidence}%` : '—'}</td>
                <td style={td}>{r.c2_count || 0}</td>
                <td style={td}>
                  <button onClick={() => nav(`/report?id=${encodeURIComponent(r.id)}`)} style={openBtn}>REPORT</button>
                  <button onClick={() => nav(`/live?id=${encodeURIComponent(r.id)}`)} style={openBtn}>LIVE</button>
                </td>
              </tr>
            ))}
            {!rows.length && !busy && (
              <tr><td colSpan={7} style={{ ...td, color: '#557755' }}>No investigations yet. Submit a URL to begin.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </HudFrame>
  );
}

const td = { padding: '0.4rem 0.6rem', borderBottom: `1px solid ${C.border}`, whiteSpace: 'nowrap' };
const openBtn = { marginRight: '0.4rem', background: 'transparent', border: `1px solid ${C.border}`, color: C.cyan, borderRadius: '0.3rem', padding: '0.2rem 0.5rem', cursor: 'pointer', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.62rem' };
