import { useEffect, useState } from 'react';
import { C, HudFrame, CopyBtn, IndicatorBadge } from '../components/CyberHawkUI.jsx';
import { api } from '../api.js';

const VC = {
  COMPROMISED_ETHERHIDING: { c: C.red, label: '☠ COMPROMISED — ETHERHIDING' },
  SUSPECTED_ETHERHIDING: { c: C.orange, label: '⚠ SUSPECTED — ETHERHIDING' },
  NO_ETHERHIDING_DETECTED: { c: C.green, label: '✓ NO ETHERHIDING DETECTED' },
  INCONCLUSIVE: { c: C.yellow, label: '◈ INCONCLUSIVE' },
};

function defang(s) { return (s || '').replace(/https?:\/\//g, (m) => m.replace('http', 'hxxp')).replace(/\./g, '[.]'); }

export default function Report({ caseId }) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    if (!caseId) return;
    setData(null); setErr('');
    api.case(caseId).then(setData).catch((e) => setErr(String(e.message || e)));
  }, [caseId]);

  if (!caseId) return <HudFrame title="Report"><div style={muted}>No case selected.</div></HudFrame>;
  if (err) return <HudFrame title="Report"><IndicatorBadge type="warning" message={err} /></HudFrame>;
  if (!data) return <HudFrame title="Report"><div style={muted}>Loading…</div></HudFrame>;

  const r = data.report;
  const row = data.case || {};
  if (!r) {
    return <HudFrame title="Report" subtitle={caseId}>
      <div style={muted}>Report not generated yet (status: {row.status || 'unknown'}). Check the Live tab.</div>
    </HudFrame>;
  }
  const v = VC[r.verdict] || { c: C.yellow, label: r.verdict };
  const bc = r.blockchain || {};
  const c2 = r.c2_chain || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxWidth: 1000 }}>
      {/* Verdict banner */}
      <div style={{ border: `1px solid ${v.c}`, background: `${v.c}11`, borderRadius: '0.75rem', padding: '1.25rem', position: 'relative' }}>
        <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: '1.4rem', color: v.c, letterSpacing: '0.06em', textShadow: `0 0 16px ${v.c}` }}>{v.label}</div>
        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.8rem', color: '#cde', marginTop: '0.5rem' }}>Confidence: <b style={{ color: v.c }}>{r.confidence}%</b> · {r.victim_domain}</div>
        <p style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.78rem', color: '#9ab89a', marginTop: '0.6rem', lineHeight: 1.6 }}>{r.summary}</p>
        {r.misp && r.misp.event_url && <p style={{ marginTop: '0.5rem', fontSize: '0.72rem' }}><a href={r.misp.event_url} target="_blank" rel="noopener">MISP event →</a></p>}
      </div>

      {/* Signals */}
      <HudFrame title="Detection Signals">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(230px,1fr))', gap: '0.5rem' }}>
          {Object.entries(r.signals || {}).map(([k, val]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem', padding: '0.4rem 0.6rem', border: `1px solid ${C.border}`, borderRadius: '0.35rem' }}>
              <span style={{ color: '#88aa88' }}>{k.replace(/_/g, ' ')}</span>
              <span style={{ color: val ? (typeof val === 'number' ? C.cyan : C.red) : '#446644', fontWeight: 700 }}>{String(val)}</span>
            </div>
          ))}
        </div>
      </HudFrame>

      {/* Blockchain */}
      <HudFrame title="Blockchain Dead Drop">
        <Row k="Contract" v={bc.contract} copy />
        <Row k="Function selector" v={bc.selector} />
        <Row k="RPC endpoint" v={bc.rpc_url} />
        <Row k="On-chain verified" v={String(bc.on_chain_verified)} />
        {!!(bc.c2_urls || []).length && (
          <div style={{ marginTop: '0.6rem' }}>
            <div style={{ color: C.gold, fontFamily: "'Share Tech Mono', monospace", fontSize: '0.65rem', letterSpacing: '0.1em', marginBottom: '0.3rem' }}>C2 URLs DECODED</div>
            {bc.c2_urls.map((u, i) => <div key={i} style={mono}>{defang(u)}</div>)}
          </div>
        )}
      </HudFrame>

      {/* C2 chain */}
      <HudFrame title="C2 / Relay / Payload Chain" subtitle={c2.clickfix_detected ? 'CLICKFIX DETECTED' : ''}>
        {c2.clickfix_detected && <div style={{ marginBottom: '0.6rem' }}><IndicatorBadge type="critical" message="ClickFix social-engineering stage detected (Win+R / clipboard / PowerShell)." /></div>}
        <Row k="Relay URLs" v={(c2.relay_urls || []).length} />
        <Row k="Payload URLs" v={(c2.payload_urls || []).length} />
        {(c2.stages || []).map((s) => (
          <div key={s.stage} style={{ ...mono, color: s.clickfix ? C.red : '#9ab89a' }}>
            stage {s.stage}: {defang(s.url)} ({s.size}B, {s.language}{s.clickfix ? ', CLICKFIX' : ''})
          </div>
        ))}
        {!(c2.stages || []).length && <div style={muted}>No C2 chain reconstructed.</div>}
      </HudFrame>

      {/* IOCs */}
      <HudFrame title="IOCs" subtitle={`${(data.iocs || []).length} ITEM(S)`}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem' }}>
            <thead><tr style={{ color: C.gold, textAlign: 'left' }}>{['Type', 'Value (defanged)', 'to_ids', 'Note'].map((h) => <th key={h} style={th}>{h}</th>)}</tr></thead>
            <tbody>
              {(data.iocs || []).map((i, idx) => (
                <tr key={idx} style={{ color: i.to_ids ? C.red : '#9ab89a' }}>
                  <td style={td}>{i.type}</td>
                  <td style={td}>{i.type === 'url' || i.type === 'domain' ? defang(i.value) : i.value}</td>
                  <td style={td}>{i.to_ids ? 'BLOCK' : 'no'}</td>
                  <td style={td}>{i.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </HudFrame>
    </div>
  );
}

function Row({ k, v, copy }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.74rem', padding: '0.25rem 0' }}>
      <span style={{ color: '#88aa88', minWidth: 150 }}>{k}</span>
      <span style={{ color: C.green, wordBreak: 'break-all' }}>{v || '—'}</span>
      {copy && v ? <CopyBtn text={v} /> : null}
    </div>
  );
}

const muted = { color: '#557755', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.78rem' };
const mono = { fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem', color: '#9ab89a', wordBreak: 'break-all', padding: '0.1rem 0' };
const th = { padding: '0.35rem 0.5rem', borderBottom: `1px solid ${C.border}` };
const td = { padding: '0.35rem 0.5rem', borderBottom: '1px solid rgba(0,255,65,0.06)', verticalAlign: 'top' };
