import { useEffect, useRef, useState } from 'react';
import { C, HudFrame } from '../components/CyberHawkUI.jsx';
import { api } from '../api.js';

export default function MitmProxy({ caseId }) {
  const [flows, setFlows] = useState([]);
  const [meta, setMeta] = useState({ count: 0, blockchain_rpc: 0, domain: '' });
  const timer = useRef(null);

  useEffect(() => {
    if (!caseId) return;
    let alive = true;
    const poll = async () => {
      try {
        const r = await api.mitmFlows(caseId);
        if (!alive) return;
        setFlows(r.flows || []);
        setMeta({ count: r.count || 0, blockchain_rpc: r.blockchain_rpc || 0, domain: r.domain || '' });
      } catch {}
      timer.current = setTimeout(poll, 2000);
    };
    poll();
    return () => { alive = false; if (timer.current) clearTimeout(timer.current); };
  }, [caseId]);

  if (!caseId) return <HudFrame title="MITM Proxy"><div style={empty}>No case selected.</div></HudFrame>;

  return (
    <HudFrame title="MITM Proxy — Live Flows" subtitle={`${meta.count} FLOW(S) · ${meta.blockchain_rpc} RPC`}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.6rem', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.68rem', color: '#88aa88' }}>
        <span>◈ Every request the target makes is intercepted below (live).</span>
        {meta.blockchain_rpc > 0 && <span style={{ color: C.red, fontWeight: 700 }}>⚠ {meta.blockchain_rpc} BLOCKCHAIN RPC CALL(S) CAPTURED</span>}
      </div>
      <div style={{ background: '#000', border: `1px solid ${C.border}`, borderRadius: '0.5rem', height: '58vh', overflow: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.68rem' }}>
          <thead style={{ position: 'sticky', top: 0, background: '#050a05' }}>
            <tr style={{ color: C.gold, textAlign: 'left' }}>
              {['#', 'Method', 'Host', 'Path', 'Status', 'Size', 'Flags'].map((h) => (
                <th key={h} style={{ padding: '0.35rem 0.5rem', borderBottom: `1px solid ${C.border}` }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {flows.map((f, i) => {
              const rpc = f.is_blockchain_rpc;
              return (
                <tr key={i} style={{ color: rpc ? C.red : '#9ab89a', background: rpc ? 'rgba(255,0,64,0.07)' : 'transparent' }}>
                  <td style={td}>{i + 1}</td>
                  <td style={td}>{f.method || f.transport}</td>
                  <td style={td}>{f.host}</td>
                  <td style={{ ...td, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.path || f.url}</td>
                  <td style={td}>{f.status ?? '—'}</td>
                  <td style={td}>{f.resp_size ? `${f.resp_size}` : '—'}</td>
                  <td style={td}>
                    {rpc && <Flag c={C.red}>RPC:{(f.rpc_calls && f.rpc_calls[0] && f.rpc_calls[0].method) || 'eth'}</Flag>}
                    {f.is_jsrepo && <Flag c={C.orange}>jsrepo</Flag>}
                    {f.is_jsonp_c2 && <Flag c={C.orange}>clickfix</Flag>}
                    {f.looks_like_large_js && <Flag c={C.yellow}>bigjs</Flag>}
                  </td>
                </tr>
              );
            })}
            {!flows.length && <tr><td colSpan={7} style={{ ...td, color: '#335533' }}>Waiting for traffic…</td></tr>}
          </tbody>
        </table>
      </div>
    </HudFrame>
  );
}

const Flag = ({ c, children }) => (
  <span style={{ display: 'inline-block', marginRight: 4, padding: '0 4px', border: `1px solid ${c}`, color: c, borderRadius: 3, fontSize: '0.58rem' }}>{children}</span>
);
const td = { padding: '0.3rem 0.5rem', borderBottom: '1px solid rgba(0,255,65,0.06)', whiteSpace: 'nowrap' };
const empty = { color: '#557755', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.8rem' };
