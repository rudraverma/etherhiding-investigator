import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { C, HudFrame, SkullLoader } from '../components/CyberHawkUI.jsx';
import { streamLogs } from '../api.js';

const LEVEL_COLOR = {
  info: '#88aa88', phase: C.cyan, warn: C.orange, error: C.red,
  critical: C.red, good: C.green, skill: C.purple, sep: '#223322',
};

export default function LiveInvestigation({ caseId }) {
  const nav = useNavigate();
  const [lines, setLines] = useState([]);
  const [running, setRunning] = useState(true);
  const [phase, setPhase] = useState('INITIALISING');
  const boxRef = useRef(null);

  useEffect(() => {
    if (!caseId) return;
    const ctrl = new AbortController();
    setLines([]); setRunning(true);
    streamLogs(caseId,
      (ev) => {
        setLines((prev) => [...prev, ev]);
        if (ev.level === 'phase') setPhase((ev.msg || '').replace(/[─ ]/g, '').toUpperCase() || 'WORKING');
      },
      () => setRunning(false),
      ctrl.signal,
    ).catch(() => setRunning(false));
    return () => ctrl.abort();
  }, [caseId]);

  useEffect(() => { if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight; }, [lines]);

  if (!caseId) return <HudFrame title="Live Investigation"><Empty /></HudFrame>;

  return (
    <HudFrame title="Live Investigation" subtitle={caseId}>
      <SkullLoader active={running} phaseText={phase} />
      <div ref={boxRef} style={{ marginTop: '1rem', background: '#000', border: `1px solid ${C.border}`, borderRadius: '0.5rem', padding: '0.75rem', height: '52vh', overflow: 'auto', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.72rem', lineHeight: 1.6 }}>
        {lines.map((l, i) => (
          <div key={i} style={{ color: LEVEL_COLOR[l.level] || '#88aa88', whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontWeight: l.level === 'critical' ? 700 : 400 }}>
            <span style={{ color: '#335533' }}>›</span> {l.msg}
          </div>
        ))}
        {!lines.length && <div style={{ color: '#335533' }}>Connecting to investigation stream…</div>}
      </div>
      {!running && (
        <div style={{ marginTop: '1rem', display: 'flex', gap: '0.6rem' }}>
          <button onClick={() => nav(`/report?id=${encodeURIComponent(caseId)}`)} style={btn}>VIEW REPORT →</button>
          <button onClick={() => nav(`/evidence?id=${encodeURIComponent(caseId)}`)} style={btn}>EVIDENCE</button>
          <button onClick={() => nav(`/mitm?id=${encodeURIComponent(caseId)}`)} style={btn}>MITM FLOWS</button>
        </div>
      )}
    </HudFrame>
  );
}

const Empty = () => <div style={{ color: '#557755', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.8rem' }}>No case selected. Submit a URL or pick one from Investigations.</div>;
const btn = { background: 'transparent', border: `1px solid ${C.border}`, color: C.cyan, borderRadius: '0.35rem', padding: '0.45rem 0.9rem', cursor: 'pointer', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem' };
