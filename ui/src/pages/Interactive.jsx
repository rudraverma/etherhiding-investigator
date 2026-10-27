import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Crosshair, Activity, Network, StopCircle } from 'lucide-react';
import { C, HudFrame, ExecButton, IndicatorBadge } from '../components/CyberHawkUI.jsx';
import { api } from '../api.js';

export default function Interactive() {
  const nav = useNavigate();
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [caseId, setCaseId] = useState('');
  const [live, setLive] = useState(null);
  const [busy, setBusy] = useState(false);
  const [finalizing, setFinalizing] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [err, setErr] = useState('');
  const [conflict, setConflict] = useState(false);
  const [flows, setFlows] = useState([]);
  const [flowsErr, setFlowsErr] = useState('');
  const timer = useRef(null);
  const flowTimer = useRef(null);

  useEffect(() => () => {
    timer.current && clearTimeout(timer.current);
    flowTimer.current && clearTimeout(flowTimer.current);
  }, []);

  // Live flow polling while session is active.
  useEffect(() => {
    if (!caseId) return;
    let active = true;
    const pollFlows = async () => {
      try {
        const r = await api.mitmFlows(caseId);
        if (active) setFlows(r.flows || []);
      } catch (e) {
        if (active) setFlowsErr(String(e.message || e));
      }
      if (active) flowTimer.current = setTimeout(pollFlows, 3000);
    };
    pollFlows();
    return () => { active = false; flowTimer.current && clearTimeout(flowTimer.current); };
  }, [caseId]);

  // resize=remote: kasmweb resizes the VNC desktop to match the iframe viewport --
  // no overflow, no horizontal scrollbar, no cut-off. Works with kasmweb's custom
  // bundle (unlike resize=scale which throws a lastActiveAt TypeError).
  // quality=4: sharp enough to read website text, ~4x smaller frames than quality=9.
  // compression=7: more zlib on LAN costs negligible CPU but cuts WebSocket payload.
  const kasmUrl = '/novnc/?password=changeme-kasm&autoconnect=1&quality=4&compression=7&resize=remote';

  const clearTimers = () => {
    timer.current && clearTimeout(timer.current);
    flowTimer.current && clearTimeout(flowTimer.current);
  };

  const resetSession = () => {
    clearTimers();
    setCaseId(''); setLive(null); setFlows([]); setFlowsErr(''); setConflict(false);
  };

  const start = async () => {
    if (!url.trim()) return;
    setBusy(true); setErr(''); setConflict(false); setLive(null); setFlows([]); setFlowsErr('');
    try {
      const r = await api.interactiveStart(url.trim(), name.trim());
      setCaseId(r.case_id);
      poll(r.case_id);
    } catch (e) {
      const msg = String(e.message || e);
      if (msg.includes('409') || msg.toLowerCase().includes('conflict')) {
        setConflict(true);
        setErr('A previous session is still active.');
      } else {
        setErr(msg);
      }
    }
    finally { setBusy(false); }
  };

  const stop = async (thenStart = false) => {
    setStopping(true); setErr('');
    try {
      await api.interactiveAbort();
      resetSession();
      if (thenStart) await start();
    } catch (e) {
      setErr(`Stop failed: ${e.message || e}`);
    } finally {
      setStopping(false);
    }
  };

  const poll = async (id) => {
    try { const r = await api.interactiveStatus(id); setLive(r.live || null); } catch {}
    timer.current = setTimeout(() => poll(id), 2500);
  };

  const finalize = async () => {
    if (!caseId) return;
    setFinalizing(true); setErr('');
    clearTimers();
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

        {/* 409 conflict — offer stop+retry */}
        {conflict && (
          <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <IndicatorBadge type="warning" message="Session conflict — a previous session is still active." />
            <button onClick={() => stop(true)} disabled={stopping}
              style={{ ...btnBase, background: `linear-gradient(135deg,${C.red}cc,${C.red}88)`, border: `1px solid ${C.red}`, color: '#110000' }}>
              <StopCircle size={13} style={{ marginRight: 4 }} />{stopping ? 'STOPPING...' : 'FORCE STOP & RETRY'}
            </button>
          </div>
        )}
        {err && !conflict && <div style={{ marginTop: '0.75rem' }}><IndicatorBadge type="warning" message={err} /></div>}
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
          <div style={{ marginTop: '0.9rem', display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
            <ExecButton onClick={finalize} loading={finalizing} label="ANALYZE & GENERATE REPORT" loadingLabel="ANALYZING..." icon={Activity} color={C.red} />
            <button onClick={() => stop(false)} disabled={stopping || finalizing}
              style={{ ...btnBase, border: `1px solid ${C.red}88`, color: C.red, background: `${C.red}11` }}>
              <StopCircle size={13} style={{ marginRight: 4 }} />{stopping ? 'STOPPING...' : 'STOP SESSION'}
            </button>
          </div>
        </HudFrame>
      )}

      {/* Live MITM flows */}
      {caseId && (
        <HudFrame title="Live Network Flows" subtitle={`${flows.length} flows captured`} accentColor={C.green}>
          {flowsErr && <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.68rem', color: C.red, marginBottom: '0.5rem' }}>{flowsErr}</div>}
          {flows.length === 0 ? (
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.68rem', color: '#446644' }}>Waiting for network traffic...</div>
          ) : (
            <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '260px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.65rem' }}>
                <thead>
                  <tr>{['time','method','host','path','status','flags'].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '0.25rem 0.4rem', color: '#557755', borderBottom: `1px solid ${C.border}`, whiteSpace: 'nowrap' }}>{h.toUpperCase()}</th>
                  ))}</tr>
                </thead>
                <tbody>
                  {[...flows].reverse().map((f, i) => {
                    const isRpc = f.is_blockchain_rpc;
                    const isC2  = f.is_jsonp_c2 || f.is_jsrepo;
                    const rowCol = isRpc ? C.red : isC2 ? C.gold : C.green;
                    return (
                      <tr key={i} style={{ borderBottom: `1px solid #112211`, background: isRpc ? '#1a0000' : isC2 ? '#1a1000' : 'transparent' }}>
                        <td style={{ padding: '0.2rem 0.4rem', color: '#557755', whiteSpace: 'nowrap' }}>{(f.ts || '').slice(11,19)}</td>
                        <td style={{ padding: '0.2rem 0.4rem', color: rowCol }}>{f.method || 'GET'}</td>
                        <td style={{ padding: '0.2rem 0.4rem', color: rowCol, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.host || ''}</td>
                        <td style={{ padding: '0.2rem 0.4rem', color: '#88aa88', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={f.path}>{(f.path || '/').slice(0,40)}</td>
                        <td style={{ padding: '0.2rem 0.4rem', color: f.status >= 400 ? C.red : rowCol }}>{f.status || ''}</td>
                        <td style={{ padding: '0.2rem 0.4rem', whiteSpace: 'nowrap' }}>
                          {isRpc && <span style={{ color: C.red, marginRight: 4 }}>CHAIN</span>}
                          {f.is_jsonp_c2 && <span style={{ color: C.gold, marginRight: 4 }}>C2</span>}
                          {f.is_jsrepo && <span style={{ color: C.gold, marginRight: 4 }}>JSREPO</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </HudFrame>
      )}

      {/* noVNC desktop — STOP SESSION button sits just above the iframe */}
      <HudFrame title="Analyst Browser (noVNC)" subtitle="auto-connect · analyst view">
        {!caseId && (
          <div style={{ marginBottom: '0.5rem', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.65rem', color: '#446644' }}>
              No active session. Enter a URL above and click OPEN IN BROWSER.
            </span>
            <button onClick={() => stop(false)} disabled={stopping}
              style={{ ...btnBase, border: `1px solid ${C.border}`, color: '#557755', fontSize: '0.62rem' }}>
              <StopCircle size={11} style={{ marginRight: 3 }} />{stopping ? 'CLEARING...' : 'CLEAR STUCK SESSION'}
            </button>
          </div>
        )}
        <iframe title="analyst-browser" src={kasmUrl}
          style={{ width: '100%', height: '85vh', border: `1px solid ${C.border}`, borderRadius: '0.4rem', background: '#000' }} />
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
const btnBase = { display: 'inline-flex', alignItems: 'center', padding: '0.45rem 0.75rem', borderRadius: '0.35rem', background: 'transparent', cursor: 'pointer', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem', letterSpacing: '0.05em' };