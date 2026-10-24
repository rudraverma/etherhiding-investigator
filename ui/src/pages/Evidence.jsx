import { useEffect, useState } from 'react';
import { C, HudFrame } from '../components/CyberHawkUI.jsx';
import { api, fetchArtifactText, fetchArtifactBlobUrl } from '../api.js';

const IMG = ['.png', '.jpg', '.jpeg', '.gif', '.webp'];
const HTMLX = ['.html', '.htm'];

function ext(p) { const i = p.lastIndexOf('.'); return i >= 0 ? p.slice(i).toLowerCase() : ''; }

export default function Evidence({ caseId }) {
  const [files, setFiles] = useState([]);
  const [sel, setSel] = useState(null);
  const [text, setText] = useState('');
  const [imgUrl, setImgUrl] = useState('');
  const [render, setRender] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => {
    if (!caseId) return;
    setFiles([]); setSel(null); setText(''); setImgUrl('');
    api.tree(caseId).then((r) => setFiles(r.files || [])).catch((e) => setErr(String(e.message || e)));
  }, [caseId]);

  const open = async (f) => {
    setSel(f); setText(''); setImgUrl(''); setRender(false); setErr('');
    const e = ext(f.path);
    try {
      if (IMG.includes(e)) setImgUrl(await fetchArtifactBlobUrl(caseId, f.path));
      else setText(await fetchArtifactText(caseId, f.path));
    } catch (ex) { setErr(String(ex.message || ex)); }
  };

  if (!caseId) return <HudFrame title="Evidence"><div style={muted}>No case selected.</div></HudFrame>;

  const e = sel ? ext(sel.path) : '';
  const isHtml = HTMLX.includes(e);

  return (
    <div style={{ display: 'flex', gap: '1rem', height: 'calc(100vh - 190px)' }}>
      <div style={{ width: 300, flexShrink: 0 }}>
        <HudFrame title="Case Files" subtitle={`${files.length}`}>
          <div style={{ overflow: 'auto', maxHeight: 'calc(100vh - 290px)' }}>
            {files.map((f) => (
              <div key={f.path} onClick={() => open(f)} title={f.path}
                style={{ cursor: 'pointer', padding: '0.25rem 0.4rem', borderRadius: '0.25rem', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.66rem', color: sel && sel.path === f.path ? C.green : '#88aa88', background: sel && sel.path === f.path ? C.greenBg : 'transparent', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {f.path} <span style={{ color: '#335533' }}>({f.size})</span>
              </div>
            ))}
            {!files.length && <div style={muted}>No artifacts.</div>}
          </div>
        </HudFrame>
      </div>

      <div style={{ flex: 1, minWidth: 0 }}>
        <HudFrame title={sel ? sel.path : 'Viewer'} subtitle={isHtml ? 'HTML — scripts disabled' : ''}>
          {err && <div style={{ color: C.red, fontFamily: "'Share Tech Mono', monospace", fontSize: '0.72rem', marginBottom: '0.5rem' }}>{err}</div>}
          {!sel && <div style={muted}>Select a file to view. Captured HTML renders in a sandboxed frame with scripts disabled.</div>}

          {sel && imgUrl && <img src={imgUrl} alt={sel.path} style={{ maxWidth: '100%', border: `1px solid ${C.border}`, borderRadius: '0.4rem' }} />}

          {sel && isHtml && (
            <div>
              <div style={{ marginBottom: '0.5rem', display: 'flex', gap: '0.5rem' }}>
                <button onClick={() => setRender(false)} style={tab(!render)}>SOURCE</button>
                <button onClick={() => setRender(true)} style={tab(render)}>RENDER (SANDBOXED)</button>
              </div>
              {render ? (
                <iframe title="rendered" sandbox="" srcDoc={text}
                  style={{ width: '100%', height: '60vh', border: `1px solid ${C.border}`, borderRadius: '0.4rem', background: '#fff' }} />
              ) : (
                <Pre text={text} />
              )}
            </div>
          )}

          {sel && !isHtml && !imgUrl && <Pre text={text} />}
        </HudFrame>
      </div>
    </div>
  );
}

const Pre = ({ text }) => (
  <pre style={{ margin: 0, maxHeight: '60vh', overflow: 'auto', background: '#000', border: `1px solid ${C.border}`, borderRadius: '0.4rem', padding: '0.75rem', color: '#9ab89a', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.68rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{text}</pre>
);
const tab = (active) => ({ background: active ? C.greenBg : 'transparent', border: `1px solid ${active ? C.greenBdr : C.border}`, color: active ? C.green : '#557755', borderRadius: '0.3rem', padding: '0.3rem 0.7rem', cursor: 'pointer', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.65rem' });
const muted = { color: '#557755', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.78rem' };
