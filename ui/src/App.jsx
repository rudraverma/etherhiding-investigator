import { useEffect, useState } from 'react';
import { Routes, Route, NavLink, useNavigate, useLocation, Navigate } from 'react-router-dom';
import { Search, MousePointerClick, List, Activity, Network, FileText, FolderTree, Settings as Cog, LogOut, Shield } from 'lucide-react';
import { C, CYBER_STYLES, LOGO_URL, MatrixRain, GlitchText } from './components/CyberHawkUI.jsx';
import { api, getToken, setToken, clearToken, AuthError } from './api.js';

import SubmitUrl from './pages/SubmitUrl.jsx';
import Interactive from './pages/Interactive.jsx';
import Investigations from './pages/Investigations.jsx';
import LiveInvestigation from './pages/LiveInvestigation.jsx';
import MitmProxy from './pages/MitmProxy.jsx';
import Report from './pages/Report.jsx';
import Evidence from './pages/Evidence.jsx';
import SettingsPage from './pages/Settings.jsx';

function Login({ onOk }) {
  const [val, setVal] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setErr('');
    setToken(val.trim());
    try { await api.checkAuth(); onOk(); }
    catch (ex) { clearToken(); setErr(ex instanceof AuthError ? 'Invalid token' : String(ex.message || ex)); }
    finally { setBusy(false); }
  };
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', zIndex: 1 }}>
      <form onSubmit={submit} className="hud-card" style={{ padding: '2rem', borderRadius: '0.75rem', width: 380, background: C.bg2 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
          <img src={LOGO_URL} alt="" width={44} height={44} style={{ borderRadius: '50%', border: `2px solid ${C.gold}` }} onError={(e) => (e.target.style.display = 'none')} />
          <div>
            <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, color: C.green, letterSpacing: '0.1em' }}>ETHERHAWK</div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.6rem', color: C.gold, letterSpacing: '0.2em' }}>ETHERHIDING INVESTIGATOR</div>
          </div>
        </div>
        <label style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem', color: '#557755' }}>DASHBOARD TOKEN</label>
        <input className="cyber-input" type="password" value={val} autoFocus onChange={(e) => setVal(e.target.value)}
          style={{ width: '100%', marginTop: '0.5rem', padding: '0.6rem', background: '#000', border: `1px solid ${C.border}`, borderRadius: '0.375rem', color: C.green, fontFamily: "'Share Tech Mono', monospace" }} />
        {err && <div style={{ color: C.red, fontSize: '0.7rem', marginTop: '0.5rem', fontFamily: "'Share Tech Mono', monospace" }}>{err}</div>}
        <button type="submit" disabled={busy} className="exec-btn" style={{ width: '100%', marginTop: '1rem', padding: '0.6rem', borderRadius: '0.375rem', background: `linear-gradient(135deg, ${C.green}cc, ${C.green}88)`, color: '#001100', border: `1px solid ${C.green}`, cursor: 'pointer' }}>
          {busy ? 'AUTHENTICATING...' : 'AUTHENTICATE'}
        </button>
      </form>
    </div>
  );
}

const NAV = [
  { to: '/interactive', label: 'Interactive', icon: MousePointerClick },
  { to: '/submit', label: 'Submit (auto)', icon: Search },
  { to: '/cases', label: 'Investigations', icon: List },
  { to: '/settings', label: 'Settings', icon: Cog },
];
const CASE_TABS = [
  { to: '/live', label: 'Live', icon: Activity },
  { to: '/mitm', label: 'MITM', icon: Network },
  { to: '/report', label: 'Report', icon: FileText },
  { to: '/evidence', label: 'Evidence', icon: FolderTree },
];

function Shell({ branding, onLogout }) {
  const loc = useLocation();
  const nav = useNavigate();
  const params = new URLSearchParams(loc.search);
  const caseId = params.get('id') || '';
  const q = caseId ? `?id=${encodeURIComponent(caseId)}` : '';

  const linkStyle = ({ isActive }) => ({
    display: 'flex', alignItems: 'center', gap: '0.6rem', padding: '0.6rem 0.9rem', borderRadius: '0.4rem',
    color: isActive ? C.green : '#557755', background: isActive ? C.greenBg : 'transparent',
    border: `1px solid ${isActive ? C.greenBdr : 'transparent'}`, textDecoration: 'none',
    fontFamily: "'Share Tech Mono', monospace", fontSize: '0.75rem', letterSpacing: '0.05em',
  });

  return (
    <div style={{ minHeight: '100vh', position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <header style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '0.75rem 1.25rem', borderBottom: `1px solid ${C.border}`, background: '#000' }}>
        <img src={LOGO_URL} alt="" width={40} height={40} style={{ borderRadius: '50%', border: `2px solid ${C.gold}` }} onError={(e) => (e.target.style.display = 'none')} />
        <div>
          <GlitchText text={branding.platformName || 'ETHERHAWK'} style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: '1.1rem', color: C.green, letterSpacing: '0.08em', textShadow: `0 0 14px ${C.green}` }} />
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.58rem', color: C.gold, letterSpacing: '0.2em' }}>{branding.tagline || 'VISIT · TRIGGER · CAPTURE · CONFIRM'}</div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.6rem', color: C.green }}>
            <span className="cyber-blink" style={{ width: 6, height: 6, borderRadius: '50%', background: C.green, boxShadow: `0 0 6px ${C.green}` }} />
            {branding.statusLabel || 'LIVE'}
          </span>
          <button onClick={onLogout} title="Log out" style={{ background: 'transparent', border: `1px solid ${C.border}`, color: '#557755', borderRadius: '0.35rem', padding: '0.35rem 0.5rem', cursor: 'pointer' }}>
            <LogOut size={14} />
          </button>
        </div>
      </header>

      <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
        {/* Sidebar */}
        <nav style={{ width: 210, padding: '1rem 0.75rem', borderRight: `1px solid ${C.border}`, background: C.bg1, display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} style={linkStyle}>
              <n.icon size={15} />{n.label}
            </NavLink>
          ))}
          <div style={{ height: 1, background: C.border, margin: '0.6rem 0' }} />
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.55rem', color: '#335533', letterSpacing: '0.15em', padding: '0 0.5rem' }}>
            {caseId ? `CASE: ${caseId}` : 'NO CASE SELECTED'}
          </div>
          {CASE_TABS.map((t) => (
            <button key={t.to} disabled={!caseId} onClick={() => nav(`${t.to}${q}`)}
              style={{ ...linkStyle({ isActive: loc.pathname === t.to }), opacity: caseId ? 1 : 0.35, cursor: caseId ? 'pointer' : 'not-allowed', background: 'transparent', textAlign: 'left' }}>
              <t.icon size={15} />{t.label}
            </button>
          ))}
        </nav>

        {/* Content */}
        <main style={{ flex: 1, minWidth: 0, padding: '1.25rem', overflow: 'auto' }}>
          <Routes>
            <Route path="/" element={<Navigate to="/interactive" replace />} />
            <Route path="/interactive" element={<Interactive />} />
            <Route path="/submit" element={<SubmitUrl />} />
            <Route path="/cases" element={<Investigations />} />
            <Route path="/live" element={<LiveInvestigation caseId={caseId} />} />
            <Route path="/mitm" element={<MitmProxy caseId={caseId} />} />
            <Route path="/report" element={<Report caseId={caseId} />} />
            <Route path="/evidence" element={<Evidence caseId={caseId} />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/interactive" replace />} />
          </Routes>
        </main>
      </div>

      <footer style={{ padding: '0.5rem 1.25rem', borderTop: `1px solid ${C.border}`, background: '#000', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.58rem', color: '#335533', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <Shield size={11} /> {branding.footerText || 'CyberHawk Threat Intel'} · EtherHawk · deterministic — no AI in the loop
      </footer>
    </div>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(false);
  const [checked, setChecked] = useState(false);
  const [branding, setBranding] = useState({});

  const loadBranding = async () => { try { const r = await api.config(); setBranding(r.branding || {}); } catch {} };

  useEffect(() => {
    (async () => {
      if (!getToken()) { setChecked(true); return; }
      setToken(getToken());   // refresh the eh_token cookie (for the noVNC gate)
      try { await api.checkAuth(); setAuthed(true); await loadBranding(); }
      catch { clearToken(); }
      finally { setChecked(true); }
    })();
  }, []);

  const onOk = async () => { setAuthed(true); await loadBranding(); };
  const onLogout = () => { clearToken(); setAuthed(false); };

  return (
    <>
      <style>{CYBER_STYLES}</style>
      <div className="cyber-grid-bg" style={{ position: 'fixed', inset: 0, zIndex: 0 }} />
      <MatrixRain opacity={0.15} />
      {!checked ? null : authed ? <Shell branding={branding} onLogout={onLogout} /> : <Login onOk={onOk} />}
    </>
  );
}
