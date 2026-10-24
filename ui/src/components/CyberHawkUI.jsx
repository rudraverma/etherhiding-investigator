/**
 * CyberHawkUI — shared cinematic UI system for CyberHawk tools.
 * Reused from the CyberHawk design system (palette, fonts, HUD components).
 */
import { useState, useEffect, useRef } from 'react';
import { Copy, Check, ExternalLink, Shield } from 'lucide-react';

// ─── Palette ────────────────────────────────────────────────────────────────
export const C = {
  green: '#00ff41', greenDim: '#00cc33', greenBg: 'rgba(0,255,65,0.06)', greenBdr: 'rgba(0,255,65,0.25)',
  red: '#ff0040', redDim: '#cc0033', redBg: 'rgba(255,0,64,0.08)', redBdr: 'rgba(255,0,64,0.3)',
  orange: '#ff6600', orangeBg: 'rgba(255,102,0,0.08)', orangeBdr: 'rgba(255,102,0,0.3)',
  yellow: '#ffd700', yellowBg: 'rgba(255,215,0,0.08)', yellowBdr: 'rgba(255,215,0,0.25)',
  gold: '#d4af37', goldDim: '#a07820',
  cyan: '#00d4ff', cyanBg: 'rgba(0,212,255,0.06)', cyanBdr: 'rgba(0,212,255,0.25)',
  purple: '#bf00ff', purpleBg: 'rgba(191,0,255,0.06)', purpleBdr: 'rgba(191,0,255,0.25)',
  bg: '#000000', bg1: '#050a05', bg2: '#080d08', bg3: '#0d150d',
  border: 'rgba(0,255,65,0.12)', borderMid: 'rgba(0,255,65,0.2)',
};

export const LOGO_URL = 'https://media.cyberhawkthreatintel.com/general/1771234479938-y9566.png';

export const CYBER_STYLES = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=VT323&display=swap');
  .cyber-font-mono  { font-family: 'Share Tech Mono', monospace; }
  .cyber-font-title { font-family: 'Orbitron', monospace; }
  .cyber-font-vt    { font-family: 'VT323', monospace; }
  .cyber-grid-bg {
    background-image:
      linear-gradient(rgba(0,255,65,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,65,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  @keyframes glitch {
    0%,100% { clip-path: none; transform: none; }
    20% { clip-path: polygon(0 15%, 100% 15%, 100% 25%, 0 25%); transform: translateX(-3px); color: #ff0040; }
    40% { clip-path: polygon(0 55%, 100% 55%, 100% 65%, 0 65%); transform: translateX(3px); color: #00d4ff; }
    60% { clip-path: polygon(0 80%, 100% 80%, 100% 90%, 0 90%); transform: translateX(-2px); }
    80% { clip-path: none; transform: none; }
  }
  .cyber-glitch { animation: glitch 4s infinite; }
  .hud-bracket { position: absolute; width: 16px; height: 16px; border-color: ${C.gold}; border-style: solid; }
  .hud-tl { top: -1px; left: -1px; border-width: 2px 0 0 2px; }
  .hud-tr { top: -1px; right: -1px; border-width: 2px 2px 0 0; }
  .hud-bl { bottom: -1px; left: -1px; border-width: 0 0 2px 2px; }
  .hud-br { bottom: -1px; right: -1px; border-width: 0 2px 2px 0; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
  .cyber-blink { animation: blink 1s infinite; }
  @keyframes scanSweep { 0% { transform: translateY(-100%); opacity: 0.6; } 100% { transform: translateY(100%); opacity: 0; } }
  .scan-sweep { animation: scanSweep 1.5s linear infinite; }
  @keyframes fadeInUp { from { opacity:0; transform:translateY(12px); } to { opacity:1; transform:translateY(0); } }
  .cyber-fade-in { animation: fadeInUp 0.4s ease both; }
  @keyframes skullPulse {
    0%,100% { filter: drop-shadow(0 0 4px #ff0040) drop-shadow(0 0 8px #ff0040); transform: scale(1); }
    50% { filter: drop-shadow(0 0 20px #ff0040) drop-shadow(0 0 40px #ff0040); transform: scale(1.06); }
  }
  .skull-pulse { animation: skullPulse 0.8s ease-in-out infinite; }
  @keyframes slideIn { from{opacity:0;transform:translateX(-10px)} to{opacity:1;transform:translateX(0)} }
  .slide-in { animation: slideIn 0.35s ease both; }
  @keyframes alertFlash { 0%,100%{opacity:1} 50%{opacity:0.5} }
  .alert-flash { animation: alertFlash 0.5s infinite; }
  .exec-btn { position: relative; overflow: hidden; font-family: 'Orbitron', monospace; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; transition: all 0.2s; }
  .exec-btn:hover { box-shadow: 0 0 20px rgba(0,255,65,0.5); transform: translateY(-1px); }
  .exec-btn:active { transform: translateY(0); }
  .cyber-input:focus { outline: none; border-color: ${C.green} !important; box-shadow: 0 0 0 1px ${C.green}, 0 0 20px rgba(0,255,65,0.15); }
  .cyber-input { caret-color: ${C.green}; }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: ${C.bg1}; }
  ::-webkit-scrollbar-thumb { background: ${C.greenDim}; border-radius: 3px; }
  .hud-card { border: 1px solid ${C.border}; position: relative; background: ${C.bg2}; }
  @keyframes rotate { to { transform: rotate(360deg); } }
  .spin-slow { animation: rotate 3s linear infinite; }
  .spin-fast { animation: rotate 0.6s linear infinite; }
  a { color: ${C.cyan}; }
`;

export function MatrixRain({ opacity = 0.25 }) {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let W = (canvas.width = window.innerWidth);
    let H = (canvas.height = window.innerHeight);
    const CHARS = 'アイウエオカキクケコ0123456789ABCDEF<>{}[]';
    const cols = Math.floor(W / 16);
    const drops = Array(cols).fill(1);
    let frame = 0;
    const draw = () => {
      ctx.fillStyle = 'rgba(0,0,0,0.05)';
      ctx.fillRect(0, 0, W, H);
      frame++;
      drops.forEach((y, i) => {
        if (frame % 2 !== 0 && i % 3 !== 0) return;
        const char = CHARS[Math.floor(Math.random() * CHARS.length)];
        const bright = y * 16 < 30 ? '#ffffff' : y * 16 < 60 ? '#88ff88' : '#00cc33';
        ctx.fillStyle = bright;
        ctx.font = "14px 'Share Tech Mono', monospace";
        ctx.fillText(char, i * 16, y * 16);
        if (y * 16 > H && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      });
    };
    const id = setInterval(draw, 50);
    const onResize = () => { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; };
    window.addEventListener('resize', onResize);
    return () => { clearInterval(id); window.removeEventListener('resize', onResize); };
  }, []);
  return <canvas ref={canvasRef} style={{ position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', opacity, pointerEvents: 'none', zIndex: 0 }} />;
}

export function HudFrame({ children, title, subtitle, accentColor = C.green, className = '' }) {
  return (
    <div className={`hud-card ${className}`} style={{ borderRadius: '0.75rem', border: `1px solid ${accentColor}22`, background: C.bg2, position: 'relative' }}>
      <div className="hud-bracket hud-tl" /><div className="hud-bracket hud-tr" />
      <div className="hud-bracket hud-bl" /><div className="hud-bracket hud-br" />
      {title && (
        <div style={{ background: `linear-gradient(90deg, ${accentColor}15, transparent)`, borderBottom: `1px solid ${accentColor}22`, padding: '0.6rem 1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: accentColor, boxShadow: `0 0 8px ${accentColor}` }} className="cyber-blink" />
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.65rem', color: accentColor, textTransform: 'uppercase', letterSpacing: '0.15em' }}>{title}</span>
          {subtitle && <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.6rem', color: accentColor, opacity: 0.4, marginLeft: 'auto' }}>{subtitle}</span>}
        </div>
      )}
      <div style={{ padding: '1rem' }}>{children}</div>
    </div>
  );
}

export function GlitchText({ text, className = '', style = {} }) {
  const [g, setG] = useState(false);
  useEffect(() => {
    const t = setInterval(() => { setG(true); setTimeout(() => setG(false), 200); }, 3000 + Math.random() * 4000);
    return () => clearInterval(t);
  }, []);
  return <span className={`${g ? 'cyber-glitch' : ''} ${className}`} style={style}>{text}</span>;
}

const IND_CFG = {
  critical: { color: '#ff0040', bg: 'rgba(255,0,64,0.08)', border: 'rgba(255,0,64,0.3)', icon: '☠', label: 'CRITICAL' },
  warning: { color: '#ff6600', bg: 'rgba(255,102,0,0.08)', border: 'rgba(255,102,0,0.3)', icon: '⚠', label: 'WARNING' },
  info: { color: '#ffd700', bg: 'rgba(255,215,0,0.06)', border: 'rgba(255,215,0,0.2)', icon: '◈', label: 'INFO' },
  pass: { color: '#00ff41', bg: 'rgba(0,255,65,0.06)', border: 'rgba(0,255,65,0.2)', icon: '✓', label: 'CLEAN' },
};

export function IndicatorBadge({ type = 'info', message, detail, idx = 0 }) {
  const cfg = IND_CFG[type] || IND_CFG.info;
  const isCrit = type === 'critical';
  return (
    <div className={`slide-in ${isCrit ? 'alert-flash' : ''}`} style={{ background: cfg.bg, border: `1px solid ${cfg.border}`, borderRadius: '0.5rem', padding: '0.75rem 1rem', display: 'flex', gap: '0.75rem', animationDelay: `${idx * 80}ms`, fontFamily: "'Share Tech Mono', monospace" }}>
      <span style={{ color: cfg.color, fontSize: '1rem', textShadow: `0 0 8px ${cfg.color}` }}>{cfg.icon}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ color: cfg.color, fontSize: '0.6rem', fontWeight: 'bold', letterSpacing: '0.15em', marginBottom: '0.15rem' }}>[{cfg.label}]</div>
        <p style={{ color: cfg.color, fontSize: '0.75rem', opacity: 0.95, lineHeight: 1.4, wordBreak: 'break-word' }}>{message}</p>
        {detail && <p style={{ color: cfg.color, fontSize: '0.65rem', opacity: 0.55, marginTop: '0.2rem', wordBreak: 'break-word' }}>{detail}</p>}
      </div>
    </div>
  );
}

export function CopyBtn({ text, label = 'COPY' }) {
  const [c, setC] = useState(false);
  return (
    <button onClick={async () => { try { await navigator.clipboard.writeText(text); } catch (e) {} setC(true); setTimeout(() => setC(false), 1500); }}
      style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', padding: '0.2rem 0.6rem', borderRadius: '0.25rem', border: `1px solid ${c ? C.green : C.border}`, background: c ? C.greenBg : 'transparent', color: c ? C.green : '#557755', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.6rem', cursor: 'pointer' }}>
      {c ? <Check size={10} /> : <Copy size={10} />}{c ? 'COPIED' : label}
    </button>
  );
}

export function ExecButton({ onClick, loading, disabled, label, loadingLabel = 'PROCESSING...', icon: Icon, color = C.green }) {
  return (
    <button onClick={onClick} disabled={loading || disabled} className="exec-btn"
      style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.6rem 1.5rem', borderRadius: '0.375rem', background: loading ? `${color}22` : `linear-gradient(135deg, ${color}cc, ${color}88)`, color: loading ? color : '#001100', border: `1px solid ${color}`, opacity: disabled ? 0.4 : 1, cursor: disabled || loading ? 'not-allowed' : 'pointer' }}>
      {loading ? <><div className="spin-fast" style={{ width: 14, height: 14, border: `2px solid ${color}44`, borderTop: `2px solid ${color}`, borderRadius: '50%' }} />{loadingLabel}</>
        : <>{Icon && <Icon size={14} />}{label}</>}
    </button>
  );
}

export function StatusBar({ path, status = 'LIVE', statusColor = C.green }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.4rem 1.2rem', background: '#000', borderBottom: `1px solid ${C.border}`, fontFamily: "'Share Tech Mono', monospace" }}>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        {['#ff3300', '#ff9900', '#00cc00'].map((c, i) => <span key={i} style={{ width: 8, height: 8, borderRadius: '50%', background: c }} />)}
      </div>
      <div style={{ color: '#336633', fontSize: '0.6rem' }}>{path}</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
        <Shield size={10} color={statusColor} />
        <span style={{ fontSize: '0.6rem', color: statusColor, fontWeight: 'bold', letterSpacing: '0.15em', textShadow: `0 0 8px ${statusColor}` }}>{status}</span>
      </div>
    </div>
  );
}

export function SkullLoader({ active, phaseText = 'INVESTIGATING' }) {
  const [dots, setDots] = useState('');
  useEffect(() => {
    if (!active) return;
    const d = setInterval(() => setDots((p) => (p.length >= 3 ? '' : p + '.')), 400);
    return () => clearInterval(d);
  }, [active]);
  if (!active) return null;
  return (
    <div style={{ display: 'flex', gap: '1.5rem', alignItems: 'center', padding: '1.5rem', background: 'rgba(255,0,64,0.05)', border: '1px solid rgba(255,0,64,0.3)', borderRadius: '0.75rem', fontFamily: "'Share Tech Mono', monospace" }}>
      <div className="skull-pulse">
        <svg width="56" height="56" viewBox="0 0 100 100" fill="none">
          <ellipse cx="50" cy="42" rx="26" ry="24" fill="#1a0000" stroke="#ff0040" strokeWidth="1.5" />
          <ellipse cx="40" cy="38" rx="7" ry="8" fill="#ff0040" /><ellipse cx="60" cy="38" rx="7" ry="8" fill="#ff0040" />
          <rect x="30" y="60" width="40" height="14" rx="4" fill="#1a0000" stroke="#ff0040" strokeWidth="1.5" />
        </svg>
      </div>
      <div>
        <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: '0.85rem', color: '#ff0040', letterSpacing: '0.15em', textShadow: '0 0 10px #ff0040' }}>⚠ ANALYSIS IN PROGRESS ⚠</div>
        <div style={{ color: C.green, fontSize: '0.75rem', marginTop: '0.4rem' }}>{phaseText}{dots}</div>
      </div>
    </div>
  );
}
