import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderOpen, Star, ChevronDown, ChevronRight,
  Search, Calendar, Archive, Shield, AlertTriangle, CheckCircle, HelpCircle,
} from 'lucide-react';
import { C, HudFrame } from '../components/CyberHawkUI.jsx';
import { api } from '../api.js';

const FAV_KEY = 'eh_favourites';
const MONTHS  = ['', 'January', 'February', 'March', 'April', 'May', 'June',
                  'July', 'August', 'September', 'October', 'November', 'December'];

const VERDICT_COLOR = {
  COMPROMISED_ETHERHIDING: '#ff4444',
  SUSPECTED_ETHERHIDING:   '#ff8800',
  NO_ETHERHIDING_DETECTED: '#44cc44',
  INCONCLUSIVE:            '#cccc44',
};

const VERDICT_ICON = {
  COMPROMISED_ETHERHIDING: <Shield size={11} color="#ff4444" />,
  SUSPECTED_ETHERHIDING:   <AlertTriangle size={11} color="#ff8800" />,
  NO_ETHERHIDING_DETECTED: <CheckCircle size={11} color="#44cc44" />,
  INCONCLUSIVE:            <HelpCircle size={11} color="#cccc44" />,
};

function loadFavs() {
  try { return JSON.parse(localStorage.getItem(FAV_KEY) || '[]'); }
  catch { return []; }
}
function saveFavs(f) {
  try { localStorage.setItem(FAV_KEY, JSON.stringify(f)); } catch {}
}

function parseCaseId(id) {
  const m = id.match(/^(\d{4})-(\d{2})-(\d{2})\//);
  if (!m) return { year: '????', month: '00', day: '00' };
  return { year: m[1], month: m[2], day: m[3] };
}

function caseSlug(id) { return id.replace(/^\d{4}-\d{2}-\d{2}\//, ''); }

export default function Investigations() {
  const navigate = useNavigate();
  const [cases,   setCases]   = useState([]);
  const [tab,     setTab]     = useState('all');
  const [favs,    setFavs]    = useState(loadFavs);
  const [search,  setSearch]  = useState('');
  const [expanded, setExpanded] = useState({ years: {}, months: {}, days: {} });

  const reload = useCallback(async () => {
    try {
      const r = await api.cases();
      const list = r.cases || [];
      setCases(list);
      const now = new Date();
      const y = String(now.getFullYear());
      const m = String(now.getMonth() + 1).padStart(2, '0');
      setExpanded(prev => ({
        ...prev,
        years:  { ...prev.years,  [y]: true },
        months: { ...prev.months, [`${y}-${m}`]: true },
      }));
    } catch {}
  }, []);

  useEffect(() => { reload(); }, [reload]);

  const isFav = (id) => favs.some(f => f.id === id);
  const toggleFav = (c) => {
    setFavs(prev => {
      const next = isFav(c.id)
        ? prev.filter(f => f.id !== c.id)
        : [{ ...c, addedAt: new Date().toISOString() }, ...prev];
      saveFavs(next);
      return next;
    });
  };

  const toggle = (type, key) => {
    setExpanded(prev => {
      const cur  = prev[type][key];
      const next = cur === undefined ? false : !cur;
      return { ...prev, [type]: { ...prev[type], [key]: next } };
    });
  };

  // Build year > month > day > cases tree
  const grouped = {};
  cases.forEach(c => {
    const { year, month, day } = parseCaseId(c.id);
    if (!grouped[year])             grouped[year]             = {};
    if (!grouped[year][month])      grouped[year][month]      = {};
    if (!grouped[year][month][day]) grouped[year][month][day] = [];
    grouped[year][month][day].push(c);
  });

  const q = search.toLowerCase();
  const filter = (list) => q
    ? list.filter(c => c.id.toLowerCase().includes(q) || (c.domain || '').toLowerCase().includes(q) || (c.verdict || '').toLowerCase().includes(q))
    : list;

  const favList  = favs.slice().sort((a, b) => b.addedAt.localeCompare(a.addedAt));
  const total    = cases.length;
  const yearCount = Object.keys(grouped).length;

  return (
    <div className="cyber-fade-in" style={{ maxWidth: '1100px', margin: '0 auto' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        <Archive size={22} color={C.green} />
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: '1rem', color: C.green, letterSpacing: '0.1em' }}>
            CASE ARCHIVE
          </div>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.6rem', color: '#336633' }}>
            {total} investigations · {yearCount} year{yearCount !== 1 ? 's' : ''}
          </div>
        </div>
        <div style={{ position: 'relative' }}>
          <Search size={11} style={{ position: 'absolute', left: '0.5rem', top: '50%', transform: 'translateY(-50%)', color: '#336633', pointerEvents: 'none' }} />
          <input
            value={search} onChange={e => setSearch(e.target.value)}
            placeholder="SEARCH CASES..."
            style={{
              paddingLeft: '1.6rem', paddingRight: '0.6rem', height: '30px',
              background: C.greenBg || 'rgba(0,30,0,0.4)', border: `1px solid ${C.greenBdr || C.border}`,
              borderRadius: '0.25rem', color: C.green,
              fontFamily: "'Share Tech Mono', monospace", fontSize: '0.6rem', outline: 'none', width: '200px',
            }}
          />
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1rem', borderBottom: `1px solid ${C.border}`, paddingBottom: '0.5rem' }}>
        {[
          { id: 'all',  label: 'ALL CASES',   badge: total },
          { id: 'favs', label: 'FAVOURITES',  badge: favs.length, icon: <Star size={11} fill={tab === 'favs' ? C.gold : 'none'} color={C.gold} /> },
        ].map(({ id, label, badge, icon }) => (
          <button key={id} onClick={() => setTab(id)} style={{
            padding: '0.35rem 1rem', border: `1px solid ${tab === id ? C.greenBdr || C.border : 'transparent'}`,
            borderRadius: '0.25rem', background: tab === id ? (C.greenBg || 'rgba(0,30,0,0.4)') : 'transparent',
            color: tab === id ? C.green : '#336633', cursor: 'pointer',
            fontFamily: "'Share Tech Mono', monospace", fontSize: '0.65rem', letterSpacing: '0.1em',
            display: 'flex', alignItems: 'center', gap: '0.4rem',
          }}>
            {icon}
            {label}
            <span style={{ background: `${C.green}22`, color: C.green, padding: '0 5px', borderRadius: '8px', fontSize: '0.55rem' }}>{badge}</span>
          </button>
        ))}
      </div>

      {/* All Cases */}
      {tab === 'all' && (
        <div>
          {Object.keys(grouped).sort((a, b) => b - a).map(year => {
            const yearAll      = Object.values(grouped[year]).flatMap(m => Object.values(m)).flat();
            const yearFiltered = filter(yearAll);
            if (q && !yearFiltered.length) return null;

            return (
              <div key={year} style={{ marginBottom: '0.75rem' }}>
                {/* Year row */}
                <div onClick={() => toggle('years', year)} style={{
                  display: 'flex', alignItems: 'center', gap: '0.6rem',
                  padding: '0.55rem 0.85rem',
                  background: 'linear-gradient(90deg,rgba(0,80,0,0.2) 0%,rgba(0,40,0,0.1) 100%)',
                  border: `1px solid ${C.greenBdr || C.border}`, borderRadius: '0.5rem',
                  cursor: 'pointer', userSelect: 'none',
                }}>
                  {expanded.years[year] ? <ChevronDown size={14} color={C.green} /> : <ChevronRight size={14} color={C.green} />}
                  <Calendar size={14} color={C.gold} />
                  <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: '0.8rem', color: C.gold, letterSpacing: '0.08em' }}>
                    {year}
                  </span>
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.55rem', color: '#336633', marginLeft: 'auto' }}>
                    {yearFiltered.length} case{yearFiltered.length !== 1 ? 's' : ''}
                  </span>
                </div>

                {expanded.years[year] && (
                  <div style={{ marginLeft: '1.5rem', marginTop: '0.25rem' }}>
                    {Object.keys(grouped[year]).sort((a, b) => b - a).map(month => {
                      const monthAll      = Object.values(grouped[year][month]).flat();
                      const monthFiltered = filter(monthAll);
                      if (q && !monthFiltered.length) return null;
                      const mKey = `${year}-${month}`;

                      return (
                        <div key={month} style={{ marginBottom: '0.35rem' }}>
                          {/* Month row */}
                          <div onClick={() => toggle('months', mKey)} style={{
                            display: 'flex', alignItems: 'center', gap: '0.5rem',
                            padding: '0.4rem 0.7rem',
                            background: 'rgba(0,60,0,0.12)', border: `1px solid ${C.border}`,
                            borderRadius: '0.375rem', cursor: 'pointer', userSelect: 'none',
                          }}>
                            {expanded.months[mKey] ? <ChevronDown size={12} color="#336633" /> : <ChevronRight size={12} color="#336633" />}
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.65rem', color: C.green, fontWeight: 600 }}>
                              {MONTHS[+month]}
                            </span>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.5rem', color: '#336633', marginLeft: 'auto' }}>
                              {monthFiltered.length} case{monthFiltered.length !== 1 ? 's' : ''}
                            </span>
                          </div>

                          {expanded.months[mKey] && (
                            <div style={{ marginLeft: '1rem', marginTop: '0.2rem' }}>
                              {Object.keys(grouped[year][month]).sort((a, b) => b - a).map(day => {
                                const dayCases = filter(grouped[year][month][day]);
                                if (!dayCases.length) return null;
                                const dKey = `${year}-${month}-${day}`;

                                return (
                                  <div key={day} style={{ marginBottom: '0.2rem' }}>
                                    {/* Day row */}
                                    <div onClick={() => toggle('days', dKey)} style={{
                                      display: 'flex', alignItems: 'center', gap: '0.4rem',
                                      padding: '0.25rem 0.5rem', cursor: 'pointer', userSelect: 'none',
                                    }}>
                                      {expanded.days[dKey] === false
                                        ? <ChevronRight size={10} color="#224422" />
                                        : <ChevronDown size={10} color="#224422" />}
                                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.6rem', color: '#336633' }}>
                                        {year}-{month}-{day}
                                      </span>
                                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.5rem', color: '#1a3320' }}>
                                        ({dayCases.length})
                                      </span>
                                    </div>

                                    {expanded.days[dKey] !== false && (
                                      <div style={{ marginLeft: '0.75rem' }}>
                                        {dayCases.map(c => (
                                          <CaseCard
                                            key={c.id}
                                            c={c}
                                            isFav={isFav(c.id)}
                                            onFav={() => toggleFav(c)}
                                            onReport={() => navigate(`/report?id=${encodeURIComponent(c.id)}`)}
                                            onLive={() => navigate(`/live?id=${encodeURIComponent(c.id)}`)}
                                          />
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}

          {cases.length === 0 && (
            <EmptyState icon={<Archive size={32} color="#1a3320" />} text="NO CASES YET — SUBMIT A URL TO BEGIN" />
          )}
          {cases.length > 0 && q && !filter(cases).length && (
            <EmptyState icon={<Search size={32} color="#1a3320" />} text={`NO CASES MATCHING "${search.toUpperCase()}"`} />
          )}
        </div>
      )}

      {/* Favourites */}
      {tab === 'favs' && (
        <div>
          {favList.length === 0 ? (
            <EmptyState
              icon={<Star size={36} color="#1a3320" />}
              text="NO FAVOURITES YET"
              sub="Star a case to pin it here for quick access"
            />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              {favList.map(fav => {
                const live = cases.find(x => x.id === fav.id) || fav;
                return (
                  <CaseCard
                    key={fav.id}
                    c={live}
                    isFav
                    onFav={() => toggleFav(fav)}
                    onReport={() => navigate(`/report?id=${encodeURIComponent(fav.id)}`)}
                    onLive={() => navigate(`/live?id=${encodeURIComponent(fav.id)}`)}
                    showDate
                  />
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CaseCard({ c, isFav, onFav, onReport, onLive, showDate }) {
  const slug    = caseSlug(c.id);
  const verdict = c.verdict;
  const color   = VERDICT_COLOR[verdict] || '#aaccaa';
  const icon    = VERDICT_ICON[verdict] || null;

  return (
    <div
      style={{
        display: 'flex', alignItems: 'center', gap: '0.5rem',
        padding: '0.42rem 0.7rem',
        background: 'rgba(0,20,0,0.5)', border: `1px solid ${C.border}`,
        borderRadius: '0.375rem', marginBottom: '0.18rem',
        transition: 'border-color 0.1s',
      }}
      onMouseOver={e => e.currentTarget.style.borderColor = C.green}
      onMouseOut={e  => e.currentTarget.style.borderColor = C.border}
    >
      <FolderOpen size={13} color={C.gold} style={{ flexShrink: 0 }} />

      {/* Case name */}
      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.7rem', color: C.green, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {slug}
        {showDate && (
          <span style={{ color: '#336633', marginLeft: '0.5rem', fontSize: '0.55rem' }}>
            {c.id.match(/^(\d{4}-\d{2}-\d{2})/)?.[1]}
          </span>
        )}
      </span>

      {/* Domain */}
      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.58rem', color: '#336633', flexShrink: 0 }}>
        {c.domain}
      </span>

      {/* Status pill */}
      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.52rem', color: c.status === 'done' ? '#44cc44' : c.status === 'error' ? '#ff4444' : '#cccc44', flexShrink: 0 }}>
        {c.status}
      </span>

      {/* Verdict */}
      {verdict && (
        <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.58rem', color, fontWeight: 700, flexShrink: 0 }}>
          {icon}{verdict.replace(/_/g, ' ')}
        </span>
      )}

      {/* Confidence */}
      {c.confidence != null && (
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.52rem', color: '#336633', flexShrink: 0 }}>
          {c.confidence}%
        </span>
      )}

      {/* C2 count */}
      {c.c2_count > 0 && (
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.52rem', color: '#ff4444', flexShrink: 0 }}>
          C2:{c.c2_count}
        </span>
      )}

      {/* Action buttons */}
      <button onClick={onReport} style={actionBtn(C.cyan)}>REPORT</button>
      <button onClick={onLive} style={actionBtn('#aaccaa')}>LIVE</button>

      {/* Favourite */}
      <button onClick={onFav} title={isFav ? 'Remove from favourites' : 'Add to favourites'}
        style={{ padding: '0.2rem 0.3rem', background: isFav ? `${C.gold}1a` : 'transparent', border: '1px solid transparent', borderRadius: '0.2rem', cursor: 'pointer', display: 'flex', alignItems: 'center', flexShrink: 0 }}>
        <Star size={12} fill={isFav ? C.gold : 'none'} color={C.gold} />
      </button>
    </div>
  );
}

function EmptyState({ icon, text, sub }) {
  return (
    <div style={{ textAlign: 'center', padding: '4rem 0' }}>
      <div style={{ marginBottom: '1rem' }}>{icon}</div>
      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.65rem', color: '#224422' }}>{text}</div>
      {sub && <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '0.55rem', color: '#1a3320', marginTop: '0.4rem' }}>{sub}</div>}
    </div>
  );
}

const actionBtn = (color) => ({
  padding: '0.18rem 0.45rem', background: 'transparent', border: `1px solid ${color}33`,
  borderRadius: '0.2rem', color, cursor: 'pointer',
  fontFamily: "'Share Tech Mono', monospace", fontSize: '0.58rem', flexShrink: 0,
});
