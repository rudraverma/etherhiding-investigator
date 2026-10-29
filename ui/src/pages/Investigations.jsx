import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw, ChevronDown, ChevronRight, FolderOpen, Folder } from 'lucide-react';
import { C, HudFrame } from '../components/CyberHawkUI.jsx';
import { api } from '../api.js';

const VERDICT_COLOR = {
  COMPROMISED_ETHERHIDING: C.red,
  SUSPECTED_ETHERHIDING: C.orange,
  NO_ETHERHIDING_DETECTED: C.green,
  INCONCLUSIVE: C.yellow,
};

const MONTH_NAMES = ['January','February','March','April','May','June','July','August','September','October','November','December'];

function parseDate(caseId) {
  const m = caseId.match(/^(\d{4})-(\d{2})-(\d{2})\//);
  if (!m) return { year: '????', month: '??', day: '??', monthName: '????' };
  return {
    year: m[1],
    month: m[2],
    day: m[3],
    monthName: MONTH_NAMES[parseInt(m[2], 10) - 1] || m[2],
  };
}

function caseName(caseId) {
  return caseId.replace(/^\d{4}-\d{2}-\d{2}\//, '');
}

function groupCases(rows) {
  const tree = {};
  for (const r of rows) {
    const { year, month, day, monthName } = parseDate(r.id);
    if (!tree[year]) tree[year] = {};
    const mk = `${month}|${monthName}`;
    if (!tree[year][mk]) tree[year][mk] = {};
    if (!tree[year][mk][day]) tree[year][mk][day] = [];
    tree[year][mk][day].push(r);
  }
  return tree;
}

const td = { padding: '0.35rem 0.6rem', borderBottom: `1px solid ${C.border}`, whiteSpace: 'nowrap' };
const openBtn = { marginRight: '0.4rem', background: 'transparent', border: `1px solid ${C.border}`, color: C.cyan, borderRadius: '0.3rem', padding: '0.18rem 0.45rem', cursor: 'pointer', fontFamily: "'Share Tech Mono', monospace", fontSize: '0.62rem' };

function CaseRow({ r, nav, depth = 0 }) {
  return (
    <tr style={{ color: '#aaccaa' }}>
      <td style={{ ...td, paddingLeft: `${0.6 + depth * 0.5}rem` }}>
        <span style={{ color: '#55aa55', marginRight: '0.4rem' }}>●</span>
        {caseName(r.id)}
      </td>
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
  );
}

function DaySection({ day, cases, nav, expanded, toggle }) {
  return (
    <>
      <tr
        onClick={toggle}
        style={{ cursor: 'pointer', color: C.cyan, background: 'rgba(0,200,180,0.04)' }}
      >
        <td colSpan={7} style={{ ...td, paddingLeft: '3rem' }}>
          {expanded ? <ChevronDown size={11} style={{ marginRight: '0.4rem', verticalAlign: 'middle' }} /> : <ChevronRight size={11} style={{ marginRight: '0.4rem', verticalAlign: 'middle' }} />}
          <span style={{ fontSize: '0.65rem', letterSpacing: '0.08em' }}>DAY {day}</span>
          <span style={{ color: '#557755', marginLeft: '0.6rem', fontSize: '0.62rem' }}>{cases.length} case{cases.length !== 1 ? 's' : ''}</span>
        </td>
      </tr>
      {expanded && cases.map((r) => <CaseRow key={r.id} r={r} nav={nav} depth={3} />)}
    </>
  );
}

function MonthSection({ monthKey, days, nav, expanded, toggle, dayStates, toggleDay }) {
  const [, monthName] = monthKey.split('|');
  const total = Object.values(days).reduce((s, a) => s + a.length, 0);
  return (
    <>
      <tr
        onClick={toggle}
        style={{ cursor: 'pointer', color: C.gold, background: 'rgba(180,160,0,0.05)' }}
      >
        <td colSpan={7} style={{ ...td, paddingLeft: '1.8rem' }}>
          {expanded
            ? <FolderOpen size={13} style={{ marginRight: '0.5rem', verticalAlign: 'middle', color: C.gold }} />
            : <Folder size={13} style={{ marginRight: '0.5rem', verticalAlign: 'middle', color: C.gold }} />}
          <span style={{ fontSize: '0.68rem', letterSpacing: '0.1em' }}>{monthName.toUpperCase()}</span>
          <span style={{ color: '#888855', marginLeft: '0.7rem', fontSize: '0.62rem' }}>{total} case{total !== 1 ? 's' : ''}</span>
        </td>
      </tr>
      {expanded && Object.entries(days)
        .sort(([a], [b]) => Number(b) - Number(a))
        .map(([day, cases]) => (
          <DaySection
            key={day}
            day={day}
            cases={cases}
            nav={nav}
            expanded={!!dayStates[`${monthKey}|${day}`]}
            toggle={() => toggleDay(`${monthKey}|${day}`)}
          />
        ))
      }
    </>
  );
}

function YearSection({ year, months, nav, expanded, toggle, monthStates, toggleMonth, dayStates, toggleDay }) {
  const total = Object.values(months).reduce((s, d) => s + Object.values(d).reduce((s2, a) => s2 + a.length, 0), 0);
  return (
    <>
      <tr
        onClick={toggle}
        style={{ cursor: 'pointer', color: '#cc9944', background: 'rgba(160,120,0,0.07)' }}
      >
        <td colSpan={7} style={{ ...td, paddingLeft: '0.4rem', fontSize: '0.78rem', letterSpacing: '0.12em', fontWeight: 700 }}>
          {expanded
            ? <ChevronDown size={13} style={{ marginRight: '0.5rem', verticalAlign: 'middle' }} />
            : <ChevronRight size={13} style={{ marginRight: '0.5rem', verticalAlign: 'middle' }} />}
          {year}
          <span style={{ color: '#886633', marginLeft: '0.7rem', fontSize: '0.62rem', fontWeight: 400 }}>{total} total</span>
        </td>
      </tr>
      {expanded && Object.entries(months)
        .sort(([a], [b]) => Number(b.split('|')[0]) - Number(a.split('|')[0]))
        .map(([mk, days]) => (
          <MonthSection
            key={mk}
            monthKey={mk}
            days={days}
            nav={nav}
            expanded={!!monthStates[`${year}|${mk}`]}
            toggle={() => toggleMonth(`${year}|${mk}`)}
            dayStates={dayStates}
            toggleDay={toggleDay}
          />
        ))
      }
    </>
  );
}

export default function Investigations() {
  const nav = useNavigate();
  const [rows, setRows] = useState([]);
  const [busy, setBusy] = useState(true);
  const [yearStates, setYearStates] = useState({});
  const [monthStates, setMonthStates] = useState({});
  const [dayStates, setDayStates] = useState({});

  const load = async () => {
    setBusy(true);
    try {
      const r = await api.cases();
      const cases = r.cases || [];
      setRows(cases);
      // Auto-expand the most recent year, month, day
      if (cases.length) {
        const first = cases[0];
        const { year, month, day, monthName } = parseDate(first.id);
        const mk = `${month}|${monthName}`;
        setYearStates({ [year]: true });
        setMonthStates({ [`${year}|${mk}`]: true });
        setDayStates({ [`${mk}|${day}`]: true });
      }
    } catch {} finally { setBusy(false); }
  };

  useEffect(() => { load(); }, []);

  const tree = groupCases(rows);

  const toggle = (setter, key) => setter(s => ({ ...s, [key]: !s[key] }));

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
            {Object.entries(tree)
              .sort(([a], [b]) => Number(b) - Number(a))
              .map(([year, months]) => (
                <YearSection
                  key={year}
                  year={year}
                  months={months}
                  nav={nav}
                  expanded={!!yearStates[year]}
                  toggle={() => toggle(setYearStates, year)}
                  monthStates={monthStates}
                  toggleMonth={(k) => toggle(setMonthStates, k)}
                  dayStates={dayStates}
                  toggleDay={(k) => toggle(setDayStates, k)}
                />
              ))
            }
            {!rows.length && !busy && (
              <tr><td colSpan={7} style={{ ...td, color: '#557755' }}>No investigations yet. Submit a URL to begin.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </HudFrame>
  );
}
