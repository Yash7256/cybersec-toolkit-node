import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth, useUser } from '@clerk/react';
import { useTier } from '../context/TierContext';
import { apiGet } from '../utils/apiClient';
import {
  LayoutDashboard, Clock, ArrowLeft, ChevronLeft, ChevronRight,
  ScanLine, Wifi, Route, Shield, FileText, Globe2, Fingerprint,
  Search, MapPin, Contact, Crosshair, Crown, Layers, Zap,
} from 'lucide-react';

const TOOL_META = {
  dns:            { label: 'DNS Lookup',      icon: Search },
  whois:          { label: 'WHOIS',           icon: Contact },
  ping:           { label: 'Ping',            icon: Wifi },
  traceroute:     { label: 'Traceroute',      icon: Route },
  ssl:            { label: 'SSL Check',       icon: Shield },
  http_headers:   { label: 'HTTP Headers',    icon: FileText },
  subdomain:      { label: 'Subdomains',      icon: Search },
  geoip:          { label: 'Geo IP',          icon: MapPin },
  os_fingerprint: { label: 'OS Fingerprint',  icon: Fingerprint },
  port_scan:      { label: 'Port Scanner',    icon: ScanLine },
  webapp:         { label: 'Web App Scanner', icon: Globe2 },
  unified:        { label: 'Unified Scan',    icon: Crosshair },
  ai_chat:        { label: 'AI Chat',         icon: Crown },
  ai_analyze:     { label: 'AI Analyze',      icon: Crown },
};

const HISTORY_PAGE_SIZE = 15;

function timeAgo(isoString) {
  if (!isoString) return '';
  const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function resetsIn() {
  const now = new Date();
  const midnight = new Date(now);
  midnight.setHours(24, 0, 0, 0);
  const diff = midnight - now;
  const h = Math.floor(diff / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function UsageBar({ count, limit }) {
  const pct = limit > 0 ? (count / limit) * 100 : 0;
  const color =
    pct >= 100 ? '#FF4D4D' :
    pct >= 60  ? '#F97316' :
    pct >= 30  ? '#FBBF24' :
    '#22d3ee';

  return (
    <div className="usage-bar-track">
      <div
        className="usage-bar-fill"
        style={{
          '--bar-width': `${Math.min(pct, 100)}%`,
          background: `linear-gradient(90deg, ${color}cc 0%, ${color} 100%)`,
          boxShadow: `0 0 8px ${color}44`,
        }}
      />
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const { getToken, signOut } = useAuth();
  const { user } = useUser();
  const { tier, toolUsage, limit, unlimited, loading: tierLoading, refresh: refreshTier } = useTier();

  const [history, setHistory] = useState([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyPage, setHistoryPage] = useState(0);
  const [historyCursors, setHistoryCursors] = useState([null]);
  const [historyHasNext, setHistoryHasNext] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyFilter, setHistoryFilter] = useState('');

  const fetchHistory = useCallback(async (page = 0, filter = '') => {
    setHistoryLoading(true);
    try {
      const params = { limit: HISTORY_PAGE_SIZE };
      if (filter) params.tool = filter;
      if (historyCursors[page]) params.cursor = historyCursors[page];
      const res = await apiGet('/api/runs', params, getToken);
      if (res && res.ok) {
        const data = await res.json();
        const runs = data.runs || [];
        setHistory(runs.map((run) => ({ ...run, tool_name: String(run.tool || '').toLowerCase(), created_at: run.createdAt })));
        setHistoryTotal(runs.length);
        setHistoryHasNext(Boolean(data.nextCursor));
        if (data.nextCursor) {
          setHistoryCursors((previous) => {
            const next = [...previous];
            next[page + 1] = data.nextCursor;
            return next;
          });
        }
      }
    } catch {
      // silent
    } finally {
      setHistoryLoading(false);
    }
  }, [getToken, historyCursors]);

  useEffect(() => { refreshTier(); }, [refreshTier]);
  // Filter changes reset pagination in the input handler below.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { fetchHistory(historyPage, historyFilter); }, [fetchHistory, historyPage, historyFilter]);

  const historyPages = historyHasNext ? historyPage + 2 : historyPage + 1;

  const email = user?.primaryEmailAddress?.emailAddress || user?.emailAddresses?.[0]?.emailAddress || '';
  const firstName = user?.firstName || email.split('@')[0] || 'there';
  const totalTools = Object.keys(TOOL_META).length;
  const dailyLimit = limit ?? 5;

  return (
    <div className="dash-fade-in flex flex-col gap-8 h-full overflow-y-auto pr-2">
      {/* ── Header / Hero ───────────────────────────────────────── */}
      <section>
        <div className="flex items-start gap-3 mb-4">
          <button
            onClick={() => navigate(-1)}
            className="dash-btn dash-btn-back"
            aria-label="Go back"
          >
            <ArrowLeft className="w-4 h-4" style={{ color: '#a78bfa' }} />
          </button>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2.5 mb-1">
              <LayoutDashboard className="w-6 h-6 flex-shrink-0" style={{ color: '#a78bfa' }} />
              <h1 className="text-2xl font-bold tracking-tight" style={{ color: '#f5f0ff' }}>
                Dashboard
              </h1>
            </div>
            <p className="text-sm ml-[38px]" style={{ color: '#6b5fa0' }}>
              Welcome back, <span style={{ color: '#c4b5fd' }}>{firstName}</span>
            </p>
          </div>
        </div>

        {/* Quick-info pills */}
        <div className="flex flex-wrap gap-2.5 ml-[38px]">
          <div className="dash-pill flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full"
            style={{ background: 'rgba(124,58,237,0.12)', border: '1px solid rgba(124,58,237,0.2)', color: '#c4b5fd' }}>
            <Crown className="w-3.5 h-3.5" style={{ color: '#a78bfa' }} />
            {unlimited ? 'Pro' : 'Free'} Plan
          </div>
          <div className="dash-pill flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full"
            style={{ background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(199,183,232,0.12)', color: '#a78bfa' }}>
            <Layers className="w-3.5 h-3.5" />
            {totalTools} Tools
          </div>
          <div className="dash-pill flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full"
            style={{ background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(199,183,232,0.12)', color: '#a78bfa' }}>
            <Zap className="w-3.5 h-3.5" />
            {unlimited ? 'Unlimited scans' : `${dailyLimit}/tool/day`}
          </div>
        </div>
      </section>

      {/* ── Section 1: Limit Meter ───────────────────────────────── */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold tracking-wide uppercase" style={{ color: '#6b5fa0' }}>Daily Usage</h2>
          <button
            onClick={refreshTier}
            disabled={tierLoading}
            className="dash-btn dash-btn-refresh"
          >
            {tierLoading ? 'Refreshing…' : '↻ Refresh'}
          </button>
        </div>
        {tierLoading ? (
          <div className="text-sm" style={{ color: '#6b5fa0' }}>Loading usage data...</div>
        ) : unlimited ? (
          <div className="flex items-center gap-2 text-sm" style={{ color: '#22d3ee' }}>
            <Crown className="w-4 h-4" /> Unlimited — no daily limits apply to your account
          </div>
        ) : (
          <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(185px, 1fr))' }}>
            {Object.entries(TOOL_META).map(([tool, meta], idx) => {
              const apiData = toolUsage[tool];
              const count   = apiData?.count     ?? 0;
              const remaining  = apiData?.remaining ?? dailyLimit;
              const isExhausted = remaining === 0;
              const remainColor =
                isExhausted ? '#FF4D4D' :
                remaining <= 1 ? '#F97316' :
                remaining <= 2 ? '#FBBF24' :
                '#22d3ee';
              const Icon = meta.icon;
              return (
                <div
                  key={tool}
                  className={`daily-card${isExhausted ? ' exhausted' : ''}`}
                  style={{ animationDelay: `${idx * 40}ms` }}
                >
                  {/* Row 1: Icon + name + badge */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 min-w-0">
                      <Icon
                        className="card-icon w-4 h-4 flex-shrink-0"
                        style={{ color: isExhausted ? '#FF4D4D' : '#a78bfa' }}
                      />
                      <span className="text-xs font-semibold truncate" style={{ color: '#c4b5fd' }}>
                        {meta.label}
                      </span>
                    </div>
                    {isExhausted && (
                      <span className="text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded-md"
                        style={{ background: 'rgba(255,77,77,0.15)', color: '#FF4D4D' }}>
                        Limit
                      </span>
                    )}
                  </div>

                  {/* Row 2: Primary stat — "3 of 5 remaining" */}
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-2xl font-bold leading-none font-mono" style={{ color: remainColor }}>
                      {remaining}
                    </span>
                    <span className="text-[10px] font-medium" style={{ color: '#6b5fa0' }}>
                      of {dailyLimit} left
                    </span>
                  </div>

                  {/* Row 3: Progress bar */}
                  <UsageBar count={count} limit={dailyLimit} />

                  {/* Row 4: Usage detail + reset timer */}
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-medium" style={{ color: count === 0 ? '#4a3960' : '#6b5fa0' }}>
                      {count === 0 ? 'Ready to use' : `${count} scan${count === 1 ? '' : 's'} used`}
                    </span>
                    <span className="text-[10px]" style={{ color: '#4a3960' }}>
                      resets in {resetsIn()}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>


      {/* ── Section 2: Account ──────────────────────────────────── */}
      <section
        className="dash-section-card rounded-xl p-4 flex flex-col sm:flex-row sm:items-center gap-4"
        style={{ background: 'rgba(19, 9, 33, 0.6)', border: '1px solid rgba(199, 183, 232, 0.1)' }}
      >
        <div className="flex flex-col gap-1 flex-1">
          <h2 className="text-sm font-semibold" style={{ color: '#c4b5fd' }}>Account</h2>
          <span className="text-sm" style={{ color: '#e9d5ff' }}>{email || 'Signed in'}</span>
          <span className="text-xs font-mono" style={{ color: '#6b5fa0' }}>
            Tier: {tier?.toUpperCase() || 'FREE'} · {unlimited ? 'Unlimited' : `${limit ?? 5}/tool/day`}
          </span>
        </div>
        <button
          onClick={() => signOut()}
          className="dash-btn dash-btn-signout self-start"
        >
          Sign Out
        </button>
      </section>

      {/* ── Section 3: Scan History ────────────────────────────── */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold" style={{ color: '#c4b5fd' }}>
            <Clock className="w-4 h-4 inline mr-1.5" style={{ color: '#a78bfa' }} />
            Scan History
          </h2>
          <div className="flex items-center gap-2">
            <select
              value={historyFilter}
              onChange={(e) => {
                setHistoryFilter(e.target.value);
                setHistoryPage(0);
                setHistoryCursors([null]);
                setHistoryHasNext(false);
              }}
              className="dash-select"
            >
              <option value="">All tools</option>
              {Object.entries(TOOL_META).map(([key, meta]) => (
                <option key={key} value={key}>{meta.label}</option>
              ))}
            </select>
          </div>
        </div>

        <div
          className="dash-section-card rounded-xl overflow-hidden"
          style={{ background: 'rgba(19, 9, 33, 0.6)', border: '1px solid rgba(199, 183, 232, 0.1)' }}
        >
          {historyLoading ? (
            <div className="p-8 text-center text-sm" style={{ color: '#6b5fa0' }}>Loading history...</div>
          ) : history.length === 0 ? (
            <div className="p-8 text-center text-sm" style={{ color: '#6b5fa0' }}>No scan history yet. Run a tool to get started.</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(199,183,232,0.1)' }}>
                  <th className="text-left px-4 py-2.5 font-medium text-xs" style={{ color: '#6b5fa0' }}>Tool</th>
                  <th className="text-left px-4 py-2.5 font-medium text-xs" style={{ color: '#6b5fa0' }}>Target</th>
                  <th className="text-right px-4 py-2.5 font-medium text-xs" style={{ color: '#6b5fa0' }}>Time</th>
                </tr>
              </thead>
              <tbody>
                {history.map((row) => {
                  const meta = TOOL_META[row.tool_name] || { label: row.tool_name, icon: ScanLine };
                  const Icon = meta.icon;
                  return (
                    <tr
                      key={row.id}
                      className="dash-table-row"
                      style={{ borderBottom: '1px solid rgba(199,183,232,0.06)' }}
                    >
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <Icon className="row-icon w-3.5 h-3.5" style={{ color: '#a78bfa' }} />
                          <span style={{ color: '#e9d5ff' }}>{meta.label}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-xs" style={{ color: '#c4b5fd' }}>
                        {row.target}
                      </td>
                      <td className="px-4 py-2.5 text-right text-xs" style={{ color: '#6b5fa0' }}>
                        {timeAgo(row.created_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}

          {/* Pagination */}
          {historyPages > 1 && (
            <div
              className="flex items-center justify-between px-4 py-2.5"
              style={{ borderTop: '1px solid rgba(199,183,232,0.1)' }}
            >
              <span className="text-xs" style={{ color: '#6b5fa0' }}>
                {historyTotal} shown · Page {historyPage + 1} of {historyPages}
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setHistoryPage((p) => Math.max(0, p - 1))}
                  disabled={historyPage === 0}
                  className="dash-btn dash-btn-page"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setHistoryPage((p) => p + 1)}
                  disabled={!historyHasNext}
                  className="dash-btn dash-btn-page"
                  aria-label="Next page"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
