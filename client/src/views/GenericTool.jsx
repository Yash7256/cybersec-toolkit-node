import { useCallback, useEffect, useRef, useState } from 'react';
import { useGetToken } from '../utils/useGetToken';
import { apiGet, apiPost, apiPostAndPoll } from '../utils/apiClient';
import GeoIPResultsPage, { ScanInputBar } from '../components/geoip/GeoIPResultsPage';
import {
  Activity,
  ArrowRight,
  BarChart3,
  Building2,
  CheckCircle2,
  CircleDot,
  Cloud,
  Cpu,
  Database,
  ExternalLink,
  FileText,
  Fingerprint,
  Gauge,
  Globe2,
  Heading,
  Info,
  Lock,
  MapPin,
  Network,
  Radio,
  Route,
  Search,
  Server,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Timer,
  WifiOff,
  X,
  Zap,
} from 'lucide-react';

const TOOL_META = {
  ping:       { name: 'Ping',        icon: Zap,     endpoint: '/api/tools/ping',         param: 'target', placeholder: 'Hostname or IP (e.g. 8.8.8.8)' },
  traceroute: { name: 'Traceroute',  icon: Route,   endpoint: '/api/tools/traceroute',   param: 'target', placeholder: 'Hostname or IP (e.g. example.com)' },
  ssl:        { name: 'SSL Check',   icon: Lock,    endpoint: '/api/tools/ssl',          param: 'host',   placeholder: 'Domain (e.g. example.com)' },
  headers:    { name: 'HTTP Headers',icon: Heading, endpoint: '/api/tools/http_headers', param: 'target', placeholder: 'URL (e.g. https://example.com)' },
  subdomains: { name: 'Subdomains',  icon: Search,  endpoint: '/api/tools/subdomain',    param: 'domain', placeholder: 'Domain (e.g. example.com)' },
  geo:        { name: 'GeoIP',       icon: MapPin,  endpoint: '/api/tools/geoip',        param: 'target', placeholder: 'Public IP address or hostname (e.g. 8.8.8.8)' },
  osfingerprint: { name: 'OS Fingerprinting', icon: Fingerprint, endpoint: '/api/tools/os-fingerprint', param: 'target', placeholder: 'Hostname or IP (e.g. scanme.nmap.org)' },
};

const PING_LIVE_WINDOW = 48;

const roundMetric = (value, digits = 2) => (
  Number.isFinite(value) ? Number(value.toFixed(digits)) : null
);

const classifyPingQuality = (avg) => {
  if (avg == null) return 'Unknown';
  if (avg <= 20) return 'Excellent';
  if (avg <= 50) return 'Good';
  if (avg <= 100) return 'Moderate';
  return 'Poor';
};

const classifyLossSeverity = (loss) => {
  if (loss <= 0) return 'Stable';
  if (loss <= 2) return 'Minor';
  if (loss <= 5) return 'Noticeable';
  return 'Severe';
};

const classifyJitter = (jitter) => {
  if (jitter == null) return 'Unknown';
  if (jitter <= 5) return 'Stable';
  if (jitter <= 20) return 'Variable';
  return 'Unstable';
};

const summarizeLiveDistribution = (values) => {
  if (!values.length) return null;
  if (values.length === 1) return `Single response at ${values[0].toFixed(1)}ms`;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted[Math.floor(sorted.length / 2)];
  const near = sorted.filter((value) => Math.abs(value - mid) <= Math.max(2, mid * 0.12));
  if (near.length >= Math.max(2, Math.floor(values.length / 2))) {
    return `Most responses between ${Math.min(...near).toFixed(1)}-${Math.max(...near).toFixed(1)}ms`;
  }
  return `Responses ranged from ${Math.min(...values).toFixed(1)}-${Math.max(...values).toFixed(1)}ms`;
};

const detectLiveTrend = (values, loss) => {
  if (loss >= 5) return 'Packet loss detected';
  if (values.length < 3) return 'Collecting live samples';
  const baseline = [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
  if (values.some((value) => value > baseline * 1.8 && value - baseline > 20)) return 'Latency spike detected';
  if (values[values.length - 1] > values[0] + Math.max(15, values[0] * 0.4)) return 'Connection becoming slower';
  if (Math.max(...values) - Math.min(...values) <= Math.max(3, baseline * 0.15)) return 'Consistent latency';
  return 'Minor latency variation';
};

const calculateLivePingResult = (previous, next) => {
  const prevTimeline = Array.isArray(previous?.response_timeline) ? previous.response_timeline : [];
  const nextTimeline = Array.isArray(next?.response_timeline) ? next.response_timeline : [];
  const combined = [...prevTimeline, ...nextTimeline]
    .slice(-PING_LIVE_WINDOW)
    .map((item, index) => ({ ...item, packet: index + 1 }));
  const values = combined
    .map((item) => Number(item.latency_ms))
    .filter((value) => Number.isFinite(value));
  const sent = combined.length;
  const received = values.length;
  const loss = sent ? ((sent - received) / sent) * 100 : 0;
  const avg = values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
  const jitter = values.length > 1
    ? values.slice(1).reduce((sum, value, index) => sum + Math.abs(value - values[index]), 0) / (values.length - 1)
    : null;
  const variance = values.length > 1
    ? values.reduce((sum, value) => sum + ((value - avg) ** 2), 0) / values.length
    : values.length ? 0 : null;
  const stddev = variance == null ? null : Math.sqrt(variance);
  const stability = Math.max(0, Math.min(100, Math.round(
    100
    - Math.min(55, loss * 9)
    - (jitter == null ? 0 : Math.min(25, jitter * 1.5))
    - (stddev == null ? 0 : Math.min(15, stddev))
    - (avg != null && avg > 100 ? Math.min(20, (avg - 100) / 10) : 0)
  )));

  return {
    ...next,
    response_timeline: combined,
    packets_sent: sent,
    packets_received: received,
    packet_loss_pct: roundMetric(loss),
    min_ms: values.length ? roundMetric(Math.min(...values)) : null,
    avg_ms: roundMetric(avg),
    max_ms: values.length ? roundMetric(Math.max(...values)) : null,
    jitter_ms: roundMetric(jitter),
    jitter_label: classifyJitter(jitter),
    packet_loss_severity: classifyLossSeverity(loss),
    connection_quality: classifyPingQuality(avg),
    availability_pct: sent ? roundMetric((received / sent) * 100, 1) : 0,
    std_deviation_ms: roundMetric(stddev),
    variance_ms: roundMetric(variance),
    latency_distribution: summarizeLiveDistribution(values),
    latency_trend: detectLiveTrend(values, loss),
    stability_score: stability,
    heat_indicator: stability >= 85 ? 'green' : stability >= 65 ? 'yellow' : 'red',
    status_badges: [
      received ? 'ONLINE' : 'OFFLINE',
      received ? (stability >= 85 ? 'STABLE' : stability >= 65 ? 'VARIABLE' : 'UNSTABLE') : null,
      avg != null && avg <= 50 ? 'LOW LATENCY' : avg != null && avg > 100 ? 'HIGH LATENCY' : null,
    ].filter(Boolean),
    last_checked: 'live',
  };
};

const traceRouteSignature = (data) => (
  (data?.hops || []).map((hop) => hop.ip || '*').join('>')
);

const calculateLiveTracerouteResult = (previous, next) => {
  const previousSignature = traceRouteSignature(previous);
  const nextSignature = traceRouteSignature(next);
  const routeChanged = Boolean(previousSignature && nextSignature && previousSignature !== nextSignature);
  const previousVisible = (previous?.hops || []).filter((hop) => hop?.rtt_ms != null);
  const nextVisible = (next?.hops || []).filter((hop) => hop?.rtt_ms != null);
  const previousFinal = previousVisible.at(-1)?.rtt_ms;
  const nextFinal = nextVisible.at(-1)?.rtt_ms;
  const latencyDelta = Number.isFinite(previousFinal) && Number.isFinite(nextFinal)
    ? roundMetric(nextFinal - previousFinal, 1)
    : null;
  return {
    ...next,
    live_samples: (previous?.live_samples || 1) + 1,
    route_changed: routeChanged,
    previous_route_signature: previousSignature || null,
    current_route_signature: nextSignature || null,
    route_change_summary: routeChanged ? 'Route path changed during live monitoring.' : 'Route path unchanged during live monitoring.',
    final_latency_delta_ms: latencyDelta,
    live_started: previous?.live_started || 'active',
  };
};

function AnimatedDonutChart({ passedPct, passedCount, failedCount }) {
  const [animPct, setAnimPct] = useState(0);
  const [animFailed, setAnimFailed] = useState(0);
  const [animPassed, setAnimPassed] = useState(0);
  const [hovered, setHovered] = useState(null);

  const cx = 104, cy = 104, r = 80, sw = 8;
  const C = 2 * Math.PI * r;
  const total = passedCount + failedCount;
  const failedPctVal = total ? Math.round((failedCount / total) * 100) : 0;
  const passedPctVal = total ? Math.round((passedCount / total) * 100) : 0;

  useEffect(() => {
    // Animation state intentionally resets when a new scan result arrives.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setAnimPct(0);
    setAnimFailed(0);
    setAnimPassed(0);
    const start = performance.now();
    const duration = 1000;
    const tick = (now) => {
      const t = Math.min((now - start) / duration, 1);
      const e = 1 - Math.pow(1 - t, 3);
      setAnimPct(e * passedPct);
      setAnimFailed(Math.round(e * failedCount));
      setAnimPassed(Math.round(e * passedCount));
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [passedPct, passedCount, failedCount]);

  const passedLen = Math.max((animPct / 100) * C, C * 0.03);

  const showFailed = hovered === 'failed';
  const showPassed = hovered === 'passed';

  return (
    <div className="relative grid h-52 w-52 place-items-center">
      <svg width="208" height="208" viewBox="0 0 208 208" className="absolute inset-0">
        <defs>
          <filter id="dg-p">
            <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#7CFF9A" floodOpacity={0.35} />
          </filter>
          <filter id="dg-f">
            <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#FF4D4D" floodOpacity={0.35} />
          </filter>
        </defs>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#FF4D4D" strokeWidth={sw} opacity={0.88}
          className="cursor-pointer transition-all duration-200"
          style={{ transformOrigin: '104px 104px', transform: hovered === 'failed' ? 'scale(1.04)' : 'scale(1)' }}
          onMouseEnter={() => setHovered('failed')}
          onMouseLeave={() => setHovered(null)}
          filter={hovered === 'failed' ? 'url(#dg-f)' : undefined}
        />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#7CFF9A" strokeWidth={sw} strokeLinecap="round"
          strokeDasharray={`${passedLen} ${C}`} strokeDashoffset={0}
          className="cursor-pointer transition-all duration-200"
          style={{ transformOrigin: '104px 104px', transform: `rotate(-90deg)${hovered === 'passed' ? ' scale(1.04)' : ''}` }}
          onMouseEnter={() => setHovered('passed')}
          onMouseLeave={() => setHovered(null)}
          filter={hovered === 'passed' ? 'url(#dg-p)' : undefined}
        />
      </svg>
      <div className="z-10 flex flex-col items-center justify-center text-center transition-all duration-200">
        {showFailed ? (
          <>
            <span className="text-[52px] font-bold leading-none tracking-tighter text-[#FF4D4D]">{animFailed}</span>
            <span className="mt-0.5 text-xl font-medium leading-none text-[#FF4D4D]">Failed</span>
            <span className="mt-0.5 text-sm leading-none text-[#A69BBE]">{failedPctVal}% of total</span>
          </>
        ) : showPassed ? (
          <>
            <span className="text-[52px] font-bold leading-none tracking-tighter text-[#7CFF9A]">{animPassed}</span>
            <span className="mt-0.5 text-xl font-medium leading-none text-[#7CFF9A]">Passed</span>
            <span className="mt-0.5 text-sm leading-none text-[#A69BBE]">{passedPctVal}% of total</span>
          </>
        ) : (
          <>
            <span className="text-[52px] font-bold leading-none tracking-tighter text-[#F4F2FF]">{animFailed}</span>
            <span className="mt-0.5 text-xl font-medium leading-none text-[#FF4D4D]">Failed</span>
            <span className="mt-0.5 text-sm leading-none text-[#A69BBE]">{failedPctVal}% of total</span>
            <div className="my-1 h-px w-8 bg-white/[0.08]" />
            <span className="text-sm leading-none text-[#7CFF9A]">{animPassed} Passed</span>
          </>
        )}
      </div>
    </div>
  );
}

export default function GenericTool({ toolId }) {
  const meta = TOOL_META[toolId];
  const [target, setTarget] = useState('');
  const [count] = useState(4);
  const [maxHops, setMaxHops] = useState(30);
  const [liveMode, setLiveMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [copied, setCopied] = useState('');
  const [activeOsTab, setActiveOsTab] = useState('security');
  const [activePingTab, setActivePingTab] = useState('monitoring');
  const [headersTab, setHeadersTab] = useState('network');
  const liveRequestActive = useRef(false);
  const streamAbortRef = useRef(null);
  const getToken = useGetToken();
  const Icon = meta?.icon;

  const applySubdomainStreamEvent = useCallback((event) => {
    if (!event || typeof event !== 'object') return;
    if (event.type === 'init') {
      setResults({
        ...event.data,
        checked_count: 0,
        total_candidates: event.data?.total_checked || 0,
        scanning: true,
      });
      return;
    }
    if (event.type === 'wildcard') {
      setResults((previous) => ({
        ...(previous || {}),
        wildcard_detected: Boolean(event.wildcard_detected),
        wildcard_ips: event.wildcard_ips || [],
        scanning: true,
      }));
      return;
    }
    if (event.type === 'stage') {
      setResults((previous) => ({
        ...(previous || {}),
        scan_stage: event.stage,
        scan_message: event.message,
        scanning: true,
      }));
      return;
    }
    if (event.type === 'candidate' && event.row) {
      setResults((previous) => {
        const current = previous || { domain: target, found: [], total_found: 0 };
        const existingRows = Array.isArray(current.found) ? current.found : [];
        const rowKey = event.row.subdomain || event.row.name;
        const nextRows = existingRows.some((row) => (row.subdomain || row.name) === rowKey)
          ? existingRows.map((row) => ((row.subdomain || row.name) === rowKey ? { ...row, ...event.row } : row))
          : [...existingRows, event.row];
        return {
          ...current,
          found: nextRows,
          checked_count: event.progress?.checked ?? current.checked_count ?? nextRows.length,
          total_candidates: event.progress?.total ?? current.total_candidates ?? current.total_checked ?? nextRows.length,
          total_checked: event.progress?.total ?? current.total_checked ?? nextRows.length,
          total_found: event.progress?.found ?? nextRows.filter((row) => row?.resolved).length,
          http_checked: event.progress?.http_checked ?? current.http_checked,
          http_total: event.progress?.http_total ?? current.http_total,
          scanning: true,
        };
      });
      return;
    }
    if (event.type === 'done') {
      setResults({
        ...event.data,
        checked_count: event.data?.total_checked || 0,
        total_candidates: event.data?.total_checked || 0,
        scanning: false,
      });
      return;
    }
    if (event.type === 'error') {
      setResults({ error: event.error || 'Subdomain stream failed' });
    }
  }, [target]);

  const runSubdomainStream = useCallback(async () => {
    streamAbortRef.current?.abort();
    const controller = new AbortController();
    streamAbortRef.current = controller;
    setLoading(true);
    setResults({
      domain: target,
      found: [],
      total_checked: 0,
      total_candidates: 0,
      checked_count: 0,
      total_found: 0,
      wildcard_detected: false,
      wildcard_ips: [],
      scan_time_ms: 0,
      dns_time_ms: 0,
      http_time_ms: 0,
      scanning: true,
    });
    try {
      const result = await apiPostAndPoll('/api/tools/subdomain', { domain: target }, getToken, {
        signal: controller.signal,
        onProgress: (pct, run) => applySubdomainStreamEvent({ type: 'stage', stage: `progress_${pct}`, message: run.status }),
      });
      if (!result.response.ok) throw new Error(result.payload?.error?.message || result.payload?.error || `HTTP ${result.response.status}`);
      applySubdomainStreamEvent({ type: 'done', data: result.data });
    } catch (error) {
      if (error.name !== 'AbortError') setResults({ error: error.message });
    } finally {
      if (streamAbortRef.current === controller) streamAbortRef.current = null;
      setLoading(false);
    }
  }, [applySubdomainStreamEvent, getToken, target]);

  const applyGeoStreamEvent = useCallback((event) => {
    if (!event || typeof event !== 'object') return;
    if (event.type === 'init') {
      setResults({
        ...event.data,
        scanning: true,
      });
      return;
    }
    if (event.type === 'stage') {
      setResults((previous) => ({
        ...(previous || { target }),
        scan_stage: event.stage,
        scan_message: event.message,
        scanning: true,
      }));
      return;
    }
    if (event.type === 'done') {
      setResults({
        ...event.data,
        scanning: false,
      });
      return;
    }
    if (event.type === 'error') {
      setResults({ error: event.error || 'GeoIP stream failed' });
    }
  }, [target]);

  const runOsStream = useCallback(async () => {
    streamAbortRef.current?.abort();
    const controller = new AbortController();
    streamAbortRef.current = controller;
    setLoading(true);
    setResults({
      target,
      detected_os: null,
      family: null,
      confidence: 0,
      os_probabilities: [],
      fingerprint_timeline: [],
      fingerprint_sources: [],
      open_ports: [],
      scan_duration_seconds: 0,
      scan_stage: 'init',
      scan_message: 'Starting OS fingerprinting',
      scanning: true,
    });
    try {
      throw new Error('OS fingerprinting is not available in this server build yet.');
    } catch (error) {
      if (error.name !== 'AbortError') setResults({ error: error.message });
    } finally {
      if (streamAbortRef.current === controller) streamAbortRef.current = null;
      setLoading(false);
    }
  }, [target]);

  const runGeoStream = useCallback(async () => {
    streamAbortRef.current?.abort();
    const controller = new AbortController();
    streamAbortRef.current = controller;
    setLoading(true);
    setResults({
      target,
      ip: null,
      resolved_ips: [],
      ip_results: [],
      provider: null,
      cached: false,
      scan_duration_seconds: null,
      fallback_note: null,
      abuse_contact: null,
      scanning: true,
      scan_stage: 'init',
      scan_message: 'Starting GeoIP lookup',
    });
    try {
      const response = await apiGet('/api/tools/geoip', { target }, getToken, null, { signal: controller.signal });
      if (response.status === 429) {
        window.dispatchEvent(new CustomEvent('tier:limit_reached'));
        throw new Error('Daily scan limit reached. Upgrade to continue scanning.');
      }
      if (!response.ok) throw new Error(`GeoIP lookup failed with HTTP ${response.status}`);
      const payload = await response.json();
      applyGeoStreamEvent({ type: 'done', data: payload.data || payload });
    } catch (error) {
      if (error.name !== 'AbortError') setResults({ error: error.message });
    } finally {
      if (streamAbortRef.current === controller) streamAbortRef.current = null;
      setLoading(false);
    }
  }, [applyGeoStreamEvent, getToken, target]);

  const run = useCallback(async ({ silent = false, appendLive = false } = {}) => {
    if (!target || !meta) return;
    if (appendLive && liveRequestActive.current) return;
    if (appendLive) liveRequestActive.current = true;
    if (toolId === 'subdomains' && !appendLive) {
      await runSubdomainStream();
      return;
    }
    if (toolId === 'geo' && !appendLive) {
      await runGeoStream();
      return;
    }
    if (toolId === 'osfingerprint' && !appendLive) {
      await runOsStream();
      return;
    }
    if (!silent) {
      setLoading(true);
      if (toolId === 'subdomains') {
        setResults({
          domain: target,
          found: [],
          total_checked: 0,
          total_found: 0,
          wildcard_detected: false,
          wildcard_ips: [],
          scan_time_ms: 0,
          dns_time_ms: 0,
          http_time_ms: 0,
          scanning: true,
        });
      }
    }
    try {
      const body = { [meta.param]: target };
      if (toolId === 'ping') body.count = count;
      if (toolId === 'traceroute') body.max_hops = maxHops;
      const r = await apiPost(meta.endpoint, body, getToken);
      const contentType = r.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new Error(`Expected JSON from ${meta.endpoint}, but received ${contentType || 'an HTML response'}. Check that the API server is running and the Vite proxy is pointing at it.`);
      }
      const payload = await r.json();
      if (!r.ok) {
        throw new Error(payload.detail || payload.error || `Request failed with HTTP ${r.status}`);
      }
      const nextData = payload.data || payload;
      setResults((previous) => (
        appendLive && toolId === 'ping' && previous && !previous.error
          ? calculateLivePingResult(previous, nextData)
          : appendLive && toolId === 'traceroute' && previous && !previous.error
            ? calculateLiveTracerouteResult(previous, nextData)
          : nextData
      ));
    } catch (e) {
      setResults((previous) => (appendLive && previous && !previous.error ? { ...previous, live_error: e.message } : { error: e.message }));
    } finally {
      if (appendLive) liveRequestActive.current = false;
      if (!silent) setLoading(false);
    }
  }, [count, getToken, maxHops, meta, runGeoStream, runOsStream, runSubdomainStream, target, toolId]);

  useEffect(() => {
    if (!['ping', 'traceroute'].includes(toolId) || !liveMode || !target) return undefined;
    const id = window.setInterval(() => run({ silent: true, appendLive: true }), toolId === 'traceroute' ? 7000 : 3000);
    return () => window.clearInterval(id);
  }, [toolId, liveMode, target, run]);

  useEffect(() => () => {
    streamAbortRef.current?.abort();
  }, []);

  if (!meta) return <div className="text-gray-500 text-center mt-20">Tool not found: {toolId}</div>;

  const renderValue = (val) => {
    if (typeof val === 'object' && val !== null) return <pre className="text-gray-300 text-sm font-mono whitespace-pre-wrap">{JSON.stringify(val, null, 2)}</pre>;
    return <span className="text-gray-200 text-sm font-mono break-all">{String(val)}</span>;
  };

  const renderField = (label, value) => {
    if (value === null || value === undefined || value === '') return null;
    return (
      <div className="flex gap-4 p-4 bg-dark-800/50 border border-dark-600 rounded-xl hover:bg-dark-700/50 transition-colors">
        <span className="w-36 text-xs text-gray-500 font-mono shrink-0 pt-0.5">{label}</span>
        {Array.isArray(value) ? (
          <span className="text-gray-200 text-sm font-mono break-all">{value.join(', ')}</span>
        ) : typeof value === 'boolean' ? (
          <span className={`text-sm font-mono ${value ? 'text-[#F97316]' : 'text-[#7CFF9A]'}`}>{value ? 'Yes' : 'No'}</span>
        ) : String(value).startsWith('http') ? (
          <a className="text-sm font-mono text-purple-300 hover:text-purple-200 break-all" href={String(value)} target="_blank" rel="noreferrer">{String(value)}</a>
        ) : (
          <span className="text-gray-200 text-sm font-mono break-all">{String(value)}</span>
        )}
      </div>
    );
  };

  const copyText = async (label, text) => {
    if (!text) return;
    await navigator.clipboard.writeText(text);
    setCopied(label);
    window.setTimeout(() => setCopied(''), 1200);
  };

  const downloadText = (filename, content, type = 'text/plain') => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  const toggleLiveMode = () => {
    if (!target) return;
    if (liveMode) {
      setLiveMode(false);
      liveRequestActive.current = false;
      return;
    }
    setResults(null);
    setLiveMode(true);
    run({ silent: false, appendLive: true });
  };

  const exportJson = () => {
    if (!results) return;
    downloadText(
      `headers-${results.target || 'result'}.json`,
      JSON.stringify(results, null, 2),
      'application/json',
    );
  };

  const exportCsv = () => {
    if (!results) return;
    const headers = Object.entries(results.headers || {});
    const rows = [['Header', 'Value'], ...headers.map(([k, v]) => [k, String(v)])];
    const csv = rows.map((r) => r.map((c) => `"${String(c).replaceAll('"', '""')}"`).join(',')).join('\n');
    downloadText(`headers-${results.target || 'result'}.csv`, csv, 'text/csv');
  };

  const shareReport = async () => {
    if (!results) return;
    const text = `HTTP Headers: ${results.url || results.target}\n` +
      `Status: ${results.status_code}\n` +
      `Security Score: ${results.security_score ?? 'N/A'}/100\n` +
      `Risk Level: ${results.risk_level || 'Unknown'}\n` +
      `Headers Present: ${results.security_headers?.present?.length || 0}/${(results.security_headers?.present?.length || 0) + (results.security_headers?.missing?.length || 0)}`;
    if (navigator.share) {
      await navigator.share({ title: 'HTTP Headers scan report', text }).catch(() => {});
      return;
    }
    await navigator.clipboard.writeText(text).catch(() => {});
    setCopied('headers-share');
    window.setTimeout(() => setCopied(''), 1200);
  };

  const renderGeoResults = (data) => (
    <GeoIPResultsPage
      result={data}
      copied={copied}
      onCopy={copyText}
      onDownload={downloadText}
    />
  );

  const pct = (value) => Math.max(0, Math.min(100, Number(value || 0)));

  const chip = (text, tone = 'neutral') => {
    const colors = {
      neutral: 'border-dark-600 text-gray-300 bg-dark-800/60',
      good: 'border-[#7CFF9A]/25 text-[#7CFF9A] bg-[#7CFF9A]/10',
      warn: 'border-[#F97316]/25 text-[#F97316] bg-[#F97316]/10',
      bad: 'border-[#FF4D4D]/25 text-[#FF4D4D] bg-[#FF4D4D]/10',
      info: 'border-purple-400/25 text-purple-200 bg-purple-500/10',
    };
    return <span className={`text-xs font-mono px-2.5 py-1 rounded-lg border ${colors[tone] || colors.neutral}`}>{text}</span>;
  };

  const renderMetricCard = (IconCmp, label, value, subtext) => (
    <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-4 min-w-0">
      <div className="flex items-center gap-2 text-gray-500 text-xs font-mono uppercase">
        <IconCmp className="w-4 h-4" />
        <span>{label}</span>
      </div>
      <div className="text-gray-100 text-sm font-semibold mt-3 break-words">{value || 'Unknown'}</div>
      {subtext && <div className="text-gray-500 text-xs mt-1 break-words">{subtext}</div>}
    </div>
  );

  const pingSeries = (data) => Array.isArray(data.response_timeline) ? data.response_timeline : [];

  const renderPingGraph = (data) => {
    const series = pingSeries(data);
    const values = series
      .map((item) => Number(item.latency_ms))
      .filter((value) => Number.isFinite(value));
    const max = Math.max(10, ...values, Number(data.max_ms || 0));
    const points = series.map((item, index) => {
      const x = series.length <= 1 ? 6 : 5 + (index / (series.length - 1)) * 90;
      const latency = Number(item.latency_ms || 0);
      const y = item.status === 'dropped' ? 91 : 91 - (latency / max) * 72;
      return `${x},${y}`;
    }).join(' ');

    return (
      <div className="ping-chart-card">
        <div className="ping-chart-head">
          <div className="ping-section-heading">
            <CircleDot className="h-4 w-4" />
            Live Latency Graph
          </div>
          <span>{data.latency_trend || 'Waiting for trend'}</span>
        </div>
        <div className="ping-axis-label top">Latency (ms)</div>
        <svg viewBox="0 0 100 100" className="ping-line-chart" preserveAspectRatio="none" aria-label="Live latency graph">
          {[10, 28, 46, 64, 82, 91].map((y) => (
            <line key={y} x1="5" x2="95" y1={y} y2={y} stroke="rgba(203,178,255,0.18)" />
          ))}
          <line x1="5" x2="5" y1="4" y2="91" stroke="rgba(222,212,233,0.74)" vectorEffect="non-scaling-stroke" />
          <line x1="5" x2="95" y1="91" y2="91" stroke="rgba(222,212,233,0.74)" vectorEffect="non-scaling-stroke" />
          {points && (
            <>
              <polygon points={`5,91 ${points} 95,91`} fill="rgba(139,103,205,0.52)" />
              <polyline points={points} fill="none" stroke="#b895ff" strokeWidth="2.3" vectorEffect="non-scaling-stroke" />
            </>
          )}
          {series.map((item, index) => {
            const x = series.length <= 1 ? 6 : 5 + (index / (series.length - 1)) * 90;
            const latency = Number(item.latency_ms || 0);
            const y = item.status === 'dropped' ? 91 : 91 - (latency / max) * 72;
            return (
              <g key={`${item.packet}-${index}`}>
                <circle cx={x} cy={y} r={item.status === 'dropped' ? 1.2 : 0.9} fill={item.status === 'dropped' ? '#FF4D4D' : '#b895ff'} vectorEffect="non-scaling-stroke" />
              </g>
            );
          })}
        </svg>
        <div className="ping-chart-ticks">
          {['-60s', '-50s', '-40s', '-30s', '-20s', '-10s', 'Now'].map((tick) => <span key={tick}>{tick}</span>)}
        </div>
      </div>
    );
  };

  const renderLatencyDistribution = (data) => {
    const values = pingSeries(data)
      .map((item) => Number(item.latency_ms))
      .filter((value) => Number.isFinite(value));
    const buckets = [
      ['200-250', 200, 250],
      ['250-270', 250, 270],
      ['270-290', 270, 290],
      ['290-310', 290, 310],
      ['310-330', 310, 330],
      ['330-350', 330, 350],
      ['350-370', 350, 370],
      ['370-390', 370, 390],
      ['390-420', 390, 420],
      ['420+', 420, Infinity],
    ];
    const counts = buckets.map(([, min, max]) => values.filter((value) => value >= min && value < max).length);
    const fallback = [1, 11, 21, 33, 27, 21, 15, 10, 5, 1];
    const bars = values.length ? counts : fallback;
    const maxCount = Math.max(1, ...bars);

    return (
      <div className="ping-chart-card">
        <div className="ping-chart-head">
          <div className="ping-section-heading">
            <CircleDot className="h-4 w-4" />
            Latency Distribution
          </div>
          <span>{data.latency_trend || 'Minor Latency Variation'}</span>
        </div>
        <div className="ping-axis-label top">Resources</div>
        <div className="ping-bar-chart" aria-label="Latency distribution">
          {bars.map((count, index) => (
            <div key={buckets[index][0]} className="ping-bar-column">
              <span style={{ height: `${Math.max(4, (count / maxCount) * 86)}%` }} />
              <em>{buckets[index][0]}</em>
            </div>
          ))}
        </div>
        <div className="ping-axis-label bottom">Latency (ms)</div>
      </div>
    );
  };

  const renderPingNetworkAnalysis = (data) => {
    const series = pingSeries(data);
    const recommendations = [
      ...(data.recommendations || []),
      ...(data.security_insights || []),
      data.route_insight,
    ].filter(Boolean);
    const packetRows = series.length ? series : [
      { packet: 1, latency_ms: data.min_ms, status: data.min_ms == null ? 'dropped' : 'received' },
      { packet: 2, latency_ms: data.avg_ms, status: data.avg_ms == null ? 'dropped' : 'received' },
      { packet: 3, latency_ms: data.max_ms, status: data.max_ms == null ? 'dropped' : 'received' },
    ];

    return (
      <div className="ping-network-grid">
        <div className="ping-network-card wide">
          <div className="ping-section-heading mb-6">
            <CircleDot className="h-4 w-4" />
            Performance Analysis
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {[
              ['Network Quality', data.connection_quality || 'Unknown', data.avg_ms != null ? `${data.avg_ms} ms avg latency` : 'No timing sample'],
              ['Reliability', data.stability_score != null ? `${data.stability_score}/100` : 'Unknown', data.packet_loss_pct != null ? `${data.packet_loss_pct}% packet loss` : 'Loss unknown'],
              ['Route Profile', data.network_type_guess || 'Public internet host', data.estimated_hops || 'Hops unknown'],
            ].map(([label, value, subtext]) => (
              <div key={label} className="ping-network-stat">
                <span>{label}</span>
                <strong>{value}</strong>
                <em>{subtext}</em>
              </div>
            ))}
          </div>
        </div>

        <div className="ping-network-card">
          <div className="ping-section-heading mb-5">
            <CircleDot className="h-4 w-4" />
            ICMP Packet Flow
          </div>
          <div className="ping-flow-list">
            {packetRows.map((item, index) => (
              <div key={`${item.packet}-${index}`} className="ping-flow-row">
                <span className={`ping-flow-dot ${item.status === 'dropped' ? 'is-bad' : ''}`} />
                <span>Packet {item.packet}</span>
                <strong className={item.status === 'dropped' ? 'text-[#FF4D4D]' : Number(item.latency_ms) > 100 ? 'text-[#F97316]' : 'text-[#7CFF9A]'}>
                  {item.status === 'dropped' ? 'Dropped' : `${item.latency_ms} ms`}
                </strong>
              </div>
            ))}
          </div>
        </div>

        <div className="ping-network-card">
          <div className="ping-section-heading mb-5">
            <CircleDot className="h-4 w-4" />
            Risk Analysis
          </div>
          <div className="ping-risk-list">
            {[data.health_summary, data.latency_trend, ...(data.security_insights || [])].filter(Boolean).map((item, index) => (
              <p key={`${item}-${index}`}>{item}</p>
            ))}
          </div>
        </div>

        <div className="ping-network-card wide accent">
          <div className="ping-section-heading mb-6">
            <CircleDot className="h-4 w-4 fill-current" />
            Recommendations
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {(recommendations.length ? recommendations : ['Connection looks healthy. No immediate network action is recommended.']).slice(0, 4).map((item, index) => (
              <div key={`${item}-${index}`} className="ping-action-row">
                <CheckCircle2 className="h-4 w-4" />
                <span>{item}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  const renderPingResults = (data) => {
    const geo = data.geo || {};
    const history = typeof data.history_delta_ms === 'number'
      ? `${data.history_delta_ms >= 0 ? '+' : ''}${data.history_delta_ms.toFixed(1)}ms since last check`
      : 'Baseline captured';
    const online = (data.packets_received || 0) > 0;
    const stability = Number(data.stability_score ?? 0);
    const availability = Number(data.availability_pct ?? 0);
    const packetLoss = Number(data.packet_loss_pct ?? 0);
    const targetName = data.target || target || 'Target';
    const provider = geo.cdn_provider || geo.org || geo.isp || 'Unknown';
    const csv = [
      ['metric', 'value'],
      ['target', data.target || ''],
      ['ip', data.ip || ''],
      ['availability_pct', data.availability_pct ?? ''],
      ['stability_score', data.stability_score ?? ''],
      ['avg_ms', data.avg_ms ?? ''],
      ['min_ms', data.min_ms ?? ''],
      ['max_ms', data.max_ms ?? ''],
      ['jitter_ms', data.jitter_ms ?? ''],
      ['packet_loss_pct', data.packet_loss_pct ?? ''],
      ['ttl', data.ttl ?? ''],
      ['estimated_hops', data.estimated_hops ?? ''],
      ['provider', provider],
    ].map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(',')).join('\n');
    const summaryText = `${targetName}: ${data.avg_ms ?? 'N/A'} ms avg, ${packetLoss}% loss, ${stability}/100 stability`;

    const pingMetricTile = (IconCmp, label, value, subtext, tone = 'neutral') => (
      <div className="ping-metric-tile">
        <div className="ping-metric-label">
          <IconCmp className="h-4 w-4" />
          <span>{label}</span>
        </div>
        <div className={`ping-metric-value tone-${tone}`}>{value ?? 'Unknown'}</div>
        {subtext && <div className={`ping-metric-sub tone-${tone}`}>{subtext}</div>}
      </div>
    );

    const securityRows = [
      ['CDN', geo.is_cdn ? 'Yes' : 'No'],
      ['CDN Provider', provider],
      ['Proxy', geo.is_proxy ? 'Yes' : 'No'],
      ['Hosting', geo.is_hosting ? 'Yes' : 'No'],
      ['Confidence', online ? (stability >= 85 ? 'High' : stability >= 65 ? 'Medium' : 'Low') : 'Low'],
      ['Location Accuracy', geo.city ? 'City' : geo.region ? 'Region' : geo.country ? 'Country' : 'Unknown'],
    ];
    const splitRows = [securityRows.slice(0, 6), securityRows.slice(0, 6)];

    return (
      <div className="ping-dashboard">
        <section className="ping-overview-panel">
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <h2 className="text-[26px] font-semibold leading-tight text-[#f4eef7]">{targetName}</h2>
            {data.ip && (
              <a href={`https://${targetName}`} target="_blank" rel="noreferrer" className="text-[#b895ff] transition hover:text-[#d9c7ff]" aria-label="Open target">
                <ExternalLink className="h-4 w-4" />
              </a>
            )}
          </div>
          <div className={`ping-status-pill ${online ? 'is-online' : 'is-offline'}`}>
            <span className="h-2 w-2 rounded-full bg-current" />
            {online ? 'Online:Target is reachable' : 'Offline:Target is unreachable'}
          </div>

          <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
            {pingMetricTile(CheckCircle2, 'Availability', `${availability || 0}%`, data.last_checked || 'Just now', online ? 'good' : 'bad')}
            {pingMetricTile(ShieldCheck, 'Stability', data.stability_score != null ? `${stability}/100` : 'Unknown', data.connection_quality || 'Unknown', stability >= 85 ? 'good' : stability >= 65 ? 'warn' : 'bad')}
            {pingMetricTile(Timer, 'Avg Latency', data.avg_ms != null ? `${data.avg_ms} ms` : 'N/A', data.connection_quality || 'Unknown', data.avg_ms != null && data.avg_ms <= 50 ? 'good' : data.avg_ms != null && data.avg_ms <= 100 ? 'warn' : 'bad')}
            {pingMetricTile(CheckCircle2, 'Min', data.min_ms != null ? `${data.min_ms} ms` : 'N/A', 'Fast Response', 'good')}
            {pingMetricTile(Network, 'Max', data.max_ms != null ? `${data.max_ms} ms` : 'N/A', 'Slowed Response', data.max_ms != null && data.max_ms <= 100 ? 'good' : 'bad')}
            {pingMetricTile(Activity, 'Jitter', data.jitter_ms != null ? `${data.jitter_ms} ms` : 'N/A', data.jitter_label || 'Unknown', data.jitter_label === 'Stable' ? 'good' : data.jitter_label === 'Variable' ? 'warn' : 'bad')}
            {pingMetricTile(ShieldAlert, 'Packet Loss', `${packetLoss}%`, data.packet_loss_severity || 'Stable', packetLoss <= 0 ? 'good' : packetLoss <= 2 ? 'warn' : 'bad')}
            {pingMetricTile(Server, 'TTL', data.ttl ?? 'Unknown', data.estimated_hops || 'Hops', 'neutral')}
            {pingMetricTile(Route, 'Network Hops', data.estimated_hops?.replace(' network hops', '') || 'Unknown', 'Hops', 'neutral')}
            {pingMetricTile(Database, 'DNS Lookup', data.dns_lookup_ms != null ? `${data.dns_lookup_ms} ms` : 'Unknown', '', 'neutral')}
            {pingMetricTile(Globe2, 'OS Guess', data.likely_os_family || 'Unknown', '', 'neutral')}
            {pingMetricTile(Building2, 'CDN/Hosting', provider, '', geo.is_cdn || geo.is_hosting ? 'good' : 'neutral')}
            {pingMetricTile(Activity, 'Distribution', data.latency_distribution || 'Unknown', '', 'good')}
            {pingMetricTile(Gauge, 'Std. Deviation', data.std_deviation_ms != null ? `${data.std_deviation_ms} ms` : 'N/A', '', data.std_deviation_ms != null && data.std_deviation_ms <= 20 ? 'good' : 'warn')}
            {pingMetricTile(Network, 'Variance', data.variance_ms != null ? `${data.variance_ms} ms` : 'N/A', '', data.variance_ms != null && data.variance_ms <= 400 ? 'good' : 'warn')}
            {pingMetricTile(Radio, 'ICMP', online ? 'Enabled' : 'Blocked', '', online ? 'good' : 'bad')}
            {pingMetricTile(Timer, 'History', history, '', 'neutral')}
          </div>
        </section>

        <section className="ping-info-panel">
          <div className="ping-info-box">
            <div className="ping-section-heading mb-7">
              <CircleDot className="h-4 w-4" />
              Security Information
            </div>
            <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
              {splitRows.map((rows, groupIndex) => (
                <div key={groupIndex} className={groupIndex === 1 ? 'lg:border-l lg:border-[#6c5a7a]/80 lg:pl-12' : ''}>
                  {rows.map(([label, value]) => (
                    <div key={`${groupIndex}-${label}`} className="ping-info-row">
                      <span>{label}</span>
                      <strong>{value}</strong>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
          <div className="ping-suitable-strip">
            <Info className="h-4 w-4" />
            <div>
              <div>Suitable For</div>
              <p>{(data.suitable_for || []).length ? data.suitable_for.join(', ') : 'No quality labels matched this run.'}</p>
            </div>
          </div>
        </section>

        <section className="ping-analysis-panel">
          <div className="ping-tabs">
            <button
              type="button"
              className={activePingTab === 'network' ? 'active' : ''}
              onClick={() => setActivePingTab('network')}
            >
              <Globe2 className="h-4 w-4" /> Network Analysis
            </button>
            <button
              type="button"
              className={activePingTab === 'monitoring' ? 'active' : ''}
              onClick={() => setActivePingTab('monitoring')}
            >
              <Globe2 className="h-4 w-4" /> Monitoring & Reporting
            </button>
          </div>
          {activePingTab === 'network' ? (
            renderPingNetworkAnalysis(data)
          ) : (
            <div className="ping-monitoring-stack">
              {renderPingGraph(data)}
              {renderLatencyDistribution(data)}
            </div>
          )}
        </section>

        <section className="ping-export-panel">
          <div className="mb-2 text-[18px] font-medium uppercase text-[#b79aff]">Export & Share</div>
          <p className="text-sm text-[#d2c5dc]">Download or share your scan report.</p>
          <div className="mt-7 grid grid-cols-1 gap-4 md:grid-cols-4">
            <button type="button" onClick={() => window.print()} className="ping-export-btn"><FileText className="h-4 w-4" /> Export PDF</button>
            <button type="button" onClick={() => downloadText(`${targetName}-ping.json`, JSON.stringify(data, null, 2), 'application/json')} className="ping-export-btn"><FileText className="h-4 w-4" /> Export JSON</button>
            <button type="button" onClick={() => downloadText(`${targetName}-ping.csv`, csv, 'text/csv')} className="ping-export-btn"><FileText className="h-4 w-4" /> Export CSV</button>
            <button type="button" onClick={() => copyText('ping-share', summaryText)} className="ping-export-btn"><Share2 className="h-4 w-4" /> {copied === 'ping-share' ? 'Copied' : 'Share report'}</button>
          </div>
        </section>
      </div>
    );
  };

  const renderTracerouteResults = (data) => {
    const hops = Array.isArray(data.hops) ? data.hops : [];
    const visible = hops.filter((hop) => hop.rtt_ms != null);
    const maxRtt = Math.max(10, ...visible.map((hop) => Number(hop.rtt_ms || 0)));
    const finalHop = visible.at(-1);
    const routePoints = hops.map((hop, index) => ({
      hop,
      x: hops.length <= 1 ? 50 : 8 + (index / (hops.length - 1)) * 84,
      y: hop.lat != null && hop.lon != null
        ? 84 - Math.max(-60, Math.min(75, Number(hop.lat))) + ((index % 3) * 3)
        : 22 + ((index * 29) % 54),
    }));
    const routePolyline = routePoints.map((point) => `${point.x},${point.y}`).join(' ');
    const colorForHop = (hop) => {
      if (hop.is_hidden) return '#64748b';
      if (hop.quality_color === 'green') return '#7CFF9A';
      if (hop.quality_color === 'cyan') return '#22d3ee';
      if (hop.quality_color === 'yellow') return '#F97316';
      if (hop.quality_color === 'red') return '#FF4D4D';
      return '#a78bfa';
    };
    const locationLabel = (hop) => [hop.city, hop.region, hop.country_code || hop.country].filter(Boolean).join(', ');

    return (
      <div className="p-6 space-y-6">
        <section className="border border-purple-400/25 bg-dark-800/65 rounded-lg p-5 overflow-hidden relative">
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div className="min-w-0 max-w-4xl">
              <div className="flex flex-wrap gap-2 mb-4">
                {(data.health_indicators || []).map((item) => chip(item, item.includes('WATCH') || item.includes('CONGESTION') || item.includes('SUBOPTIMAL') ? 'warn' : 'good'))}
                {data.cdn_detected && chip(data.cdn_detected, 'info')}
                {liveMode && chip('LIVE ROUTE MONITORING', 'info')}
                {data.route_changed && chip('ROUTE CHANGED', 'warn')}
              </div>
              <h2 className="text-3xl font-semibold text-gray-100 break-words">
                {data.target} Route
              </h2>
              <p className="text-sm text-gray-300 mt-3 leading-6">{data.ai_summary || 'Traceroute intelligence will appear after a successful run.'}</p>
            </div>
            <div className="grid grid-cols-2 gap-3 min-w-[280px]">
              {renderMetricCard(Gauge, 'Stability', data.route_stability_score != null ? `${data.route_stability_score}/100` : 'Unknown', data.route_efficiency)}
              {renderMetricCard(Activity, 'Final Latency', finalHop?.rtt_ms != null ? `${finalHop.rtt_ms}ms` : 'Hidden', data.final_latency_delta_ms != null ? `${data.final_latency_delta_ms >= 0 ? '+' : ''}${data.final_latency_delta_ms}ms live delta` : 'Latest visible hop')}
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3">
          {renderMetricCard(Route, 'Visible Hops', `${visible.length}/${hops.length || 0}`, `${data.hidden_hops || 0} filtered`)}
          {renderMetricCard(ShieldAlert, 'Packet Loss Hops', data.packet_loss_hops || 0, 'Traceroute probe loss')}
          {renderMetricCard(Network, 'Route Risk', data.route_risk || 'Unknown', (data.route_risk_factors || [])[0])}
          {renderMetricCard(Cloud, 'CDN / Cloud', data.cdn_detected || 'Not detected', 'Cloud edge inference')}
          {renderMetricCard(MapPin, 'Geo Route', data.international_route ? 'Cross-border' : 'Local/unknown', 'Based on resolved hop GeoIP')}
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)] gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5 overflow-hidden">
            <div className="flex items-center justify-between gap-3 mb-5">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500">
                <Route className="w-4 h-4" />
                Hop Visualization Timeline
              </div>
              <span className="text-xs font-mono text-purple-200">{data.route_efficiency || 'Analyzing route'}</span>
            </div>
            <div className="space-y-0">
              {hops.map((hop, index) => (
                <div key={`${hop.hop}-${hop.ip || 'hidden'}`} className="grid grid-cols-[42px_1fr] gap-4 min-h-[76px]">
                  <div className="relative flex justify-center">
                    <div className="w-9 h-9 rounded-full border grid place-items-center text-xs font-mono mt-1"
                      style={{ borderColor: colorForHop(hop), color: colorForHop(hop), boxShadow: `0 0 20px ${colorForHop(hop)}55` }}>
                      {hop.hop}
                    </div>
                    {index < hops.length - 1 && <div className="absolute top-11 bottom-0 w-px bg-gradient-to-b from-purple-300/60 to-cyan-300/20" />}
                    {index < hops.length - 1 && (
                      <span className="absolute top-12 w-2 h-2 rounded-full bg-cyan-300 shadow-[0_0_16px_rgba(34,211,238,0.9)] animate-pulse" />
                    )}
                  </div>
                  <div className="pb-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-mono text-gray-100">{hop.is_hidden ? 'No ICMP response' : hop.ip}</span>
                      {chip(hop.quality || 'Unknown', hop.quality_color === 'red' ? 'bad' : hop.quality_color === 'yellow' ? 'warn' : hop.is_hidden ? 'neutral' : 'good')}
                      {hop.hop_type && chip(hop.hop_type, 'info')}
                    </div>
                    <div className="text-xs text-gray-400 mt-2 break-words">
                      {[locationLabel(hop), hop.provider, hop.asn, hop.hostname].filter(Boolean).join(' · ') || hop.hidden_reason || 'Public router'}
                    </div>
                    {hop.latency_added_ms >= 40 && <div className="text-xs text-[#F97316] mt-2">Latency spike: +{hop.latency_added_ms}ms at this hop.</div>}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="border border-dark-600 bg-dark-900/35 rounded-lg p-5 overflow-hidden">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">
              <MapPin className="w-4 h-4" />
              Interactive Network Map
            </div>
            <div className="relative rounded-lg border border-purple-400/20 bg-[radial-gradient(circle_at_50%_45%,rgba(34,211,238,0.16),rgba(19,9,33,0.18)_42%,rgba(9,4,18,0.8))] h-[360px] overflow-hidden">
              <svg viewBox="0 0 100 100" className="absolute inset-0 w-full h-full" preserveAspectRatio="none">
                {[20, 40, 60, 80].map((x) => <line key={x} x1={x} x2={x} y1="0" y2="100" stroke="rgba(167,139,250,0.08)" />)}
                {[25, 50, 75].map((y) => <line key={y} x1="0" x2="100" y1={y} y2={y} stroke="rgba(167,139,250,0.08)" />)}
                <polyline points={routePolyline} fill="none" stroke="rgba(34,211,238,0.72)" strokeWidth="1.4" strokeDasharray="3 2" vectorEffect="non-scaling-stroke" />
                {routePoints.map(({ hop, x, y }) => (
                  <g key={`map-${hop.hop}`}>
                    <circle cx={x} cy={y} r="2.7" fill={colorForHop(hop)} vectorEffect="non-scaling-stroke" />
                    <circle cx={x} cy={y} r="5.6" fill="none" stroke={colorForHop(hop)} opacity="0.35" vectorEffect="non-scaling-stroke" />
                  </g>
                ))}
              </svg>
              <div className="absolute left-4 right-4 bottom-4 grid grid-cols-2 gap-2">
                {(data.ownership_chain || []).slice(0, 4).map((owner) => (
                  <div key={owner} className="rounded-lg border border-dark-600 bg-dark-900/80 px-3 py-2 text-xs font-mono text-gray-300 truncate">{owner}</div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-5">
              <BarChart3 className="w-4 h-4" />
              Hop Response Time Graph
            </div>
            <div className="space-y-3">
              {hops.map((hop) => (
                <div key={`bar-${hop.hop}`} className="grid grid-cols-[64px_1fr_84px] items-center gap-3">
                  <span className="text-xs font-mono text-gray-500">Hop {hop.hop}</span>
                  <div className="h-3 rounded-full bg-dark-700 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{ width: `${hop.rtt_ms == null ? 4 : Math.max(5, (hop.rtt_ms / maxRtt) * 100)}%`, background: colorForHop(hop), boxShadow: `0 0 18px ${colorForHop(hop)}66` }}
                    />
                  </div>
                  <span className="text-xs font-mono text-gray-300 text-right">{hop.rtt_ms == null ? 'Filtered' : `${hop.rtt_ms}ms`}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Routing Intelligence</div>
            <div className="space-y-3">
              {[...(data.routing_intelligence || []), ...(data.security_insights || []), ...(data.route_risk_factors || []), data.route_change_summary].filter(Boolean).map((item, index) => (
                <div key={`${item}-${index}`} className="text-sm text-gray-300 border border-dark-700 rounded-lg p-3">{item}</div>
              ))}
            </div>
          </div>
        </section>

        <section className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Expandable Hop Cards</div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
            {hops.map((hop) => (
              <details key={`detail-${hop.hop}`} className="group border border-dark-700 rounded-lg bg-dark-900/25 p-4">
                <summary className="cursor-pointer list-none flex flex-wrap items-center justify-between gap-3">
                  <span className="text-sm font-mono text-gray-100">Hop {hop.hop} · {hop.ip || 'Filtered'}</span>
                  <span className="text-xs font-mono" style={{ color: colorForHop(hop) }}>{hop.rtt_ms == null ? 'No response' : `${hop.rtt_ms}ms`}</span>
                </summary>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
                  {renderField('hostname', hop.hostname)}
                  {renderField('provider', hop.provider)}
                  {renderField('asn', hop.asn)}
                  {renderField('location', locationLabel(hop))}
                  {renderField('packet_loss', `${hop.packet_loss_pct || 0}%`)}
                  {renderField('samples', hop.rtt_samples_ms)}
                  {renderField('type', hop.hop_type)}
                  {renderField('insight', hop.insight || hop.hidden_reason)}
                </div>
              </details>
            ))}
          </div>
        </section>
      </div>
    );
  };

  const renderHeadersResults = (data) => {
    const headers = data.headers || {};
    const present = data.security_headers?.present || [];
    const missing = data.security_headers?.missing || [];
    const score = Number(data.security_score ?? (data.risk_score != null ? 100 - data.risk_score : 0));
    const riskScore = Number(data.risk_score ?? (score ? 100 - score : 40));
    const totalSecurityHeaders = present.length + missing.length;
    const wafDetected = Boolean(data.waf);
    const cookieCount = Array.isArray(data.cookies) ? data.cookies.length : 0;
    const compression = data.compression?.type || data.compression || 'None';
    const csp = data.csp?.strength || (missing.some((item) => item.header === 'Content-Security-Policy') ? 'Missing' : 'Unknown');
    const cors = data.cors?.risk || 'None';
    const serverDisclosure = data.server ? 'Hidden' : 'Hidden';
    const infrastructure = data.os_guess || data.operating_system || data.os || data.cloud_provider || data.server || 'Unknown';
    const confidence = data.os_confidence || data.infrastructure_confidence || data.confidence || (infrastructure !== 'Unknown' ? 73 : null);
    const provider = data.cloud_provider || data.cdn || data.provider || 'Unknown';
    const timeline = data.timeline?.length ? data.timeline : [
      { label: 'DNS', status: 'Completed' },
      { label: 'TCP', status: 'Completed' },
      { label: 'TLS', status: data.protocol ? 'Completed' : 'Unknown' },
      { label: 'Redirects', status: data.redirect_chain?.length ? `${data.redirect_chain.length}` : 'Unknown' },
      { label: 'Headers Received', status: Object.keys(headers).length ? 'Completed' : 'Unknown' },
    ];
    const recommendations = data.recommendations?.length ? data.recommendations : [
      'Implement Content Security Policy (CSP).',
      'Review software versions exposed through header intelligence.',
      'Enable security headers where applicable.',
      'Verify clickjacking protections.',
      'Review CORS configuration.',
      'Continue monitoring for header and security changes.',
    ];
    const aiSummary = data.ai_summary || [
      `The target appears to be a ${infrastructure} host${provider !== 'Unknown' ? ` associated with ${provider}` : ''}${confidence ? ` with an estimated confidence of ${confidence}%` : ''}.`,
      wafDetected ? `WAF signatures were detected: ${data.waf}.` : 'No WAF signatures, framework indicators, or cookie-related controls were detected during analysis.',
      'Server disclosure is limited, reducing direct fingerprinting opportunities, though infrastructure characteristics remain observable.',
      'The absence of CSP and limited header visibility restrict confidence in the security assessment.',
      'Overall posture remains inconclusive and additional header telemetry is recommended.',
    ].join(' ');

    const valueOrUnknown = (value, empty = 'Unknown') => (
      value === null || value === undefined || value === '' ? empty : String(value)
    );

    const HeaderStat = ({ icon: IconCmp, title, value, subtext, tone = 'neutral' }) => {
      const tones = {
        neutral: 'text-white',
        good: 'text-[#7CFF9A]',
        bad: 'text-[#FF4D4D]',
        warn: 'text-[#F97316]',
      };
      return (
        <div className="min-h-[116px] rounded-[10px] border border-white/[0.22] bg-[#160d24]/80 p-4">
          <div className="flex items-center gap-2 text-[10px] font-bold text-white">
            <IconCmp className="h-4 w-4 shrink-0" />
            <span>{title}</span>
          </div>
          <div className={`mt-5 text-[17px] font-semibold leading-tight ${tones[tone] || tones.neutral}`}>{valueOrUnknown(value)}</div>
          <div className="mt-2 text-[9px] font-medium text-[#8e819b]">{valueOrUnknown(subtext, '')}</div>
        </div>
      );
    };

    const InsightCard = ({ title, icon: IconCmp = CircleDot, children, className = '' }) => (
      <section className={`rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 p-5 ${className}`}>
        <div className="mb-4 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-[#b895ff]">
          <IconCmp className="h-3.5 w-3.5" />
          <span>{title}</span>
        </div>
        {children}
      </section>
    );

    const InfoRow = ({ label, value, tone = 'neutral' }) => {
      const toneClass = tone === 'good' ? 'text-[#7CFF9A]' : tone === 'bad' ? 'text-[#FF4D4D]' : 'text-[#ded4e9]';
      return (
        <div className="grid grid-cols-[minmax(0,1fr)_auto] gap-4 border-b border-white/[0.1] py-2 last:border-b-0">
          <span className="text-[10px] text-[#8e819b]">{label}</span>
          <span className={`text-right text-[10px] font-semibold ${toneClass}`}>{valueOrUnknown(value, 'Unknown')}</span>
        </div>
      );
    };

    return (
      <div className="space-y-6">
        <section className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-8">
          <h2 className="mb-8 text-[28px] font-semibold leading-tight text-white">HTTP Header Intelligence</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <HeaderStat icon={ShieldCheck} title="Risk Level" value={`${riskScore}/100`} subtext={data.risk_level || 'Poor'} tone={riskScore >= 55 ? 'bad' : 'warn'} />
            <HeaderStat icon={Timer} title="Header Security Score" value={data.security_score != null ? `${data.security_score}/100` : 'Unknown'} subtext={data.security_score != null ? 'Calculated' : 'Insufficient Data'} />
            <HeaderStat icon={Building2} title="Security Headers" value={`${present.length}/${totalSecurityHeaders || 0}`} subtext="Controls Detected" />
            <HeaderStat icon={CheckCircle2} title="Infrastructure" value={infrastructure} subtext={confidence ? `${confidence}% Confidence` : 'Unknown Confidence'} tone={confidence ? 'good' : 'neutral'} />
            <HeaderStat icon={CheckCircle2} title="WAF Detection" value={wafDetected ? data.waf : 'Not detected'} subtext={wafDetected ? 'WAF signature observed' : 'No WAF signatures'} tone={wafDetected ? 'good' : 'good'} />
            <HeaderStat icon={FileText} title="Cookie Security" value={cookieCount ? `${cookieCount} cookie${cookieCount === 1 ? '' : 's'} observed` : 'No cookies observed'} subtext={cookieCount ? 'Set-Cookie detected' : ''} />
            <HeaderStat icon={Activity} title="Compression" value={compression} subtext={compression === 'None' ? 'No compression' : 'Compression detected'} />
          </div>
        </section>

        <section className="overflow-hidden rounded-xl border border-white/[0.14] bg-[#201330]/82">
          <div className="grid grid-cols-2" role="tablist" aria-label="HTTP header result views">
            {[
              { id: 'network', label: 'Header Analysis' },
              { id: 'monitoring', label: 'Security Insights' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={headersTab === tab.id}
                className={`flex h-[54px] items-center justify-center gap-2 border-b border-white/[0.14] text-[12px] font-medium transition ${
                  headersTab === tab.id
                    ? 'bg-[#5a457d] text-white shadow-[inset_0_-2px_0_#b895ff]'
                    : 'bg-[#271b3c] text-[#9f93aa] hover:text-white'
                }`}
                onClick={() => setHeadersTab(tab.id)}
              >
                <Globe2 className="h-3.5 w-3.5" />
                {tab.label}
              </button>
            ))}
          </div>

          {headersTab === 'network' ? (
            <div className="grid grid-cols-1 gap-5 p-6 lg:grid-cols-3">
              <InsightCard title="HTTP Header Intelligence" icon={CircleDot}>
                <p className="text-[11px] leading-5 text-[#ded4e9]">The target appears to be a {infrastructure} host</p>
                {confidence && <p className="text-[10px] leading-5 text-[#7CFF9A]">Confidence: {confidence}%</p>}
                <div className="mt-5 space-y-2">
                  <InfoRow label="Infrastructure Provider" value={provider} />
                  <InfoRow label="Exposed Services" value={data.exposed_services || data.open_services || 'SSH (TCP/22), HTTP (TCP/80)'} />
                  <InfoRow label="Software Review" value={data.software_review || 'Some detected software appears aged and should be reviewed.'} />
                </div>
              </InsightCard>

              <InsightCard title="Security Header Matrix" icon={CircleDot}>
                <InfoRow label="OWASP Coverage" value={`${data.compliance?.owasp_secure_headers?.passed ?? present.length}/${data.compliance?.owasp_secure_headers?.total ?? (totalSecurityHeaders || 0)}`} />
                <InfoRow label="Strict-Transport-Security (HSTS)" value={present.some((item) => item.header === 'Strict-Transport-Security') ? 'Present' : 'Unknown'} />
                <InfoRow label="Content-Security-Policy (CSP)" value={csp} tone={String(csp).toLowerCase() === 'missing' ? 'bad' : 'neutral'} />
                <InfoRow label="X-Content-Type-Options" value={present.some((item) => item.header === 'X-Content-Type-Options') ? 'Present' : 'Unknown'} />
                <InfoRow label="Referrer-Policy" value={present.some((item) => item.header === 'Referrer-Policy') ? 'Present' : 'Unknown'} />
                <InfoRow label="Permissions-Policy" value={present.some((item) => item.header === 'Permissions-Policy') ? 'Present' : 'Unknown'} />
                <InfoRow label="X-Frame-Options" value={present.some((item) => item.header === 'X-Frame-Options') ? 'Present' : 'Unknown'} />
              </InsightCard>

              <InsightCard title="Technology Fingerprint" icon={CircleDot}>
                <InfoRow label="Operating System" value={infrastructure} />
                <InfoRow label="Framework Detection" value={data.technologies?.length ? data.technologies.join(', ') : 'Not Detected'} />
                <InfoRow label="Server Identification" value={data.server || 'Hidden'} />
                <InfoRow label="Web Server" value={data.web_server || data.server || 'Unknown'} />
              </InsightCard>

              <InsightCard title="HTTP Header Intelligence" icon={CircleDot} className="lg:col-span-2">
                <div className="flex items-start justify-between gap-2 py-5">
                  {timeline.map((step, index) => (
                    <div key={`${step.label || step.step}-${index}`} className="relative flex min-w-0 flex-1 flex-col items-center text-center">
                      {index > 0 && <div className="absolute left-[-50%] top-[19px] h-px w-full border-t border-dashed border-[#6b5b78]" />}
                      <div className="relative z-10 grid h-12 w-12 place-items-center rounded-full border border-white/[0.45] bg-[#201330] text-[18px] text-white">{String(index + 1).padStart(2, '0')}</div>
                      <div className="mt-3 text-[10px] text-[#ded4e9]">{step.label || step.step}</div>
                      <div className={`mt-1 text-[10px] ${(step.status || '').toLowerCase() === 'completed' ? 'text-[#7CFF9A]' : 'text-[#9f93aa]'}`}>{step.status || 'Unknown'}</div>
                    </div>
                  ))}
                </div>
              </InsightCard>

              <InsightCard title="Response Overview" icon={CircleDot}>
                <InfoRow label="Response Status" value={data.status_code || 'Unknown'} />
                <InfoRow label="Server" value={data.server || 'Hidden'} />
                <InfoRow label="Infrastructure" value={provider} />
                <InfoRow label="Web Application Firewall" value={wafDetected ? data.waf : 'Not Detected'} tone={wafDetected ? 'good' : 'neutral'} />
                <InfoRow label="Compression" value={compression} />
                <InfoRow label="CORS" value={data.cors?.allow_origin || 'No ACAO header'} />
                <InfoRow label="Header Security" value={`${present.length}/${totalSecurityHeaders || 0}`} />
              </InsightCard>

              <InsightCard title="Response Header Explorer" icon={CircleDot}>
                <div className="space-y-0">
                  {Object.entries(headers).slice(0, 5).map(([key, value]) => (
                    <InfoRow key={key} label={key} value={String(value)} />
                  ))}
                  {!Object.keys(headers).length && <p className="text-[11px] text-[#8e819b]">No response headers available.</p>}
                </div>
              </InsightCard>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-5 p-6 lg:grid-cols-3">
              <section className="rounded-xl border border-[#8f55d6]/45 bg-[#42186d]/80 p-8 lg:col-span-3">
                <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="grid h-12 w-12 place-items-center rounded-full bg-[#b895ff] text-[#160d24]">
                      <Sparkles className="h-5 w-5" />
                    </div>
                    <h3 className="text-[17px] font-semibold text-[#d8c8ff]">AI SUMMARY</h3>
                  </div>
                  <span className="rounded-full border border-[#d46a57]/45 bg-[#8c3c50]/70 px-4 py-2 text-[13px] font-semibold uppercase text-[#F97316]">Confidence:Medium</span>
                </div>
                <p className="max-w-5xl whitespace-pre-line text-[15px] leading-7 text-[#ded4e9]">{aiSummary}</p>
              </section>

              <InsightCard title="Cookie Security" icon={CircleDot}>
                <InfoRow label="Set cookie headers found" value={cookieCount} />
                <p className="mt-3 text-[11px] leading-5 text-[#ded4e9]">{cookieCount ? 'Review cookie flags for Secure, HttpOnly, and SameSite coverage.' : 'No set cookie headers observed.'}</p>
              </InsightCard>

              <InsightCard title="Policy Analysis" icon={CircleDot}>
                <InfoRow label="Clickjacking protection" value={data.clickjacking?.protected ? 'Protected' : 'Unknown'} />
                <InfoRow label="Content-Security-Policy (CSP)" value={csp} tone={String(csp).toLowerCase() === 'missing' ? 'bad' : 'neutral'} />
                <InfoRow label="CORS Policy" value={cors} />
                <InfoRow label="Access Control Allow Origin" value={data.cors?.allow_origin || 'Not present'} />
              </InsightCard>

              <InsightCard title="Infrastructure Details" icon={CircleDot}>
                <InfoRow label="Hosting Provider" value={provider} />
                <InfoRow label="Web Application Firewall" value={wafDetected ? data.waf : 'Not Detected'} tone={wafDetected ? 'good' : 'good'} />
                <InfoRow label="Compression" value={compression} />
                <InfoRow label="Server Disclosure" value={serverDisclosure} />
              </InsightCard>

              <InsightCard title="Security Recommendations" icon={CircleDot} className="lg:col-span-2">
                <div className="space-y-0">
                  {recommendations.slice(0, 6).map((item, index) => (
                    <div key={`${item}-${index}`} className="border-b border-white/[0.1] py-2 text-[11px] leading-5 text-[#ded4e9] last:border-b-0">{item}</div>
                  ))}
                </div>
              </InsightCard>

              <InsightCard title="Redirect Chain Visualisation" icon={CircleDot}>
                {data.redirect_chain?.length ? (
                  <div className="space-y-3">
                    {data.redirect_chain.map((step, index) => (
                      <div key={`${step.url}-${index}`} className="text-[11px] leading-5 text-[#ded4e9]">{index + 1}. HTTP {step.status_code} - {step.url}</div>
                    ))}
                  </div>
                ) : (
                  <p className="text-[11px] text-[#8e819b]">Redirect Information Not Available</p>
                )}
              </InsightCard>
            </div>
          )}
        </section>

        <section className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-8">
          <h3 className="text-[18px] font-semibold uppercase text-[#ba9cff]">Export &amp; Share</h3>
          <p className="mt-4 text-[14px] text-[#ded4e9]">Download or share your scan report.</p>
          <div className="mt-8 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <button type="button" onClick={() => window.print()} className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]"><FileText className="h-5 w-5" />Export PDF</button>
            <button type="button" onClick={exportJson} className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]"><FileText className="h-5 w-5" />Export JSON</button>
            <button type="button" onClick={exportCsv} className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]"><FileText className="h-5 w-5" />Export CSV</button>
            <button type="button" onClick={shareReport} className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]"><Share2 className="h-5 w-5" />Share report</button>
          </div>
        </section>
      </div>
    );
  };

  const formatMs = (value) => {
    const number = Number(value);
    if (!Number.isFinite(number)) return '0 ms';
    if (number >= 1000) return `${(number / 1000).toFixed(number >= 10000 ? 0 : 1)} s`;
    return `${Math.round(number)} ms`;
  };

  const subStatus = (row) => {
    if (row?.resolved && row?.http?.alive) return `HTTP ${row.http.status || 'OK'}`;
    if (row?.resolved) return 'RESOLVED';
    return row?.error || 'NXDOMAIN';
  };

  const subTone = (row) => {
    if (row?.resolved && row?.verified) return 'good';
    if (row?.resolved) return 'warn';
    return 'bad';
  };

  const subToneClasses = (tone) => {
    const tones = {
      good: 'border-[#42cf70] bg-[#14301f] text-[#6df68a]',
      warn: 'border-[#d7b449] bg-[#2d2515] text-[#F97316]',
      bad: 'border-[#FF4D4D] bg-[#2a1119] text-[#FF4D4D]',
      neutral: 'border-[#63516e] bg-[#13091f] text-[#d6cbe2]',
    };
    return tones[tone] || tones.neutral;
  };

  const sectionTitle = (title, IconCmp = CircleDot) => (
    <div className="mb-7 flex items-center gap-3 text-[13px] font-medium uppercase text-[#b79aff]">
      <IconCmp className="h-5 w-5" />
      <span>{title}</span>
    </div>
  );

  const renderSubdomainResults = (data) => {
    const isScanning = Boolean(data.scanning);
    const rows = Array.isArray(data.found)
      ? data.found
      : Array.isArray(data.subdomains_found)
        ? data.subdomains_found
        : Array.isArray(data.results)
          ? data.results
          : [];
    const checkedCount = Number(data.checked_count ?? data.total_checked ?? rows.length ?? 0);
    const totalCandidates = Number(data.total_candidates ?? data.total_checked ?? rows.length ?? 0);
    const resolvedRows = rows.filter((row) => row?.resolved);
    const failedRows = rows.filter((row) => !row?.resolved);
    const totalFound = Number(data.total_found ?? resolvedRows.length);
    const verifiedCount = rows.filter((row) => row?.verified).length;
    const wildcard = Boolean(data.wildcard_detected);
    const avgDns = rows.length
      ? rows.reduce((sum, row) => sum + (Number(row?.dns_ms) || 0), 0) / rows.length
      : Number(data.dns_time_ms || 0);
    const maxDns = Math.max(1, ...rows.map((row) => Number(row?.dns_ms) || 0));
    const scanSeconds = isScanning ? 'Scanning' : Number(data.scan_time_ms) ? `${(Number(data.scan_time_ms) / 1000).toFixed(1)}s` : '0s';
    const domain = data.domain || target;
    const foundPct = checkedCount ? Math.round((totalFound / checkedCount) * 100) : 0;
    const failedPct = checkedCount ? 100 - foundPct : 0;
    const recordCounts = rows.reduce((acc, row) => {
      const records = row?.records || {};
      Object.entries(records).forEach(([type, values]) => {
        if (Array.isArray(values) && values.length) acc[type] = (acc[type] || 0) + values.length;
      });
      return acc;
    }, {});
    const errorCounts = rows.reduce((acc, row) => {
      const key = row?.resolved ? 'RESOLVED' : (row?.error || 'NXDOMAIN');
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
    const tableRows = rows.slice(0, 10);
    const csv = [
      ['#', 'Subdomain', 'Status', 'Resolved', 'DNS Time', 'Error', 'Source', 'Verified', 'Confidence'].join(','),
      ...rows.map((row, index) => [
        index + 1,
        row.subdomain || row.name || '',
        subStatus(row),
        row.resolved ? 'yes' : 'no',
        row.dns_ms ?? '',
        row.error || '',
        Array.isArray(row.source) ? row.source.join('|') : row.source || '',
        row.verified ? 'yes' : 'no',
        row.confidence ?? 0,
      ].map((value) => `"${String(value).replaceAll('"', '""')}"`).join(',')),
    ].join('\n');

    const summaryItems = [
      [CheckCircle2, `${checkedCount}/${totalCandidates} Candidates Checked`],
      [Search, `${totalFound} Live Subdomains Found`],
      [Zap, `Wildcard : ${wildcard ? 'Detected' : 'Not detected'}`],
      [Timer, scanSeconds],
    ];
    const metricItems = [
      [Globe2, 'Checked', `${checkedCount}/${totalCandidates}`],
      [BarChart3, 'Found', totalFound],
      [WifiOff, 'Failed', failedRows.length],
      [Database, 'Wildcard', wildcard ? 'Yes' : 'No'],
      [Activity, 'Avg DNS', formatMs(avgDns)],
      [Timer, 'Scan Time', scanSeconds],
    ];
    const findingItems = [
      [isScanning ? 'Waiting for subdomain candidates' : `${totalFound ? totalFound : 'No'} exposed subdomains found`, isScanning || totalFound === 0],
      [isScanning ? 'Wildcard DNS check pending' : `${wildcard ? 'Wildcard DNS detected' : 'No wildcard DNS detected'}`, isScanning || !wildcard],
      [isScanning ? 'DNS records will appear as scan completes' : `${Object.values(recordCounts).reduce((sum, value) => sum + value, 0) ? 'DNS records discovered' : 'No DNS records discovered'}`, isScanning || Object.values(recordCounts).reduce((sum, value) => sum + value, 0) === 0],
    ];

    return (
      <div className="space-y-8 p-1 md:p-2">
        <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <div className="flex flex-wrap items-center gap-3">
            {isScanning ? <Activity className="h-7 w-7 animate-pulse text-[#b79aff]" /> : <CheckCircle2 className="h-7 w-7 text-[#7CFF9A]" />}
            <h2 className="text-[26px] font-medium text-[#f4eef7]">{isScanning ? 'Subdomain Enumeration Running' : 'Subdomain Enumeration Completed'}</h2>
          </div>
          <div className="mt-5 flex flex-wrap gap-3">
            {summaryItems.map(([IconCmp, label]) => (
              <span key={label} className="inline-flex h-7 items-center gap-1.5 rounded-full border border-[#63516e]/80 bg-[#13091f]/74 px-3 text-[11px] text-[#d6cbe2]">
                <IconCmp className="h-3.5 w-3.5 text-[#f4eef7]" />
                {label}
              </span>
            ))}
          </div>
          <div className="mt-6 grid grid-cols-1 gap-1.5 md:grid-cols-2 xl:grid-cols-6">
            {metricItems.map(([IconCmp, label, value]) => (
              <div key={label} className="min-h-[78px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
                <div className="flex items-center gap-2 text-[10px] font-bold text-[#efe9f5]">
                  <IconCmp className="h-3.5 w-3.5" />
                  <span>{label}</span>
                </div>
                <div className="mt-4 text-[13px] font-semibold text-[#f4eef7]">{value}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="grid grid-cols-1 gap-8 rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)] xl:grid-cols-2">
          <div className="rounded-2xl border border-white/10 bg-[#1a0b30]/85 px-8 py-7 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/25 hover:shadow-[0_20px_50px_rgba(0,0,0,0.35)]">
            <div className="mb-7 flex items-center gap-3 text-sm font-semibold uppercase text-[#b79aff]">
              <CircleDot className="h-5 w-5" />
              <span>Discovery Overview</span>
            </div>
            <div className="flex flex-col items-center">
              <AnimatedDonutChart passedPct={foundPct} passedCount={totalFound} failedCount={failedRows.length} />
              <div className="mt-8 w-full border-t border-white/[0.08] pt-5">
                <div className="flex items-stretch">
                  <div className="flex flex-1 flex-col items-center gap-1">
                    <div className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-[#FF4D4D] shadow-[0_0_6px_rgba(255,77,77,0.5)]" />
                      <span className="text-xs font-medium uppercase tracking-wider text-[#A69BBE]">Failed</span>
                    </div>
                    <span className="text-[34px] font-bold leading-none text-[#F4F2FF]">{failedRows.length}</span>
                    <span className="text-xs leading-none text-[#A69BBE]">{failedPct}%</span>
                  </div>
                  <span className="w-px self-stretch bg-white/[0.08]" />
                  <div className="flex flex-1 flex-col items-center gap-1">
                    <div className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-[#7CFF9A] shadow-[0_0_6px_rgba(124,255,154,0.5)]" />
                      <span className="text-xs font-medium uppercase tracking-wider text-[#A69BBE]">Passed</span>
                    </div>
                    <span className="text-[34px] font-bold leading-none text-[#F4F2FF]">{totalFound}</span>
                    <span className="text-xs leading-none text-[#A69BBE]">{foundPct}%</span>
                  </div>
                  <span className="w-px self-stretch bg-white/[0.08]" />
                  <div className="flex flex-1 flex-col items-center gap-1">
                    <span className="text-xs font-medium uppercase tracking-wider text-[#A69BBE]">Total</span>
                    <span className="text-[34px] font-bold leading-none text-[#F4F2FF]">{totalFound + failedRows.length}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
            {sectionTitle('Enumeration Summary')}
            <div>
              {[
                ['Domain', domain],
                ['Technique', 'Worldwide Enumeration'],
                ['Wildcard DNS', wildcard ? 'Enabled' : 'Disabled'],
                ['Verified Hosts', verifiedCount],
              ].map(([label, value]) => (
                <div key={label} className="grid grid-cols-[150px_minmax(0,1fr)] border-b border-[#554365]/70 py-4 text-sm last:border-b-0">
                  <span className="text-[#92859d]">{label}</span>
                  <span className="text-[#d8cce6] break-words">{value}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
            {sectionTitle('DNS Response (Lower is better)')}
            <div className="grid grid-cols-1 gap-x-12 gap-y-4 xl:grid-cols-2">
              {rows.length === 0 && (
                <div className="col-span-full rounded-lg border border-[#4f3b63] bg-[#1a1029] px-5 py-6 text-sm text-[#92859d] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
                  {isScanning ? 'Waiting for DNS responses...' : 'No DNS response samples available.'}
                </div>
              )}
              {rows.slice(0, 14).map((row) => {
                const dns = Number(row?.dns_ms) || 0;
                const tone = row?.resolved ? '#7CFF9A' : '#FF4D4D';
                return (
                  <div key={row.subdomain || row.name} className="grid grid-cols-[minmax(120px,1fr)_minmax(120px,260px)_58px] items-center gap-4">
                    <span className="truncate text-[11px] text-[#8f839b]">{row.subdomain || row.name}</span>
                    <div className="h-1.5 rounded-full bg-[#43364b]">
                      <div className="h-full rounded-full" style={{ width: `${Math.max(8, (dns / maxDns) * 100)}%`, background: tone }} />
                    </div>
                    <span className="text-right text-[11px] text-[#d8cce6]">{formatMs(dns)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
            {sectionTitle('Enumerated Subdomains')}
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-[#554365]/80 text-[11px] text-[#92859d]">
                    {['#', 'Subdomain', 'Status', 'Resolved', 'DNS Time', 'Error', 'Source', 'Verified', 'Confidence'].map((head) => (
                      <th key={head} className="px-3 py-3 font-medium">{head}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tableRows.length === 0 && (
                    <tr>
                      <td colSpan="9" className="px-3 py-8 text-center text-sm text-[#92859d]">
                        {isScanning ? 'Scan started. Enumerated subdomains will fill in here.' : 'No subdomains were enumerated.'}
                      </td>
                    </tr>
                  )}
                  {tableRows.map((row, index) => (
                    <tr key={row.subdomain || row.name || index} className="border-b border-[#382748] text-[11px] text-[#d8cce6] last:border-b-0">
                      <td className="px-3 py-4 text-[#92859d]">{index + 1}</td>
                      <td className="px-3 py-4 font-mono text-[10px]">{row.subdomain || row.name}</td>
                      <td className="px-3 py-4">
                        <span className={`rounded-full border px-2 py-1 text-[9px] font-semibold uppercase ${subToneClasses(subTone(row))}`}>{subStatus(row)}</span>
                      </td>
                      <td className="px-3 py-4">{row.resolved ? <CheckCircle2 className="h-4 w-4 text-[#7CFF9A]" /> : <X className="h-4 w-4 text-[#FF4D4D]" />}</td>
                      <td className="px-3 py-4 text-[#7CFF9A]">{formatMs(row.dns_ms)}</td>
                      <td className="px-3 py-4 text-[#FF4D4D]">{row.error || '-'}</td>
                      <td className="px-3 py-4">{Array.isArray(row.source) ? row.source.join(', ') : row.source || 'wordlist'}</td>
                      <td className="px-3 py-4">{row.verified ? <CheckCircle2 className="h-4 w-4 text-[#7CFF9A]" /> : <X className="h-4 w-4 text-[#FF4D4D]" />}</td>
                      <td className="px-3 py-4 text-[#FF4D4D]">{Math.round(Number(row.confidence || 0) * 100)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-6 rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)] xl:grid-cols-3">
          <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-6 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
            {sectionTitle('DNS Record Summary')}
            {['A', 'MX', 'AAAA', 'TXT', 'CNAME', 'NS'].map((type) => (
              <div key={type} className="flex items-center justify-between border-b border-[#554365]/70 py-3 text-sm last:border-b-0">
                <span className="text-[#92859d]">{type} Records</span>
                <span className="text-[#d8cce6]">{recordCounts[type] || 0}</span>
              </div>
            ))}
          </div>
          <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-6 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
            {sectionTitle('Contact Information')}
            <div className="flex flex-col items-center">
              <div
                className="h-24 w-24 rounded-full"
                style={{ background: `conic-gradient(#FF4D4D 0deg ${failedPct * 3.6}deg, #7CFF9A ${failedPct * 3.6}deg 360deg)` }}
              />
              <div className="mt-6 w-full space-y-3">
                {Object.entries(errorCounts).length === 0 && (
                  <div className="text-center text-sm text-[#92859d]">{isScanning ? 'No response classes yet' : 'No response classes recorded'}</div>
                )}
                {Object.entries(errorCounts).slice(0, 5).map(([label, value]) => (
                  <div key={label} className="flex items-center justify-between text-sm">
                    <span className="text-[#92859d]">{label}</span>
                    <span className="text-[#d8cce6]">{value} ({Math.round((value / Math.max(1, rows.length)) * 100)}%)</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-6 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
            {sectionTitle('Findings')}
            <div className="space-y-3">
              {findingItems.map(([text, ok]) => (
                <div key={text} className="flex items-center justify-between border-b border-[#554365]/70 pb-3 text-sm text-[#d8cce6] last:border-b-0">
                  <span>{text}</span>
                  {ok ? <CheckCircle2 className="h-4 w-4 text-[#7CFF9A]" /> : <ShieldAlert className="h-4 w-4 text-[#F97316]" />}
                </div>
              ))}
            </div>
            <div className="mt-8 rounded-lg border border-[#4f3b63] bg-[#24183b] p-4 text-xs leading-5 text-[#b7abc5] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
              {isScanning
                ? 'The scan is in progress. This dashboard starts empty and updates when enumeration data returns.'
                : totalFound === 0
                ? 'All checked subdomains returned unresolved results. No active assets were discovered.'
                : `${totalFound} candidate host${totalFound === 1 ? '' : 's'} resolved. Review verified hosts first.`}
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
          <div className="mb-2 text-[18px] font-medium uppercase text-[#b79aff]">Export & Share</div>
          <p className="text-sm text-[#d2c5dc]">Download or share your scan report.</p>
          <div className="mt-7 grid grid-cols-1 gap-4 md:grid-cols-4">
            <button type="button" onClick={() => window.print()} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
              <FileText className="h-4 w-4" /> Export PDF
            </button>
            <button type="button" onClick={() => downloadText(`${domain || 'subdomains'}-subdomains.json`, JSON.stringify(data, null, 2), 'application/json')} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
              <FileText className="h-4 w-4" /> Export JSON
            </button>
            <button type="button" onClick={() => downloadText(`${domain || 'subdomains'}-subdomains.csv`, csv, 'text/csv')} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
              <FileText className="h-4 w-4" /> Export CSV
            </button>
            <button type="button" onClick={() => copyText('subdomain-share', `${domain}: ${totalFound}/${totalCandidates} subdomains found`)} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
              <Share2 className="h-4 w-4" /> {copied === 'subdomain-share' ? 'Copied' : 'Share report'}
            </button>
          </div>
        </section>
      </div>
    );
  };

  const renderOsFingerprintResults = (data) => {
    const asArray = (value) => (Array.isArray(value) ? value : []);
    const confidence = pct(data.confidence);
    const risk = data.risk_score || {};
    const tcp = data.tcp_ip_stack || {};
    const exposure = data.internet_exposure || {};
    const geo = data.geolocation || {};
    const sourceSections = asArray(data.fingerprint_sources);
    const probabilities = asArray(data.os_probabilities);
    const timeline = asArray(data.fingerprint_timeline);
    const openPorts = asArray(data.open_ports);
    const attackSurfaceByOs = asArray(data.attack_surface_by_os);
    const mitreAttack = asArray(data.mitre_attack);
    const cpeMatches = asArray(data.cpe_matches);
    const eolFindings = asArray(data.eol_findings);
    const vulnerabilityCorrelation = asArray(data.vulnerability_correlation);
    const scanDuration = Number.isFinite(Number(data.scan_duration_seconds)) ? `${Number(data.scan_duration_seconds).toFixed(1)}s` : '—';
    const hostingLabel = data.hosting_provider || geo.provider || geo.org || geo.isp || '—';
    const hostingSubtext = [geo.asn, geo.org].filter(Boolean).join(' · ') || '—';
    const detectionQuality = data.confidence_label || data.scan_quality?.label || '—';
    const sourcesByName = new Map(sourceSections.map((source) => [String(source.name || '').toLowerCase(), source]));
    const sourceCard = (label, keys, IconCmp) => {
      const source = keys.map((key) => sourcesByName.get(key)).find(Boolean);
      const observed = source && !['not observed', 'limited'].includes(String(source.status || '').toLowerCase());
      return (
        <div className="rounded-lg border border-[#4f3b63] bg-[#24183b]/80 p-5 min-h-[210px]">
          <div className="mb-4 flex items-start justify-between gap-3">
            <div className="flex items-center gap-2 text-[12px] font-medium text-[#e9d5ff]">
              <IconCmp className="h-4 w-4" />
              <span>{label}</span>
            </div>
            <span className={`text-[10px] ${observed ? 'text-[#7CFF9A]' : 'text-[#FF4D4D]'}`}>
              {source?.status || 'Not observed'}
            </span>
          </div>
          {source?.inference && <p className="text-[11px] leading-relaxed text-[#b7abc5]">{source.inference}</p>}
          {source?.observed_ttl !== undefined && (
            <div className="mt-5 border-t border-[#554365]/70 pt-3 text-[11px] text-[#d8cce6]">
              ICMP TTL {source.observed_ttl}
            </div>
          )}
          {Array.isArray(source?.items) && source.items.length > 0 && (
            <div className="mt-4 space-y-3">
              {source.items.slice(0, 4).map((item, index) => (
                <div key={`${label}-${index}`} className="border-b border-[#554365]/70 pb-2 text-[11px] text-[#d8cce6] last:border-b-0">
                  <span className="text-[#b79aff]">{item.service || 'Signal'}</span>: {item.reason || item.os_signal || '—'}
                </div>
              ))}
            </div>
          )}
          {source?.details && typeof source.details === 'object' && !Array.isArray(source.details) && (
            <div className="mt-4 text-[11px] text-[#b7abc5]">
              {Object.entries(source.details).slice(0, 3).map(([key, value]) => (
                <div key={key} className="flex justify-between gap-3 border-b border-[#554365]/70 py-2 last:border-b-0">
                  <span>{key}</span>
                  <span>{String(value)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      );
    };
    const fieldRow = (label, value) => (
      <div className="flex items-center justify-between gap-4 border-b border-[#554365]/70 py-3 text-[12px] text-[#d8cce6] last:border-b-0">
        <span>{label}</span>
        <span className="text-right text-[#f4eef7]">{value === undefined || value === null || value === '' ? '—' : Array.isArray(value) ? value.join(', ') || '—' : String(value)}</span>
      </div>
    );
    const analysisCard = (title, children, extraClass = '') => (
      <div className={`rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7 ${extraClass}`}>
        <div className="mb-6 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]">
          <CircleDot className="h-4 w-4" />
          <span>{title}</span>
        </div>
        {children}
      </div>
    );
    const renderOsTabContent = () => {
      if (activeOsTab === 'security') {
        const securityRows = [
          ['Firewall', data.firewall_detection?.possible ? 'Possible' : 'Not obvious'],
          ['Honeypot', data.honeypot_detection?.possible ? 'Possible' : 'No obvious signal'],
          ['Quality', data.scan_quality?.label || '—'],
          ['ICMP Response', data.ttl == null ? 'Not observed' : `TTL ${data.ttl}`],
        ];
        const correlationItems = [...eolFindings, ...vulnerabilityCorrelation];
        return (
          <>
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
              {analysisCard('Security Indicators', (
                <div>
                  {securityRows.map(([label, value]) => (
                    <div key={label} className="flex items-center justify-between gap-4 border-b border-[#554365]/70 py-3 text-[12px] text-[#d8cce6] last:border-b-0">
                      <span>{label}</span>
                      <span className={label === 'Firewall' && value === 'Possible' ? 'text-[#F97316]' : label === 'Honeypot' && value === 'No obvious signal' ? 'text-[#7CFF9A]' : 'text-[#f4eef7]'}>
                        {value}
                      </span>
                    </div>
                  ))}
                </div>
              ))}
              {analysisCard('Attack Surface by OS', (
                <div className="space-y-4">
                  {attackSurfaceByOs.length === 0 && <p className="text-[12px] text-[#b7abc5]">—</p>}
                  {attackSurfaceByOs.slice(0, 4).map((item) => (
                    <div key={item} className="rounded-lg bg-[#2a1a3d] p-4 text-[12px] leading-relaxed text-[#d8cce6]">{item}</div>
                  ))}
                </div>
              ))}
              {analysisCard('MITRE ATT&CK Mapping', (
                <div className="relative space-y-5 before:absolute before:left-2 before:top-2 before:h-[calc(100%-16px)] before:w-px before:bg-[#6b5790]">
                  {mitreAttack.length === 0 && <p className="text-[12px] text-[#b7abc5]">—</p>}
                  {mitreAttack.slice(0, 4).map((item) => (
                    <div key={`${item.id}-${item.name}`} className="relative grid grid-cols-[20px_minmax(0,1fr)] gap-3 text-[12px]">
                      <span className="mt-1 h-4 w-4 rounded-full bg-[#b89cff]" />
                      <span>
                        <strong className="block text-[#f4eef7]">{item.id}</strong>
                        <span className="block text-[#d8cce6]">{item.name}</span>
                        <span className="text-[#92859d]">{item.tactic}{item.reason ? ` · ${item.reason}` : ''}</span>
                      </span>
                    </div>
                  ))}
                </div>
              ))}
            </div>
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.3fr_1fr]">
              {analysisCard('CPE Mapping', (
                <div className="space-y-5">
                  {cpeMatches.length === 0 && <p className="text-[12px] text-[#b7abc5]">—</p>}
                  {cpeMatches.slice(0, 4).map((item) => (
                    <div key={item.cpe}>
                      <div className="mb-2 flex items-center justify-between gap-4 text-[12px] text-[#d8cce6]">
                        <span className="break-all">{item.cpe}</span>
                        <span>{pct(item.confidence)}%</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-[#3f3348]"><div className="h-full rounded-full bg-[#b89cff]" style={{ width: `${pct(item.confidence)}%` }} /></div>
                    </div>
                  ))}
                </div>
              ))}
              {analysisCard('EOL & Vulnerability Correlation', (
                <div className="space-y-4">
                  {correlationItems.length === 0 && <p className="text-[12px] text-[#b7abc5]">—</p>}
                  {correlationItems.slice(0, 5).map((item, index) => (
                    <div key={`${item.component || item.name || index}`} className="rounded-lg bg-[#2a1a3d] p-4">
                      <div className="text-[13px] font-semibold text-[#f4eef7]">{item.component || item.name || 'Finding'}</div>
                      <div className="mt-1 text-[11px] leading-relaxed text-[#92859d]">{item.reason || item.finding || item.detail || '—'}</div>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </>
        );
      }

      if (activeOsTab === 'services') {
        return (
          <div className="space-y-6">
            {analysisCard('Open Services', (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[720px] border-collapse text-left">
                  <thead>
                    <tr className="border-b border-[#554365]/80 text-[11px] text-[#92859d]">
                      {['Port', 'Service', 'Version / Detail', 'Actions', 'Risk'].map((head) => (
                        <th key={head} className="px-4 py-3 font-medium">{head}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {openPorts.length === 0 && (
                      <tr><td colSpan="5" className="px-4 py-10 text-center text-sm text-[#92859d]">—</td></tr>
                    )}
                    {openPorts.map((port) => (
                      <tr key={port.port} className="border-b border-[#382748] text-[12px] text-[#d8cce6] last:border-b-0">
                        <td className="px-4 py-5 font-mono text-[#ddd6fe]">{port.port}</td>
                        <td className="px-4 py-5">{port.service || '—'}</td>
                        <td className="px-4 py-5">
                          <div className="font-semibold text-[#f4eef7]">{port.version || port.fingerprint?.detected || '—'}</div>
                          {port.fingerprint?.method && <div className="mt-1 text-[10px] text-[#92859d]">{port.fingerprint.method}</div>}
                        </td>
                        <td className="px-4 py-5">
                          <button type="button" className="rounded-md bg-[#b89cff] px-4 py-2 text-[11px] font-semibold text-[#24183b]">
                            View Details
                          </button>
                        </td>
                        <td className="px-4 py-5">
                          <span className="rounded-full border border-[#743248]/80 bg-[#351222]/72 px-3 py-1 text-[10px] font-semibold uppercase text-[#FF4D4D]">
                            {port.risk_level || '—'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
            {analysisCard('Historical Fingerprint Comparison', (
              <div className="grid min-h-[180px] place-items-center text-center">
                <div>
                  <FileText className="mx-auto mb-4 h-10 w-10 text-[#8d7aa8]" />
                  <p className="text-[13px] text-[#d8cce6]">{data.historical_comparison?.summary || '—'}</p>
                  {data.historical_comparison?.available === false && (
                    <p className="mt-1 text-[11px] text-[#92859d]">First fingerprint baseline.</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        );
      }

      return (
        <>
          <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
            <div className="mb-7 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]"><CircleDot className="h-4 w-4" />Fingerprinting Sources Breakdown</div>
            <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">
              {sourceCard('TTL Analysis', ['ttl analysis', 'ttl'], Timer)}
              {sourceCard('Banner Analysis', ['banner analysis', 'banner'], Database)}
              {sourceCard('Port Behaviour', ['port behaviour', 'port behavior', 'port'], Radio)}
              {sourceCard('TCP/IP Stack', ['tcp/ip stack', 'tcp stack'], Network)}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
            <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
              <div className="mb-5 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]"><CircleDot className="h-4 w-4" />TCP/IP Stack Fingerprinting</div>
              {fieldRow('Window Size', tcp.window_size)}
              {fieldRow('MSS', tcp.mss)}
              {fieldRow('SACK Permitted', tcp.sack_permitted)}
              <div className="mt-6 rounded-lg bg-[#2a1a3d] p-4 text-[11px] text-[#d8cce6]">
                TCP Options {(Array.isArray(tcp.tcp_options) ? tcp.tcp_options : []).join(', ') || '—'}
              </div>
            </div>
            <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
              <div className="mb-5 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]"><CircleDot className="h-4 w-4" />Environment</div>
              <div className="space-y-4">
                <div className="rounded-lg bg-[#2a1a3d] p-4">
                  <div className="text-[12px] font-semibold text-[#f4eef7]">Virtual Machine</div>
                  <div className="mt-1 text-[11px] text-[#b7abc5]">{data.environment || '—'}</div>
                </div>
                <div className="rounded-lg bg-[#2a1a3d] p-4">
                  <div className="text-[12px] font-semibold text-[#f4eef7]">Uptime</div>
                  <div className="mt-1 text-[11px] text-[#b7abc5]">{data.uptime_estimate?.value || data.uptime_estimate?.confidence || '—'}</div>
                </div>
              </div>
            </div>
            <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
              <div className="mb-5 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]"><CircleDot className="h-4 w-4" />Internet Exposure Context</div>
              {fieldRow('Classification', exposure.classification)}
              {fieldRow('Country', [geo.country, geo.country_code && `(${geo.country_code})`].filter(Boolean).join(' '))}
              {fieldRow('SACK Permitted', tcp.sack_permitted)}
            </div>
          </div>
        </>
      );
    };
    const csv = [
      ['Field', 'Value'],
      ['Target', data.target],
      ['IP', data.ip],
      ['Detected OS', data.detected_os],
      ['Family', data.family],
      ['Confidence', data.confidence],
      ['Kernel', data.kernel_estimate],
      ['Hosting', hostingLabel],
    ].map((row) => row.map((value) => `"${String(value ?? '').replaceAll('"', '""')}"`).join(',')).join('\n');

    return (
      <div className="flex-1 overflow-y-auto p-1 md:p-2">
        <div className="space-y-8">
          <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
            <div className="mb-6 flex flex-wrap items-center gap-3">
              {data.scanning ? <Activity className="h-6 w-6 animate-pulse text-[#b79aff]" /> : <CheckCircle2 className="h-6 w-6 text-[#7CFF9A]" />}
              <h2 className="text-[26px] font-medium text-[#f4eef7]">{data.scanning ? 'OS Fingerprinting Running' : 'OS Fingerprinting Completed'}</h2>
            </div>
            <div className="mb-7 flex flex-wrap gap-3">
              <span className="inline-flex h-7 items-center gap-1.5 rounded-full border border-[#63516e]/80 bg-[#13091f]/74 px-3 text-[11px] text-[#d6cbe2]">
                <Timer className="h-3.5 w-3.5 text-[#f4eef7]" /> {scanDuration}
              </span>
              {data.scan_message && (
                <span className="inline-flex h-7 items-center gap-1.5 rounded-full border border-[#63516e]/80 bg-[#13091f]/74 px-3 text-[11px] text-[#d6cbe2]">
                  <Activity className="h-3.5 w-3.5 text-[#f4eef7]" /> {data.scan_message}
                </span>
              )}
            </div>
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.3fr_1fr]">
              <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-6">
                <div className="mb-7 flex items-start gap-3">
                  <Fingerprint className="mt-1 h-6 w-6 text-[#F97316]" />
                  <div>
                    <div className="text-[18px] font-semibold text-[#f4eef7]">{data.detected_os || '—'}</div>
                    <div className="text-[12px] text-[#b7abc5]">{data.os_version_estimate || data.distribution_family || '—'}</div>
                  </div>
                </div>
                <div className="grid grid-cols-1 items-center gap-7 md:grid-cols-[150px_minmax(0,1fr)]">
                  <div className="grid h-36 w-36 place-items-center rounded-full" style={{ background: `conic-gradient(#7CFF9A 0deg ${confidence * 2.2}deg, #ffea5f ${confidence * 2.2}deg ${confidence * 3.05}deg, #F97316 ${confidence * 3.05}deg ${confidence * 3.6}deg, #4a3857 0deg)` }}>
                    <div className="grid h-24 w-24 place-items-center rounded-full bg-[#13091f] text-center">
                      <strong className="text-2xl text-[#7CFF9A]">{confidence}%<span className="block text-[10px] uppercase text-[#7CFF9A]">Confidence</span></strong>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div className="grid grid-cols-[54px_minmax(0,1fr)] gap-4">
                      <div className="grid h-12 w-12 place-items-center rounded-lg bg-[#281743] text-[#b79aff]"><ShieldCheck className="h-6 w-6" /></div>
                      <div>
                        <div className="text-[16px] font-semibold text-[#f4eef7]">{detectionQuality}</div>
                        <div className="text-[12px] text-[#92859d]">Detection Quality</div>
                      </div>
                    </div>
                    <div className="grid grid-cols-[54px_minmax(0,1fr)] gap-4">
                      <div className="grid h-12 w-12 place-items-center rounded-lg bg-[#281743] text-[#b79aff]"><Fingerprint className="h-6 w-6" /></div>
                      <div>
                        <div className="text-[16px] font-semibold text-[#f4eef7]">{data.detection_mode || data.method || '—'}</div>
                        <div className="text-[12px] text-[#92859d]">Fingerprinting</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-5">
                    <div className="mb-4 flex items-center gap-2 text-[11px] font-bold text-[#efe9f5]"><Globe2 className="h-4 w-4" />OS Family</div>
                    <div className="text-[17px] text-[#f4eef7]">{data.family || '—'}</div>
                  </div>
                  <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-5">
                    <div className="mb-4 flex items-center gap-2 text-[11px] font-bold text-[#efe9f5]"><Cpu className="h-4 w-4" />Kernel</div>
                    <div className="text-[17px] text-[#f4eef7]">{data.kernel_estimate || '—'}</div>
                  </div>
                  <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-5">
                    <div className="mb-4 flex items-center gap-2 text-[11px] font-bold text-[#efe9f5]"><ShieldAlert className="h-4 w-4" />Exposure Score</div>
                    <div className="text-[17px] text-[#F97316]">{risk.level || '—'}</div>
                    <div className="text-[12px] text-[#b7abc5]">{risk.score != null ? `${risk.score}/100` : '—'}</div>
                  </div>
                  <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-5">
                    <div className="mb-4 flex items-center gap-2 text-[11px] font-bold text-[#efe9f5]"><Building2 className="h-4 w-4" />Hosting</div>
                    <div className="text-[17px] text-[#f4eef7]">{hostingLabel}</div>
                    <div className="text-[12px] text-[#b7abc5]">{hostingSubtext}</div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-lg border border-[#5b3f78] bg-[#3a1760]/82 p-8">
            <div className="mb-7 flex items-center gap-4">
              <div className="grid h-11 w-11 place-items-center rounded-full bg-[#b89cff] text-[#1b0d2b]">
                <Zap className="h-5 w-5" />
              </div>
              <div className="text-[18px] font-medium uppercase text-[#c4b5fd]">AI Summary</div>
            </div>
            <p className="text-[15px] leading-7 text-[#eee6f6]">{data.ai_summary || '—'}</p>
            <div className="mt-7 flex flex-wrap gap-8">
              <div className="flex items-center gap-3">
                <div className="grid h-10 w-10 place-items-center rounded-lg bg-[#6d45aa] text-[#d8c7ff]"><ShieldCheck className="h-5 w-5" /></div>
                <div>
                  <div className="text-sm font-semibold text-[#f4eef7]">Hosting</div>
                  <div className="text-xs text-[#d8cce6]">{hostingLabel}</div>
                </div>
              </div>
              <div className="h-10 w-px bg-[#8d6ab8]/70" />
              <div className="flex items-center gap-3">
                <div className="grid h-10 w-10 place-items-center rounded-lg bg-[#6d45aa] text-[#d8c7ff]"><Fingerprint className="h-5 w-5" /></div>
                <div>
                  <div className="text-sm font-semibold text-[#f4eef7]">Open Services</div>
                  <div className="text-xs text-[#d8cce6]">{openPorts.length ? openPorts.slice(0, 4).map((port) => `${port.service} / TCP ${port.port}`).join(' ') : '—'}</div>
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
              <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
                <div className="mb-7 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]"><CircleDot className="h-4 w-4" />OS Probability Engine</div>
                <div className="space-y-5">
                  {(probabilities.length ? probabilities : [{ name: '—', probability: 0 }]).map((item) => (
                    <div key={item.name}>
                      <div className="mb-2 flex items-center justify-between text-[12px] text-[#d8cce6]">
                        <span>{item.name}</span>
                        <span>{pct(item.probability)}%</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-[#3f3348]"><div className="h-full rounded-full bg-[#b89cff]" style={{ width: `${pct(item.probability)}%` }} /></div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
                <div className="mb-7 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]"><CircleDot className="h-4 w-4" />Timeline/Detection Flow</div>
                <div className="relative space-y-5 before:absolute before:left-2 before:top-2 before:h-[calc(100%-16px)] before:w-px before:bg-[#6b5790]">
                  {(timeline.length ? timeline : [{ step: '—', detail: '—', confidence_after: 0 }]).map((step) => (
                    <div key={step.step} className="relative grid grid-cols-[20px_minmax(0,1fr)_44px] gap-3 text-[12px]">
                      <span className="mt-1 h-4 w-4 rounded-full bg-[#b89cff]" />
                      <span>
                        <strong className="block text-[#f4eef7]">{step.step}</strong>
                        <span className="text-[#92859d]">{step.detail}</span>
                      </span>
                      <span className="text-right text-[#b89cff]">{pct(step.confidence_after)}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>

          <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78">
            <div className="grid grid-cols-1 overflow-hidden rounded-t-lg border-b border-[#4f3b63] bg-[#24183b] text-center text-sm text-[#b7abc5] md:grid-cols-3">
              {[
                ['identity', 'Fingerprinting & Identification'],
                ['security', 'Security & Vulnerability Analysis'],
                ['services', 'Service discovery & History'],
              ].map(([key, label], index) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setActiveOsTab(key)}
                  aria-pressed={activeOsTab === key}
                  className={`px-4 py-4 transition hover:bg-[#382748] ${activeOsTab === key ? 'bg-[#654f90] text-[#f4eef7]' : index > 0 ? 'border-l border-[#4f3b63]' : ''}`}
                >
                  <Globe2 className="mr-2 inline h-4 w-4" />{label}
                </button>
              ))}
            </div>
            <div className="space-y-8 p-8">
              {renderOsTabContent()}
            </div>
          </section>

          <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
            <div className="mb-2 text-[18px] font-medium uppercase text-[#b79aff]">Export & Share</div>
            <p className="text-sm text-[#d2c5dc]">Download or share your scan report.</p>
            <div className="mt-7 grid grid-cols-1 gap-4 md:grid-cols-4">
              <button type="button" onClick={() => window.print()} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:border-[#9f7aea]"><FileText className="h-4 w-4" /> Export PDF</button>
              <button type="button" onClick={() => downloadText(`${data.target || 'os-fingerprint'}-os.json`, JSON.stringify(data, null, 2), 'application/json')} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:border-[#9f7aea]"><FileText className="h-4 w-4" /> Export JSON</button>
              <button type="button" onClick={() => downloadText(`${data.target || 'os-fingerprint'}-os.csv`, csv, 'text/csv')} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:border-[#9f7aea]"><FileText className="h-4 w-4" /> Export CSV</button>
              <button type="button" onClick={() => copyText('os-share', `${data.target}: ${data.detected_os || 'OS unknown'} (${confidence}% confidence)`)} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:border-[#9f7aea]"><Share2 className="h-4 w-4" /> {copied === 'os-share' ? 'Copied' : 'Share report'}</button>
            </div>
          </section>
        </div>
      </div>
    );
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot">
          <Icon className="w-3 h-3" />
        </span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>{meta.name}</span>
      </div>
      {toolId === 'geo' ? (
        <ScanInputBar
          target={target}
          placeholder={meta.placeholder}
          loading={loading}
          onTargetChange={setTarget}
          onClear={() => setTarget('')}
          onRun={() => run()}
        />
      ) : (
        <div className="scanner-control-shell">
          <div className="relative flex-1 min-w-[320px]">
            <input type="text" className="scan-input" placeholder={meta.placeholder} value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
            {target && <button onClick={() => setTarget('')} className="clear-input-btn" aria-label="Clear target"><X className="w-4 h-4" /></button>}
          </div>
          {toolId === 'traceroute' && (
            <input
              type="number"
              min="1"
              max="64"
              className="scan-input max-w-[136px]"
              value={maxHops}
              onChange={(e) => setMaxHops(Math.max(1, Math.min(64, Number(e.target.value) || 30)))}
              disabled={liveMode}
              aria-label="Traceroute max hops"
            />
          )}
          {['ping', 'traceroute'].includes(toolId) && (
            <button
              type="button"
              onClick={toggleLiveMode}
              disabled={!target}
              className={`run-btn min-w-[132px] ${liveMode ? 'shadow-[0_0_24px_rgba(34,211,238,0.35)]' : ''}`}
            >
              <span>{liveMode ? 'Live On' : 'Live'}</span>
              <Radio className="w-4 h-4" />
            </button>
          )}
          <button onClick={() => run()} disabled={loading || !target} className="run-btn">
            <span>{loading ? 'Running' : toolId === 'ping' ? 'Run Ping' : 'Run'}</span>
            {loading ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <ArrowRight className="w-4 h-4" />}
          </button>
        </div>
      )}
      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto" style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>Your {meta.name} results will appear here</span>
          </div>
        ) : results.error ? (
          <div className="p-6 text-[#FF4D4D] font-mono text-sm">{results.error}</div>
        ) : toolId === 'subdomains' ? (
          renderSubdomainResults(results)
        ) : toolId === 'geo' ? (
          renderGeoResults(results)
        ) : toolId === 'osfingerprint' ? (
          renderOsFingerprintResults(results)
        ) : toolId === 'ping' ? (
          renderPingResults(results)
        ) : toolId === 'traceroute' ? (
          renderTracerouteResults(results)
        ) : toolId === 'headers' ? (
          <div className="p-6">
            {renderHeadersResults(results)}
          </div>
        ) : (
          <div className="p-6 space-y-3">
            {Object.entries(results).map(([key, val]) => (
              <div key={key} className="flex gap-4 p-4 bg-dark-800/50 border border-dark-600 rounded-xl hover:bg-dark-700/50 transition-colors">
                <span className="w-36 text-xs text-gray-500 font-mono shrink-0 pt-0.5">{key}</span>
                {renderValue(val)}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
