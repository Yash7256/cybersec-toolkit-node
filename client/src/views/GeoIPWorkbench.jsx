import { useCallback, useState } from 'react';
import {
  ArrowRight,
  Building2,
  Clock3,
  Download,
  FileText,
  GitCompare,
  Globe2,
  History,
  Layers3,
  MapPin,
  Network,
  Radio,
  Search,
  Share2,
  Trash2,
} from 'lucide-react';
import { useGetToken } from '../utils/useGetToken';
import { apiDelete, apiGet, apiPost, apiPostAndPoll } from '../utils/apiClient';
import GeoIPResultsPage from '../components/geoip/GeoIPResultsPage';

const TABS = [
  { id: 'lookup', label: 'Lookup', icon: MapPin },
  { id: 'bulk', label: 'Bulk', icon: Layers3 },
  { id: 'cidr', label: 'CIDR', icon: Network },
  { id: 'asn', label: 'ASN', icon: Building2 },
  { id: 'history', label: 'History', icon: History },
];

const fallback = (value, empty = 'Not available') => (
  value === null || value === undefined || value === '' ? empty : String(value)
);

const downloadText = (filename, content, type = 'text/plain') => {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
};

const Card = ({ children, className = '' }) => (
  <section className={`rounded-xl border border-white/[0.14] bg-[#201330]/82 p-5 shadow-[0_18px_60px_rgba(0,0,0,0.18)] ${className}`}>
    {children}
  </section>
);

const Stat = ({ label, value, subtext }) => (
  <div className="rounded-[10px] border border-white/[0.18] bg-[#190f23]/78 p-4">
    <div className="text-[10px] font-semibold uppercase tracking-wider text-[#ba9cff]">{label}</div>
    <div className="mt-2 text-[13px] font-semibold leading-snug text-white break-words">{fallback(value)}</div>
    {subtext && <div className="mt-0.5 text-[10px] text-[#aaaaaa] break-words">{subtext}</div>}
  </div>
);

const SummaryGrid = ({ summary = {} }) => {
  const countries = Object.entries(summary.countries || {}).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const asns = Object.entries(summary.asns || {}).sort((a, b) => b[1] - a[1]).slice(0, 5);
  return (
    <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
      <Stat label="Countries" value={countries.map(([code, count]) => `${code} (${count})`).join(', ')} />
      <Stat label="ASNs" value={asns.map(([asn, count]) => `${asn} (${count})`).join(', ')} />
      <Stat label="Hosting" value={summary.hosting ?? 0} />
      <Stat label="Tor exits" value={summary.tor ?? 0} />
    </div>
  );
};

const ResultTable = ({ rows = [], kind = 'bulk' }) => (
  <div className="overflow-x-auto rounded-xl border border-white/[0.12]">
    <table className="min-w-full text-left text-[11px] text-[#ded4e9]">
      <thead className="bg-[#190f23]/80 text-[10px] uppercase tracking-wider text-[#ba9cff]">
        <tr>
          <th className="px-3 py-2">{kind === 'bulk' ? 'Input' : 'IP'}</th>
          <th className="px-3 py-2">Status</th>
          <th className="px-3 py-2">Country</th>
          <th className="px-3 py-2">City</th>
          <th className="px-3 py-2">ASN</th>
          <th className="px-3 py-2">Type</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row, index) => (
          <tr key={`${row.ip || row.input}-${index}`} className="border-t border-white/[0.08]">
            <td className="px-3 py-2 font-mono">{fallback(row.ip || row.input)}</td>
            <td className={`px-3 py-2 ${row.status === 'error' ? 'text-[#FF9B9B]' : 'text-[#7CFF9A]'}`}>{row.status}</td>
            <td className="px-3 py-2">{fallback(row.country_code, '—')}</td>
            <td className="px-3 py-2">{fallback(row.city, '—')}</td>
            <td className="px-3 py-2">{fallback(row.asn, '—')}</td>
            <td className="px-3 py-2">{fallback(row.ip_type, '—')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

const COMPARE_FIELDS = [
  ['Country', 'country'],
  ['City', 'city'],
  ['ASN', 'asn'],
  ['Organization', 'org'],
  ['ISP', 'isp'],
  ['IP type', 'ip_type'],
  ['CDN', 'is_cdn'],
  ['Hosting', 'privacy.hosting'],
  ['VPN', 'privacy.vpn'],
  ['Tor', 'privacy.tor'],
  ['Abuse score', 'reputation.abuseipdb.abuse_confidence_score'],
  ['Reports', 'reputation.abuseipdb.total_reports'],
  ['DNSBL listed', 'reputation.dnsbl.listed'],
];

const readPath = (value, path) => path.split('.').reduce((current, key) => current?.[key], value);

const displayValue = (value) => {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
};

const ComparePanel = ({ compare, onClose }) => {
  const runs = compare?.runs ?? [];
  if (runs.length === 0) return null;
  return (
    <Card>
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]"><GitCompare className="h-4 w-4" />Result comparison</div>
        <button type="button" className="rounded border border-white/[0.14] px-2 py-1 text-[10px] text-[#ded4e9] hover:border-[#ba9cff]" onClick={onClose}>Close</button>
      </div>
      <div className="overflow-auto">
        <table className="w-full min-w-[720px] text-left text-[11px]">
          <thead className="text-[10px] uppercase tracking-wide text-[#aaaaaa]">
            <tr>
              <th className="px-2 py-2">Field</th>
              {runs.map((run) => <th key={run.id} className="px-2 py-2 font-mono text-white">{run.target}<div className="text-[9px] font-normal text-[#aaaaaa]">{run.tool}</div></th>)}
            </tr>
          </thead>
          <tbody>
            {COMPARE_FIELDS.map(([label, path]) => {
              const values = runs.map((run) => displayValue(readPath(run.data, path)));
              const differs = new Set(values).size > 1;
              return (
                <tr key={path} className="border-t border-white/[0.08]">
                  <td className="px-2 py-1.5 text-[#b7abc5]">{label}</td>
                  {values.map((value, index) => <td key={`${path}-${runs[index].id}`} className={`px-2 py-1.5 font-mono ${differs ? 'bg-[#ffd38a]/10 text-[#ffd38a]' : 'text-[#ded4e9]'}`}>{value}</td>)}
                </tr>
              );
            })}
            <tr className="border-t border-white/[0.08]">
              <td className="px-2 py-1.5 text-[#b7abc5]">Summary</td>
              {runs.map((run) => <td key={`summary-${run.id}`} className="px-2 py-1.5 font-mono text-[#ded4e9]">{displayValue(run.summary)}</td>)}
            </tr>
          </tbody>
        </table>
      </div>
    </Card>
  );
};

const ShareBar = ({ runId, shareLink, onCreate }) => runId ? (
  <div className="flex flex-wrap items-center gap-2 rounded-xl border border-white/[0.12] bg-[#190f23]/70 p-3">
    <button type="button" className="run-btn" onClick={onCreate}><Share2 className="h-4 w-4" />Create share link</button>
    {shareLink && <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-[#7CFF9A]">{shareLink}</span>}
  </div>
) : null;

export default function GeoIPWorkbench() {
  const getToken = useGetToken();
  const [tab, setTab] = useState('lookup');
  const [target, setTarget] = useState('');
  const [bulkText, setBulkText] = useState('');
  const [cidr, setCidr] = useState('');
  const [asn, setAsn] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [runId, setRunId] = useState(null);
  const [shareLink, setShareLink] = useState('');
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [compareIds, setCompareIds] = useState([]);
  const [compare, setCompare] = useState(null);
  const [compareLoading, setCompareLoading] = useState(false);

  const handleResponse = useCallback(async (response) => {
    if (response.status === 429) {
      window.dispatchEvent(new CustomEvent('tier:limit_reached'));
      throw new Error('Daily scan limit reached. Upgrade to continue scanning.');
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload?.error?.message || `Request failed with HTTP ${response.status}`);
    return payload;
  }, []);

  const runLookup = useCallback(async (path = '/api/tools/geoip', params = { target }) => {
    setLoading(true);
    setError('');
    setShareLink('');
    try {
      const response = await apiGet(path, params, getToken);
      const payload = await handleResponse(response);
      setResult(payload.data || payload);
      setRunId(payload.runId ?? null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [getToken, handleResponse, target]);

  const runBulk = useCallback(async () => {
    const targets = bulkText.split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
    if (targets.length === 0) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const poll = await apiPostAndPoll('/api/tools/geoip_bulk', { targets }, getToken);
      if (!poll.data) throw new Error(poll.payload?.error?.message || 'Bulk lookup failed');
      setResult(poll.data);
      setRunId(poll.payload?.id ?? poll.payload?.runId ?? null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [bulkText, getToken]);

  const runCidr = useCallback(async () => {
    if (!cidr.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const poll = await apiPostAndPoll('/api/tools/geoip_cidr', { target: cidr.trim() }, getToken);
      if (!poll.data) throw new Error(poll.payload?.error?.message || 'CIDR lookup failed');
      setResult(poll.data);
      setRunId(poll.payload?.id ?? poll.payload?.runId ?? null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [cidr, getToken]);

  const runAsn = useCallback(async () => {
    if (!asn.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const response = await apiGet('/api/tools/asn', { asn: asn.trim() }, getToken);
      const payload = await handleResponse(response);
      setResult(payload.data || payload);
      setRunId(payload.runId ?? null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [asn, getToken, handleResponse]);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    setError('');
    try {
      const response = await apiGet('/api/tools/geoip/history', { limit: 50 }, getToken);
      const payload = await handleResponse(response);
      setHistory(payload.runs || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setHistoryLoading(false);
    }
  }, [getToken, handleResponse]);

  const createShare = useCallback(async () => {
    if (!runId) return;
    setError('');
    try {
      const response = await apiPost(`/api/runs/${runId}/share`, { ttlDays: 7, redactAbuseContact: true }, getToken);
      const payload = await handleResponse(response);
      const url = `${window.location.origin}${payload.path}`;
      setShareLink(url);
      await navigator.clipboard.writeText(url).catch(() => {});
    } catch (err) {
      setError(err.message);
    }
  }, [getToken, handleResponse, runId]);

  const downloadReport = useCallback(async (id, format = 'md') => {
    setError('');
    try {
      const response = await apiGet(`/api/runs/${id}/report`, { format }, getToken);
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload?.error?.message || 'Report download failed');
      }
      const text = await response.text();
      downloadText(`run-${id}.${format === 'json' ? 'json' : 'md'}`, text, format === 'json' ? 'application/json' : 'text/markdown');
    } catch (err) {
      setError(err.message);
    }
  }, [getToken]);

  const deleteRun = useCallback(async (id) => {
    setError('');
    try {
      const response = await apiDelete(`/api/runs/${id}`, getToken);
      if (!response.ok) throw new Error('Delete failed');
      setHistory((rows) => rows.filter((row) => row.id !== id));
      setCompareIds((ids) => ids.filter((item) => item !== id));
    } catch (err) {
      setError(err.message);
    }
  }, [getToken]);

  const toggleCompare = useCallback((id) => {
    setCompareIds((ids) => ids.includes(id) ? ids.filter((item) => item !== id) : ids.length >= 4 ? ids : [...ids, id]);
  }, []);

  const runCompare = useCallback(async () => {
    if (compareIds.length < 2) return;
    setCompareLoading(true);
    setError('');
    try {
      const response = await apiGet('/api/runs/compare', { ids: compareIds.join(',') }, getToken);
      const payload = await handleResponse(response);
      setCompare(payload);
    } catch (err) {
      setError(err.message);
    } finally {
      setCompareLoading(false);
    }
  }, [compareIds, getToken, handleResponse]);

  const clearHistory = useCallback(async () => {
    setError('');
    try {
      const response = await apiDelete('/api/tools/geoip/history', getToken);
      if (!response.ok) throw new Error('Clear history failed');
      setCompare(null);
      setCompareIds([]);
      await loadHistory();
    } catch (err) {
      setError(err.message);
    }
  }, [getToken, loadHistory]);

  const renderInput = () => {
    if (tab === 'lookup') {
      return (
        <div className="flex flex-wrap gap-2">
          <input className="scan-input min-w-[280px] flex-1" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="Public IP address or hostname (e.g. 8.8.8.8)" onKeyDown={(event) => event.key === 'Enter' && runLookup()} />
          <button type="button" className="run-btn" disabled={loading || !target} onClick={() => runLookup()}>{loading ? 'Running' : 'Lookup'}<ArrowRight className="h-4 w-4" /></button>
          <button type="button" className="run-btn" disabled={loading} onClick={() => runLookup('/api/tools/geoip/me', null)}>{loading ? 'Running' : 'My IP'}<Globe2 className="h-4 w-4" /></button>
        </div>
      );
    }
    if (tab === 'bulk') {
      return (
        <div className="space-y-2">
          <textarea className="scan-input min-h-[96px] w-full" value={bulkText} onChange={(event) => setBulkText(event.target.value)} placeholder="One host or IP per line, or comma-separated (max 100)" />
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] text-[#aaaaaa]">{bulkText.split(/[\n,]/).filter((value) => value.trim()).length} entries</span>
            <button type="button" className="run-btn" disabled={loading || !bulkText.trim()} onClick={runBulk}>{loading ? 'Running' : 'Run bulk'}<Layers3 className="h-4 w-4" /></button>
          </div>
        </div>
      );
    }
    if (tab === 'cidr') {
      return (
        <div className="flex flex-wrap gap-2">
          <input className="scan-input min-w-[280px] flex-1" value={cidr} onChange={(event) => setCidr(event.target.value)} placeholder="8.8.8.0/24 (IPv4 /24–/32, IPv6 /120–/128)" onKeyDown={(event) => event.key === 'Enter' && runCidr()} />
          <button type="button" className="run-btn" disabled={loading || !cidr.trim()} onClick={runCidr}>{loading ? 'Running' : 'Run CIDR'}<Network className="h-4 w-4" /></button>
        </div>
      );
    }
    if (tab === 'asn') {
      return (
        <div className="flex flex-wrap gap-2">
          <input className="scan-input min-w-[280px] flex-1" value={asn} onChange={(event) => setAsn(event.target.value)} placeholder="AS15169" onKeyDown={(event) => event.key === 'Enter' && runAsn()} />
          <button type="button" className="run-btn" disabled={loading || !asn.trim()} onClick={runAsn}>{loading ? 'Running' : 'Lookup ASN'}<Building2 className="h-4 w-4" /></button>
        </div>
      );
    }
    return (
      <div className="flex items-center justify-between gap-3">
        <span className="text-[11px] text-[#aaaaaa]">Your recent GeoIP, CIDR, bulk, and ASN runs.</span>
        <div className="flex items-center gap-2">
          <button type="button" className="run-btn" disabled={compareIds.length < 2 || compareLoading} onClick={runCompare}>{compareLoading ? 'Comparing' : `Compare (${compareIds.length})`}<GitCompare className="h-4 w-4" /></button>
          <button type="button" className="rounded-lg border border-[#FF9B9B]/30 px-3 py-1.5 text-[11px] text-[#FF9B9B] hover:border-[#FF9B9B]" disabled={history.length === 0} onClick={clearHistory}>Clear all</button>
          <button type="button" className="run-btn" disabled={historyLoading} onClick={loadHistory}>{historyLoading ? 'Loading' : 'Refresh'}<History className="h-4 w-4" /></button>
        </div>
      </div>
    );
  };

  const renderResult = () => {
    if (error) return <div className="rounded-xl border border-[#FF4D4D]/30 bg-[#FF4D4D]/10 p-4 text-sm text-[#FF9B9B]">{error}</div>;
    if (tab === 'history') {
      return (
        <div className="space-y-3">
        {compare && <ComparePanel compare={compare} onClose={() => { setCompare(null); setCompareIds([]); }} />}
        <Card>
          <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]"><Clock3 className="h-4 w-4" />Run history</div>
          {history.length === 0 ? <p className="text-[12px] text-[#aaaaaa]">No runs yet.</p> : (
            <div className="space-y-2">
              {history.map((run) => (
                <div key={run.id} className="flex flex-wrap items-center gap-2 rounded-lg border border-white/[0.08] bg-[#190f23]/70 p-3">
                  {run.status === 'COMPLETED' && <input type="checkbox" checked={compareIds.includes(run.id)} onChange={() => toggleCompare(run.id)} aria-label={`Select ${run.target} for comparison`} />}
                  <span className="rounded-full border border-white/[0.14] px-2 py-0.5 text-[9px] uppercase tracking-wide text-[#ba9cff]">{run.tool}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-white">{run.target}</span>
                  <span className={`text-[10px] ${run.status === 'COMPLETED' ? 'text-[#7CFF9A]' : run.status === 'FAILED' ? 'text-[#FF9B9B]' : 'text-[#ffd38a]'}`}>{run.status}</span>
                  <span className="text-[10px] text-[#aaaaaa]">{new Date(run.createdAt).toLocaleString()}</span>
                  {run.status === 'COMPLETED' && (
                    <>
                      <button type="button" className="rounded border border-white/[0.14] px-2 py-1 text-[10px] text-[#ded4e9] hover:border-[#ba9cff]" onClick={() => downloadReport(run.id, 'md')}><FileText className="mr-1 inline h-3 w-3" />Report</button>
                      <button type="button" className="rounded border border-white/[0.14] px-2 py-1 text-[10px] text-[#ded4e9] hover:border-[#ba9cff]" onClick={() => downloadReport(run.id, 'json')}><Download className="mr-1 inline h-3 w-3" />JSON</button>
                    </>
                  )}
                  <button type="button" className="rounded border border-white/[0.14] px-2 py-1 text-[10px] text-[#FF9B9B] hover:border-[#FF9B9B]" onClick={() => deleteRun(run.id)}><Trash2 className="mr-1 inline h-3 w-3" />Delete</button>
                </div>
              ))}
            </div>
          )}
        </Card>
        </div>
      );
    }
    if (!result) {
      return (
        <Card className="grid min-h-[220px] place-items-center text-center">
          <div>
            <img src="/assets/logo.svg" alt="" className="mx-auto w-auto opacity-30" style={{ filter: 'grayscale(22%) saturate(90%)' }} />
            <p className="mt-3 text-xs uppercase tracking-wide text-[#6d579b]">Your GeoIP workflow results will appear here</p>
          </div>
        </Card>
      );
    }
    if (tab === 'lookup') {
      return (
        <div className="space-y-3">
          <ShareBar runId={runId} shareLink={shareLink} onCreate={createShare} />
          <GeoIPResultsPage result={result} copied="" onCopy={() => {}} onDownload={downloadText} />
        </div>
      );
    }
    if (tab === 'asn') {
      return (
        <div className="space-y-3">
          <ShareBar runId={runId} shareLink={shareLink} onCreate={createShare} />
          <Card>
            <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]"><Building2 className="h-4 w-4" />ASN details</div>
            <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
              <Stat label="ASN" value={result.asn} />
              <Stat label="Name" value={result.name} />
              <Stat label="Country" value={result.country} />
              <Stat label="RIR" value={result.rir} />
              <Stat label="Allocated" value={result.allocated} />
              <Stat label="Prefixes" value={result.prefix_count} />
              <Stat label="Truncated" value={result.truncated ? 'Yes' : 'No'} />
            </div>
            {result.warnings?.length > 0 && <p className="mt-3 text-[11px] text-[#ffd38a]">Warnings: {result.warnings.map((warning) => warning.source).join(', ')}</p>}
          </Card>
          <Card>
            <div className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]">Announced prefixes</div>
            <div className="flex flex-wrap gap-2">
              {(result.prefixes || []).map((prefix) => <span key={prefix} className="rounded-lg border border-white/[0.14] bg-[#190f23]/70 px-2.5 py-1 font-mono text-[11px] text-white">{prefix}</span>)}
              {(!result.prefixes || result.prefixes.length === 0) && <span className="text-[11px] text-[#aaaaaa]">No prefixes returned.</span>}
            </div>
          </Card>
        </div>
      );
    }
    const rows = result.results || [];
    return (
      <div className="space-y-3">
        <ShareBar runId={runId} shareLink={shareLink} onCreate={createShare} />
        <Card>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]"><Radio className="h-4 w-4" />{tab === 'bulk' ? 'Bulk' : 'CIDR'} summary</div>
            <span className="text-[11px] text-[#aaaaaa]">{fallback(result.completed, 0)}/{fallback(result.total, 0)} completed · {fallback(result.failed, 0)} failed</span>
          </div>
          <SummaryGrid summary={result.summary} />
          {result.rejected?.length > 0 && <p className="mt-3 text-[11px] text-[#ffd38a]">Rejected: {result.rejected.map((row) => `${row.input} (${row.reason})`).join(', ')}</p>}
          {result.skipped?.length > 0 && <p className="mt-3 text-[11px] text-[#ffd38a]">Skipped private/reserved: {result.skipped.map((row) => row.ip).join(', ')}</p>}
        </Card>
        <Card>
          <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]"><Search className="h-4 w-4" />Per-target results</div>
          <ResultTable rows={rows} kind={tab === 'bulk' ? 'bulk' : 'cidr'} />
        </Card>
      </div>
    );
  };

  return (
    <div className="flex h-full flex-col animate-in fade-in duration-300">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><MapPin className="h-3 w-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>GeoIP Workbench</span>
      </div>
      <div className="mb-3 flex flex-wrap gap-1.5">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button key={id} type="button" onClick={() => { setTab(id); setResult(null); setError(''); setShareLink(''); if (id === 'history') loadHistory(); }} className={`inline-flex h-8 items-center gap-1.5 rounded-lg border px-3 text-[11px] font-medium transition ${tab === id ? 'border-[#ba9cff]/70 bg-[#ba9cff]/15 text-white' : 'border-white/[0.12] bg-[#190f23]/60 text-[#b7abc5] hover:border-[#ba9cff]/40'}`}>
            <Icon className="h-3.5 w-3.5" />{label}
          </button>
        ))}
      </div>
      <div className="scanner-control-shell">{renderInput()}</div>
      <div className="scanner-results-panel mt-3 flex-1 overflow-auto">{renderResult()}</div>
    </div>
  );
}
