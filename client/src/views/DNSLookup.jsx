import { useState } from 'react';
import { Globe, X, ArrowRight } from 'lucide-react';
import { apiGet } from '../utils/apiClient';
import { useGetToken } from '../utils/useGetToken';

const RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR'];

export default function DNSLookup() {
  const [target, setTarget] = useState('');
  const [recordType, setRecordType] = useState('A');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const getToken = useGetToken();

  const run = async () => {
    if (!target) return;
    setLoading(true);
    try {
      const r = await apiGet('/api/tools/dns', { target, type: recordType }, getToken);
      const data = await r.json();
      setResults(data);
    } catch (e) {
      setResults({ error: e.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><Globe className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>DNS Lookup</span>
      </div>

      <div className="scanner-control-shell">
        <div className="relative flex-1 min-w-[320px]">
          <input type="text" className="scan-input" placeholder="Domain (e.g. example.com)" value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
          {target && <button onClick={() => setTarget('')} className="clear-input-btn" aria-label="Clear target"><X className="w-4 h-4" /></button>}
        </div>
        <select className="scan-select max-w-[150px]" value={recordType} onChange={(e) => setRecordType(e.target.value)}>
          {RECORD_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <button onClick={run} disabled={loading || !target} className="run-btn">
          <span>{loading ? 'Looking Up' : 'Lookup'}</span>
          {loading ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <ArrowRight className="w-4 h-4" />}
        </button>
      </div>

      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto" style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>Your DNS results will appear here</span>
          </div>
        ) : results.error ? (
          <div className="p-6 text-[#FF4D4D] font-mono text-sm">{results.error}</div>
        ) : (
          <div className="p-6 space-y-2">
            {Object.entries(results).map(([key, val]) => (
              <div key={key} className="flex gap-4 p-4 bg-dark-800/50 border border-dark-600 rounded-xl hover:bg-dark-700/50 transition-colors">
                <span className="w-16 font-mono text-xs bg-primary-500/10 text-primary-400 border border-primary-500/20 rounded px-2 py-1 h-fit">{key}</span>
                <pre className="flex-1 text-gray-300 text-sm font-mono whitespace-pre-wrap break-all">{Array.isArray(val) ? val.join('\n') : String(val)}</pre>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
