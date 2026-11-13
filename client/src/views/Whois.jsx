import { useEffect, useRef, useState } from 'react';
import { Server } from 'lucide-react';
import { useGetToken } from '../utils/useGetToken';
import { apiGet } from '../utils/apiClient';
import { ScanInputBar } from '../components/geoip/GeoIPResultsPage';
import WhoisResultsPage from '../components/whois/WhoisResultsPage';

function Whois() {
  const getToken = useGetToken();
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [copied, setCopied] = useState('');
  const streamAbortRef = useRef(null);

  useEffect(() => () => {
    streamAbortRef.current?.abort();
  }, []);

  const applyWhoisStreamEvent = (event) => {
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
        ...(previous || { target, domain: target }),
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
      setResults({ error: event.error || 'WHOIS stream failed' });
    }
  };

  const run = async () => {
    if (!target) return;
    streamAbortRef.current?.abort();
    const controller = new AbortController();
    streamAbortRef.current = controller;
    setLoading(true);
    setResults({
      target,
      domain: target,
      scanning: true,
      scan_stage: 'init',
      scan_message: 'Starting WHOIS lookup',
      name_servers: [],
      status: [],
      emails: [],
      risk_indicators: [],
      status_explanations: [],
      historical_whois: { available: false, reason: 'Pending lookup' },
      related_domains: { available: false, reason: 'Pending lookup' },
      normalized: {},
      cached: false,
    });
    try {
      const response = await apiGet('/api/tools/whois', { target }, getToken);
      if (response.status === 429) {
        window.dispatchEvent(new CustomEvent('tier:limit_reached'));
        throw new Error('Daily scan limit reached. Upgrade to continue scanning.');
      }
      if (!response.ok) {
        throw new Error(`WHOIS lookup failed with HTTP ${response.status}`);
      }
      applyWhoisStreamEvent({ type: 'done', data: (await response.json()).data });
    } catch (error) {
      if (error.name !== 'AbortError') setResults({ error: error.message });
    } finally {
      if (streamAbortRef.current === controller) streamAbortRef.current = null;
      setLoading(false);
    }
  };

  const copyText = async (label, text) => {
    if (!text) return;
    await navigator.clipboard.writeText(text);
    setCopied(label);
    window.setTimeout(() => setCopied(''), 1200);
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><Server className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>WHOIS</span>
      </div>
      <ScanInputBar
        target={target}
        placeholder="Domain or IP (e.g. example.com)"
        loading={loading}
        onTargetChange={setTarget}
        onClear={() => setTarget('')}
        onRun={run}
      />
      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto" style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>Your WHOIS results will appear here</span>
          </div>
        ) : results.error ? (
          <div className="p-6 text-[#FF4D4D] font-mono text-sm">{results.error}</div>
        ) : (
          <WhoisResultsPage result={results} copied={copied} onCopy={copyText} />
        )}
      </div>
    </div>
  );
}

export default Whois;
