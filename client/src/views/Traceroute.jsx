import { useState } from 'react';
import { Route } from 'lucide-react';
import { apiPostAndPoll } from '../utils/apiClient';
import { useGetToken } from '../utils/useGetToken';
import { ScanInputBar } from '../components/geoip/GeoIPResultsPage';
import TracerouteResultsPage from '../components/traceroute/TracerouteResultsPage';
import MonitoringPanel from '../components/traceroute/MonitoringPanel';
import HopTimeline from '../components/traceroute/HopTimeline';

function ratingFromLatency(ms) {
  if (ms == null) return 'filtered';
  if (ms < 50) return 'good';
  if (ms < 150) return 'moderate';
  return 'poor';
}

function adaptTracerouteResult(raw) {
  if (!raw || raw.error) return null;

  const rawHops = raw.hops || [];

  const adaptedHops = rawHops.map((h) => ({
    hop: h.hop,
    ip: h.is_hidden ? '(No ICMP response)' : (h.ip || '*'),
    latencyMs: h.rtt_ms,
    deltaMs: null,
    type: h.hop_type || (h.is_hidden ? 'Filtered' : h.is_private ? 'Private' : 'Transit'),
    network: h.provider || h.asn || (h.is_private ? 'Private network' : 'Public router'),
    ok: !h.is_hidden && h.quality_color !== 'red',
  }));

  for (let i = 1; i < adaptedHops.length; i++) {
    const prev = adaptedHops[i - 1];
    const curr = adaptedHops[i];
    if (prev.latencyMs != null && curr.latencyMs != null) {
      curr.deltaMs = curr.latencyMs - prev.latencyMs;
    }
  }

  const visibleHopsCount = rawHops.filter((h) => !h.is_hidden).length;
  const visibleWithRtt = rawHops.filter((h) => !h.is_hidden && h.rtt_ms != null);
  const finalLatencyMs = visibleWithRtt.length > 0
    ? visibleWithRtt[visibleWithRtt.length - 1].rtt_ms
    : null;

  const latentPoints = rawHops.map((h) => ({
    hop: h.hop,
    latencyMs: h.rtt_ms,
    rating: ratingFromLatency(h.rtt_ms),
  }));

  const routingInsights = [
    ...(raw.routing_intelligence || []).map((text, i) => ({ id: `ri-${i}`, text })),
    ...(raw.security_insights || []).map((text, i) => ({ id: `si-${i}`, text })),
  ];

  const geoHops = rawHops
    .filter((h) => h.lat != null && h.lon != null && h.city)
    .map((h) => ({
      city: h.city,
      countryCode: h.country_code || h.country || '',
      lat: h.lat,
      lng: h.lon,
    }));

  const firstHop = rawHops.find((h) => !h.is_hidden);
  const lastHop = [...rawHops].reverse().find((h) => !h.is_hidden);

  const makeSecurityInfo = (hop) => {
    if (!hop) return null;
    return {
      cdn: hop.is_cdn || false,
      cdnProvider: hop.cdn_provider || null,
      proxy: false,
      hosting: false,
      confidence: hop.quality || 'Medium',
      locationAccuracy: hop.city ? 'City' : 'Country',
    };
  };

  return {
    summary: {
      target: raw.target,
      status: raw.error ? 'offline' : 'online',
      stabilityScore: raw.route_stability_score ?? null,
      finalLatencyMs,
      packetLossHops: raw.packet_loss_hops ?? 0,
      visibleHops: visibleHopsCount,
      totalHops: raw.total_hops || rawHops.length,
      filteredHops: raw.hidden_hops ?? 0,
      cdnProvider: raw.cdn_detected || null,
      routeRisk: raw.route_risk || null,
      routeRiskReason: raw.route_risk_factors?.[0] || null,
      geoRouteSummary: raw.international_route ? 'Cross border' : 'Domestic',
      geoRouteDetail: raw.international_route
        ? 'Route traverses multiple geographic regions.'
        : 'Route stays within a single geographic region.',
    },
    networkAnalysis: {
      latencyPoints: latentPoints,
      routingInsights,
      geoHops,
      originSecurity: makeSecurityInfo(firstHop),
      destinationSecurity: makeSecurityInfo(lastHop),
    },
    hops: adaptedHops,
  };
}

export default function Traceroute() {
  const getToken = useGetToken();
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const run = async () => {
    if (!target) return;
    setLoading(true);
    try {
      const result = await apiPostAndPoll('/api/tools/traceroute', { target, max_hops: 30 }, getToken);
      if (!result.response.ok) {
        if (result.response.status === 429) {
          window.dispatchEvent(new CustomEvent('tier:limit_reached'));
          throw new Error('Daily scan limit reached. Upgrade to continue scanning.');
        }
        const err = result.payload || {};
        throw new Error(err.detail || err.error || `HTTP ${result.response.status}`);
      }
      setResults(result.data || result.payload);
    } catch (e) {
      setResults({ error: e.message });
    } finally {
      setLoading(false);
    }
  };

  const adapted = results ? adaptTracerouteResult(results) : null;

  const downloadFile = (filename, content, mimeType) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportPdf = () => window.print();

  const exportJson = () => {
    if (!results) return;
    downloadFile(
      `traceroute-${results.target || 'result'}.json`,
      JSON.stringify(results, null, 2),
      'application/json',
    );
  };

  const exportCsv = () => {
    if (!results) return;
    const rows = [['Hop', 'IP', 'Hostname', 'RTT (ms)', 'Provider', 'ASN', 'Location', 'Quality', 'Loss %']];
    (results.hops || []).forEach((h) => {
      const loc = [h.city, h.region, h.country_code || h.country].filter(Boolean).join(', ');
      rows.push([
        h.hop, h.ip || '*', h.hostname || '', h.rtt_ms ?? '',
        h.provider || '', h.asn || '', loc,
        h.quality || '', h.packet_loss_pct ?? 0,
      ]);
    });
    const csv = rows.map((r) => r.map((c) => `"${String(c).replaceAll('"', '""')}"`).join(',')).join('\n');
    downloadFile(`traceroute-${results.target || 'result'}.csv`, csv, 'text/csv');
  };

  const shareReport = async () => {
    if (!results) return;
    const text = `Traceroute: ${results.target}\n` +
      (results.hops || []).map((h) => {
        const loc = [h.city, h.country_code].filter(Boolean).join(', ');
        return `Hop ${h.hop}: ${h.ip || '*'} ${h.rtt_ms != null ? h.rtt_ms + 'ms' : 'filtered'} ${loc}`;
      }).join('\n');
    if (navigator.share) {
      await navigator.share({ title: 'Traceroute scan report', text }).catch(() => {});
      return;
    }
    await navigator.clipboard.writeText(text).catch(() => {});
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><Route className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>Traceroute</span>
      </div>

      <ScanInputBar
        target={target}
        placeholder="Hostname or IP (e.g. example.com)"
        loading={loading}
        onTargetChange={setTarget}
        onClear={() => setTarget('')}
        onRun={run}
        runLabel="Run Ping"
      />

      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto"
              style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>
              Your traceroute results will appear here
            </span>
          </div>
        ) : results.error ? (
          <div className="p-6 text-[#FF4D4D] font-mono text-sm">{results.error}</div>
        ) : (
          <div className="p-1 md:p-2">
            <TracerouteResultsPage
              result={adapted}
              loading={loading}
              error={null}
              onExportPdf={exportPdf}
              onExportJson={exportJson}
              onExportCsv={exportCsv}
              onShare={shareReport}
              monitoringPanel={
                <MonitoringPanel
                  data={results}
                  hops={results?.hops || []}
                />
              }
              hopTimeline={<HopTimeline hops={adapted?.hops || []} />}
            />
          </div>
        )}
      </div>
    </div>
  );
}
