import { useMemo } from 'react';
import {
  BarChart3, Share2, ShieldAlert, Sparkles, ArrowDown,
} from 'lucide-react';

const roundMs = (v) => (Number.isFinite(v) ? Number(v.toFixed(1)) : null);

function segmentColor(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('local') || t.includes('private')) return { bar: '#a78bfa', badge: 'rgba(167,139,250,0.15)', text: '#a78bfa', border: 'rgba(167,139,250,0.3)' };
  if (t.includes('cdn') || t.includes('cloud')) return { bar: '#22d3ee', badge: 'rgba(34,211,238,0.12)', text: '#22d3ee', border: 'rgba(34,211,238,0.28)' };
  if (t.includes('backbone') || t.includes('transit') || t.includes('isp')) return { bar: '#7CFF9A', badge: 'rgba(124,255,154,0.12)', text: '#7CFF9A', border: 'rgba(124,255,154,0.28)' };
  if (t.includes('filtered') || t.includes('hidden')) return { bar: '#64748b', badge: 'rgba(100,116,139,0.12)', text: '#64748b', border: 'rgba(100,116,139,0.22)' };
  return { bar: '#F97316', badge: 'rgba(249,115,22,0.1)', text: '#F97316', border: 'rgba(249,115,22,0.25)' };
}

function segmentSeverity(avgLatency) {
  if (avgLatency == null) return { label: 'Unknown', color: '#64748b' };
  if (avgLatency < 20) return { label: 'Good', color: '#7CFF9A' };
  if (avgLatency < 80) return { label: 'Moderate', color: '#F97316' };
  if (avgLatency < 200) return { label: 'High', color: '#F97316' };
  return { label: 'Severe', color: '#FF4D4D' };
}

function buildSegments(hops) {
  if (!hops || !hops.length) return [];
  const segments = [];
  let start = 0;
  const types = hops.map((h) => h.hop_type || (h.is_hidden ? 'filtered' : 'transit'));
  while (start < hops.length) {
    let end = start;
    while (end + 1 < hops.length && types[end + 1] === types[start]) end++;
    const slice = hops.slice(start, end + 1);
    const rtts = slice.filter((h) => h.rtt_ms != null).map((h) => Number(h.rtt_ms));
    const avgRtt = rtts.length ? rtts.reduce((a, b) => a + b, 0) / rtts.length : null;
    const sev = segmentSeverity(avgRtt);
    const firstLoc = [slice[0].city, slice[0].country_code].filter(Boolean).join(', ');
    const lastLoc = [slice.at(-1).city, slice.at(-1).country_code].filter(Boolean).join(', ');
    segments.push({
      type: types[start],
      label: types[start].replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
      hopRange: slice.length === 1 ? `Hop ${slice[0].hop}` : `Hop ${slice[0].hop}\u2013${slice.at(-1).hop}`,
      avgRtt,
      severity: sev,
      location: firstLoc && lastLoc && firstLoc !== lastLoc ? `${firstLoc} \u2192 ${lastLoc}` : firstLoc || lastLoc || null,
      color: segmentColor(types[start]),
      loss: Math.round(slice.filter((h) => h.is_hidden).length / slice.length * 100),
    });
    start = end + 1;
  }
  return segments;
}

function buildAsnFlow(hops) {
  if (!hops || !hops.length) return [];
  const seen = new Set();
  const nodes = [];
  hops.forEach((h) => {
    const key = h.asn || h.provider || (h.is_hidden ? '*hidden' : null);
    if (!key || seen.has(key)) return;
    seen.add(key);
    const t = h.hop_type || (h.is_hidden ? 'filtered' : 'transit');
    let category = 'transit';
    const lowerType = (h.hop_type || '').toLowerCase();
    if (h.is_private || lowerType.includes('local')) category = 'private';
    else if (lowerType.includes('cdn') || h.is_cdn) category = 'cdn';
    else if (lowerType.includes('isp') || lowerType.includes('backbone')) category = 'isp';
    else if (key === '*hidden') category = 'filtered';
    nodes.push({ key, asn: h.asn, provider: h.provider, type: t, category, is_cdn: h.is_cdn, cdn_provider: h.cdn_provider });
  });
  nodes.push({ key: 'destination', asn: null, provider: 'Destination', type: 'destination', category: 'destination' });
  return nodes;
}

const CATEGORY_COLORS = {
  private: { bg: 'rgba(167,139,250,0.12)', border: 'rgba(167,139,250,0.25)', text: '#a78bfa' },
  isp: { bg: 'rgba(124,255,154,0.12)', border: 'rgba(124,255,154,0.25)', text: '#7CFF9A' },
  transit: { bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.22)', text: '#F97316' },
  cdn: { bg: 'rgba(34,211,238,0.12)', border: 'rgba(34,211,238,0.25)', text: '#22d3ee' },
  filtered: { bg: 'rgba(100,116,139,0.12)', border: 'rgba(100,116,139,0.22)', text: '#94a3b8' },
  destination: { bg: 'rgba(186,156,255,0.15)', border: 'rgba(186,156,255,0.3)', text: '#ba9cff' },
};

function buildMitreFindings(hops, data) {
  if (!hops || !hops.length) return [];
  const findings = [];
  let severity;
  let maxSev = 0;

  hops.forEach((h) => {
    if (h.latency_added_ms >= 60) {
      findings.push({ hop: h.hop, label: `Latency increased by +${h.latency_added_ms}ms`, severity: 'high' });
      maxSev = Math.max(maxSev, 3);
    } else if (h.latency_added_ms >= 30) {
      findings.push({ hop: h.hop, label: `Latency increased by +${h.latency_added_ms}ms`, severity: 'medium' });
      maxSev = Math.max(maxSev, 2);
    }
    if (h.packet_loss_pct > 10) {
      findings.push({ hop: h.hop, label: `${h.packet_loss_pct}% probe loss detected`, severity: 'high' });
      maxSev = Math.max(maxSev, 3);
    }
    if (h.is_hidden && h.hidden_reason) {
      findings.push({ hop: h.hop, label: h.hidden_reason, severity: 'medium' });
      maxSev = Math.max(maxSev, 2);
    } else if (h.is_hidden) {
      findings.push({ hop: h.hop, label: 'ICMP filtering detected', severity: 'medium' });
      maxSev = Math.max(maxSev, 2);
    }
    if (h.insight) {
      findings.push({ hop: h.hop, label: h.insight, severity: 'low' });
    }
  });

  if (data?.international_route) {
    findings.push({ hop: null, label: 'Cross-region routing detected', severity: 'medium' });
    maxSev = Math.max(maxSev, 2);
  }
  if (data?.hidden_hops > 0) {
    findings.push({ hop: null, label: `${data.hidden_hops} hidden hop${data.hidden_hops > 1 ? 's' : ''} detected`, severity: 'medium' });
    maxSev = Math.max(maxSev, 2);
  }
  if (data?.cdn_detected) {
    findings.push({ hop: null, label: `Destination behind ${data.cdn_detected}`, severity: 'low' });
  }

  const rtts = hops.filter((h) => h.rtt_ms != null).map((h) => h.rtt_ms);
  if (rtts.length > 1) {
    const avg = rtts.reduce((a, b) => a + b, 0) / rtts.length;
    const variance = rtts.reduce((sum, v) => sum + (v - avg) ** 2, 0) / rtts.length;
    if (Math.sqrt(variance) > 50) {
      findings.push({ hop: null, label: 'High RTT variance detected', severity: 'medium' });
      maxSev = Math.max(maxSev, 2);
    }
  }

  if (maxSev >= 3) severity = 'high';
  else if (maxSev >= 2) severity = 'medium';
  else severity = 'low';

  return { findings, severity };
}

function buildAiSummary(data, hops, segments) {
  if (data?.ai_summary) {
    return data.ai_summary.split(/\.\s+/).filter(Boolean).map((s) => s.replace(/\.$/, '') + '.');
  }

  const lines = [];
  const vis = hops.filter((h) => !h.is_hidden);
  const visRtt = vis.filter((h) => h.rtt_ms != null);
  const avgRtt = visRtt.length ? visRtt.reduce((s, h) => s + h.rtt_ms, 0) / visRtt.length : null;
  const maxRtt = visRtt.length ? Math.max(...visRtt.map((h) => h.rtt_ms)) : null;

  const countries = [...new Set(hops.filter((h) => h.country_code).map((h) => h.country_code))];
  const cdns = [...new Set(hops.filter((h) => h.is_cdn).map((h) => h.cdn_provider).filter(Boolean))];
  const lossHops = hops.filter((h) => h.packet_loss_pct > 0);

  lines.push(`This traceroute reveals a route${data?.target ? ` to ${data.target}` : ''} spanning ${countries.length || 'multiple'} geographic region${countries.length !== 1 ? 's' : ''} with ${vis.length} visible hops out of ${hops.length} total.`);

  if (avgRtt != null && maxRtt != null) {
    lines.push(`Average latency across responsive hops is ${roundMs(avgRtt)} ms with a maximum of ${roundMs(maxRtt)} ms.`);
  }

  if (data?.hidden_hops > 0) {
    lines.push(`${data.hidden_hops} intermediate router${data.hidden_hops > 1 ? 's' : ''} ${data.hidden_hops > 1 ? 'suppress' : 'suppresses'} ICMP responses, reducing path visibility.`);
  }

  if (cdns.length > 0) {
    lines.push(`CDN${cdns.length > 1 ? 's' : ''} detected along the route: ${cdns.join(', ')}.`);
  }

  if (data?.cdn_detected) {
    lines.push(`The destination appears protected behind ${data.cdn_detected}.`);
  }

  if (lossHops.length > 0) {
    lines.push(`${lossHops.length} hop${lossHops.length > 1 ? 's' : ''} exhibit${lossHops.length === 1 ? 's' : ''} packet loss, suggesting potential congestion or filtering.`);
  }

  const totalLat = hops.filter((h) => h.country_code).reduce((s, h) => {
    if (!s.has(h.country_code)) s.add(h.country_code);
    return s;
  }, new Set()).size;

  if (totalLat > 2) {
    lines.push(`The route traverses at least ${totalLat} different countries, indicating a long-distance international path.`);
  }

  if (segments.length > 1) {
    const backboneSegs = segments.filter((s) => s.type === 'backbone' || s.type === 'transit');
    if (backboneSegs.length > 0 && avgRtt != null) {
      lines.push(`Most latency originates within the ${backboneSegs[0].label} segment (${backboneSegs.map((s) => s.label).join(', ')}).`);
    }
  }

  lines.push(`Overall route quality is ${data?.route_risk ? data.route_risk.toLowerCase() : 'moderate'} with a final RTT of ${roundMs(visRtt[visRtt.length - 1]?.rtt_ms)} ms.`);
  lines.push(`Recommendation: ${data?.hidden_hops > 3 ? 'Investigate hidden hops for potential firewall or routing issues.' : 'Monitor route stability over time for performance trends.'}`);

  return lines;
}

function confidenceLevel(data, hops) {
  if (data?.ai_summary) return { label: 'Very High', color: '#7CFF9A' };
  const rttCount = hops.filter((h) => h.rtt_ms != null).length;
  if (rttCount >= 12) return { label: 'High', color: '#22d3ee' };
  if (rttCount >= 8) return { label: 'Medium', color: '#F97316' };
  if (rttCount >= 4) return { label: 'Low', color: '#F97316' };
  return { label: 'Very Low', color: '#FF4D4D' };
}

/* ─── Segment Breakdown ──────────────────────────────────────────── */
function SegmentBreakdown({ hops }) {
  const segments = buildSegments(hops);
  if (!segments.length) return <p className="m-0 text-sm italic text-[#5a4d72]">No segments yet</p>;

  return (
    <div className="flex flex-col gap-2.5">
      {segments.map((seg, i) => {
        const c = seg.color;
        const sev = seg.severity;
        return (
          <div key={i} className="flex gap-2.5 items-start">
            <div className="w-1 shrink-0 self-stretch rounded-sm overflow-hidden min-h-[38px]" style={{ background: 'rgba(124,58,237,0.12)' }}>
              <div className="w-full h-full rounded-sm" style={{ background: c.bar, boxShadow: `0 0 8px ${c.bar}55` }} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide" style={{ background: c.badge, color: c.text, borderColor: c.border, border: '1px solid' }}>
                  {seg.label}
                </span>
                <span className="text-[10px] font-mono text-[#7a6d8a]">{seg.hopRange}</span>
              </div>
              <div className="flex flex-wrap gap-2 text-[10px] text-[#7a6d8a]">
                {seg.avgRtt != null && <span>Avg latency <strong style={{ color: '#c4b5fd' }}>{roundMs(seg.avgRtt)} ms</strong></span>}
                {seg.location && <span>{seg.location}</span>}
                {seg.loss > 0 && <span style={{ color: '#FF4D4D' }}>{seg.loss}% loss</span>}
              </div>
              <div className="mt-1.5 inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[9px] font-bold" style={{ background: `${sev.color}18`, color: sev.color, border: `1px solid ${sev.color}33` }}>
                {sev.label}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ─── ASN / Provider Flow ───────────────────────────────────────── */
function AsnFlowDiagram({ hops }) {
  const nodes = buildAsnFlow(hops);
  if (!nodes.length) return <p className="m-0 text-sm italic text-[#5a4d72]">No ASN data available</p>;

  return (
    <div className="flex flex-col items-stretch gap-0">
      {nodes.map((n, i) => {
        const cc = CATEGORY_COLORS[n.category] || CATEGORY_COLORS.transit;
        return (
          <div key={`${n.key}-${i}`} className="flex flex-col items-center">
            <div className="w-full rounded-lg p-2.5 flex flex-col gap-0.5 transition duration-150 hover:brightness-110" style={{ background: cc.bg, border: `1px solid ${cc.border}`, boxShadow: `0 0 18px ${cc.border.replace('0.25', '0.08')}` }}>
              <span className="text-[12px] font-bold leading-tight break-words" style={{ color: cc.text }}>
                {n.provider || n.asn || (n.key === 'destination' ? 'Destination' : 'Unknown')}
              </span>
              {n.asn && <span className="text-[10px] font-mono text-[#7a6d8a]">{n.asn}</span>}
              {n.is_cdn && n.cdn_provider && <span className="text-[9px] font-bold uppercase tracking-wider text-[#22d3ee]">CDN: {n.cdn_provider}</span>}
            </div>
            {i < nodes.length - 1 && (
              <div className="flex flex-col items-center py-1">
                <div className="w-px h-3" style={{ background: 'linear-gradient(180deg, rgba(124,58,237,0.4), rgba(124,58,237,0.1))' }} />
                <ArrowDown className="w-3 h-3" style={{ color: '#5a4d72', marginTop: '-2px' }} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ─── MITRE ATT&CK Mapping ────────────────────────────────────────── */
function MitrePanel({ hops, data }) {
  const { findings, severity } = useMemo(() => buildMitreFindings(hops, data), [hops, data]);

  const severityColor = severity === 'high' ? '#FF4D4D' : severity === 'medium' ? '#F97316' : '#64748b';
  const severityBg = severity === 'high' ? 'rgba(255,77,77,0.12)' : severity === 'medium' ? 'rgba(249,115,22,0.12)' : 'rgba(100,116,139,0.12)';

  if (!findings.length) {
    return <p className="m-0 text-sm italic text-[#5a4d72]">No anomalies detected on this route</p>;
  }

  const colors = { high: '#FF4D4D', medium: '#F97316', low: '#94a3b8' };
  const severityLabel = severity.charAt(0).toUpperCase() + severity.slice(1);

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <span className="text-[10px] font-bold text-[#7a6d8a] uppercase tracking-wide">{findings.length} observation{findings.length !== 1 ? 's' : ''}</span>
        <span className="inline-flex items-center rounded-full px-2 py-0.5 text-[9px] font-bold" style={{ background: severityBg, color: severityColor, border: `1px solid ${severityColor}44` }}>
          {severityLabel}
        </span>
      </div>
      <ul className="flex flex-col gap-2 m-0 p-0 list-none">
        {findings.map((f, i) => (
          <li key={i} className="flex items-start gap-2 text-[11px] leading-5">
            <span className="w-[6px] h-[6px] rounded-full shrink-0 mt-[5px]" style={{ background: colors[f.severity] || colors.low, boxShadow: `0 0 6px ${colors[f.severity] || colors.low}88` }} />
            <span style={{ color: colors[f.severity] || '#c4b5fd' }}>
              {f.hop != null ? `Hop ${f.hop} \u2014 ` : ''}{f.label}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ─── AI Summary ─────────────────────────────────────────────────── */
function AiSummaryPanel({ data, hops, segments }) {
  const lines = useMemo(() => buildAiSummary(data, hops, segments), [data, hops, segments]);
  const confidence = useMemo(() => confidenceLevel(data, hops), [data, hops]);

  return (
    <div className="rounded-[10px] border border-[rgba(124,58,237,0.3)] p-[18px_20px] relative overflow-hidden transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]" style={{ background: 'linear-gradient(135deg, rgba(52,20,80,0.72) 0%, rgba(28,12,50,0.8) 100%)' }}>
      <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(167,139,250,0.55), transparent)' }} />
      <div className="flex items-center gap-2.5 mb-3.5">
        <div className="w-7 h-7 rounded-lg grid place-items-center shrink-0" style={{ background: 'rgba(124,58,237,0.25)', border: '1px solid rgba(167,139,250,0.35)' }}>
          <Sparkles className="w-4 h-4" style={{ color: '#c4b5fd' }} />
        </div>
        <span className="text-[13px] font-bold uppercase tracking-wide" style={{ color: '#c4b5fd' }}>AI Summary</span>
        <span className="ml-auto inline-flex items-center rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-wider" style={{ background: `${confidence.color}18`, color: confidence.color, border: `1px solid ${confidence.color}33` }}>
          {confidence.label}
        </span>
      </div>
      <ul className="m-0 p-0 list-none flex flex-col gap-[7px]">
        {lines.map((line, i) => (
          <li key={i} className="flex items-start gap-2 text-[12px] leading-[1.65]" style={{ color: '#c4b5fd' }}>
            <span className="w-[5px] h-[5px] rounded-full shrink-0 mt-[6px]" style={{ background: 'rgba(167,139,250,0.6)' }} />
            <span>{line}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ─── Monitoring Panel (Main) ────────────────────────────────────── */
export default function MonitoringPanel({ data, hops }) {
  const segments = useMemo(() => buildSegments(hops || []), [hops]);

  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3.5">
        <div className="rounded-[10px] border p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]" style={{ borderColor: 'rgba(124,58,237,0.18)', background: 'rgba(15,8,27,0.6)' }}>
          <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest mb-3.5" style={{ color: '#7a6d8a' }}>
            <BarChart3 className="w-4 h-4" />
            <span>Segment Breakdown</span>
          </div>
          <SegmentBreakdown hops={hops || []} />
        </div>

        <div className="rounded-[10px] border p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]" style={{ borderColor: 'rgba(124,58,237,0.18)', background: 'rgba(15,8,27,0.6)' }}>
          <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest mb-3.5" style={{ color: '#7a6d8a' }}>
            <Share2 className="w-4 h-4" />
            <span>ASN / Provider Flow</span>
          </div>
          <AsnFlowDiagram hops={hops || []} />
        </div>

        <div className="rounded-[10px] border p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]" style={{ borderColor: 'rgba(124,58,237,0.18)', background: 'rgba(15,8,27,0.6)' }}>
          <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest mb-3.5" style={{ color: '#7a6d8a' }}>
            <ShieldAlert className="w-4 h-4" />
            <span>MITRE ATT&CK Mapping</span>
            {data?.route_risk && (
              <span className="ml-auto inline-flex items-center rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider" style={{ color: '#FF4D4D', background: 'rgba(255,77,77,0.12)', border: '1px solid rgba(255,77,77,0.28)' }}>
                {data.route_risk}
              </span>
            )}
          </div>
          <MitrePanel hops={hops || []} data={data} />
        </div>
      </div>

      <AiSummaryPanel data={data} hops={hops || []} segments={segments} />
    </div>
  );
}
