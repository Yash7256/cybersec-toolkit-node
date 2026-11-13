import { CheckCircle2, ShieldCheck, UserX, Clock, Terminal, HeartPulse, ExternalLink } from 'lucide-react';

function ratingFromLatency(ms) {
  if (ms == null) return { label: '\u2014', tone: '' };
  if (ms < 50) return { label: 'Good', tone: 'success' };
  if (ms < 150) return { label: 'Moderate', tone: '' };
  return { label: 'High', tone: 'danger' };
}

function ratingFromScore(score) {
  if (score == null) return { label: '\u2014', tone: '' };
  if (score >= 80) return { label: 'Excellent', tone: 'success' };
  if (score >= 50) return { label: 'Fair', tone: '' };
  return { label: 'Poor', tone: 'danger' };
}

export default function ScanSummaryHero({ data }) {
  if (!data) return null;

  const stability = ratingFromScore(data.stabilityScore);
  const latencyRating = ratingFromLatency(data.finalLatencyMs);

  const cards = [
    {
      icon: ShieldCheck, label: 'Stability',
      value: data.stabilityScore != null ? `${data.stabilityScore}/100` : '\u2014',
      valueTone: stability.tone, sub: stability.label, subTone: stability.tone,
    },
    {
      icon: Clock, label: 'Final Latency',
      value: data.finalLatencyMs != null ? `${data.finalLatencyMs.toFixed(2)} ms` : '\u2014',
      valueTone: latencyRating.tone, sub: latencyRating.label, subTone: latencyRating.tone,
    },
    {
      icon: UserX, label: 'Packet Loss Hops',
      value: data.packetLossHops ?? '\u2014',
      sub: 'Traceroute probe loss',
    },
    {
      icon: CheckCircle2, label: 'Visible Hops',
      value: `${data.visibleHops}/${data.totalHops}`,
      sub: data.filteredHops ? `${data.filteredHops} Filtered` : 'All hops visible',
    },
    {
      icon: CheckCircle2, label: 'Route Risk',
      value: data.routeRisk || '\u2014',
      valueTone: data.routeRisk === 'High' ? 'danger' : data.routeRisk === 'Low' ? 'success' : '',
      sub: data.routeRiskReason,
    },
    {
      icon: Terminal, label: 'CDN/Cloud',
      value: data.cdnProvider || 'None detected',
      sub: data.cdnProvider ? 'Cloud edge inference.' : 'No CDN/cloud signature found.',
    },
    {
      icon: HeartPulse, label: 'Geo Route',
      value: data.geoRouteSummary || '\u2014',
      sub: data.geoRouteDetail,
    },
  ];

  return (
    <section className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-8 shadow-[0_18px_60px_rgba(0,0,0,0.18)] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
      <div className="mb-[12px] flex items-center justify-between">
        <h1 className="m-0 flex items-center gap-2 text-[28px] font-semibold break-all">
          {data.target}
          <ExternalLink className="h-4 w-4 text-[#b895ff]" />
        </h1>
      </div>

      <div className="mb-[22px] flex flex-wrap gap-2">
        <span className={`inline-flex items-center gap-1.5 rounded-full border border-white/[0.28] bg-[#190f23] px-4 py-1 text-[10px] ${data.status === 'online' ? 'text-[#7CFF9A]' : 'text-white'}`}>
          <CheckCircle2 size={12} />
          {data.status === 'online' ? 'Online: Target is reachable' : 'Target unreachable'}
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map((c) => (
          <div key={c.label} className="min-h-[116px] rounded-[10px] border border-white/[0.22] bg-[#160d24]/80 p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
            <div className="mb-5 flex items-center gap-2 text-[10px] font-bold text-white">
              <c.icon size={16} className="shrink-0 text-white" />
              {c.label}
            </div>
            <div className={`mb-1.5 text-[17px] font-semibold leading-tight ${c.valueTone === 'danger' ? 'text-[#FF4D4D]' : c.valueTone === 'success' ? 'text-[#7CFF9A]' : 'text-white'}`}>
              {c.value}
            </div>
            {c.sub ? (
              <div className={`text-[9px] font-medium text-[#8e819b] ${c.subTone === 'danger' ? 'text-[#FF4D4D]' : ''}`}>
                {c.sub}
              </div>
            ) : null}
          </div>
        ))}
      </div>
    </section>
  );
}
