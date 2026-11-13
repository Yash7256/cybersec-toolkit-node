import { useMemo } from 'react';

const RATING_COLOR = {
  good: '#7CFF9A',
  moderate: '#ffd166',
  poor: '#FF4D4D',
  filtered: '#8b8b8b',
};

const PADDING = { top: 16, right: 16, bottom: 32, left: 48 };
const WIDTH = 720;
const HEIGHT = 260;

export default function LiveLatencyChart({ points }) {
  const { path, dots, yTicks, xTicks, maxY } = useMemo(() => {
    if (!points || points.length === 0) {
      return { path: '', dots: [], yTicks: [], xTicks: [], maxY: 0 };
    }
    const values = points.map((p) => p.latencyMs).filter((v) => v != null);
    const maxVal = Math.max(100, ...values);
    const roundedMax = Math.ceil(maxVal / 100) * 100;
    const chartW = WIDTH - PADDING.left - PADDING.right;
    const chartH = HEIGHT - PADDING.top - PADDING.bottom;
    const xFor = (i) => PADDING.left + (i / Math.max(points.length - 1, 1)) * chartW;
    const yFor = (v) => PADDING.top + chartH - (v / roundedMax) * chartH;
    const linePoints = points
      .filter((p) => p.latencyMs != null)
      .map((p) => `${xFor(points.indexOf(p))},${yFor(p.latencyMs)}`);
    const dots = points.map((p, i) => ({
      x: xFor(i),
      y: p.latencyMs != null ? yFor(p.latencyMs) : PADDING.top + chartH,
      rating: p.latencyMs == null ? 'filtered' : p.rating,
      hop: p.hop,
      latencyMs: p.latencyMs,
    }));
    const yTicks = [0, 100, 200, 300, 400, 500].filter((t) => t <= roundedMax || t === 0);
    const xTicks = points.map((p) => p.hop);
    return {
      path: linePoints.length > 1 ? `M ${linePoints.join(' L ')}` : '',
      dots, yTicks, xTicks, maxY: roundedMax,
    };
  }, [points]);

  if (!points || points.length === 0) {
    return (
      <div className="rounded-[10px] border border-white/[0.18] bg-[#190f23]/78 p-6 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
        <p className="m-0 text-center text-sm text-[#aaaaaa]">No latency data yet \u2014 run a scan to see the graph.</p>
      </div>
    );
  }

  const chartH = HEIGHT - PADDING.top - PADDING.bottom;
  const yFor = (v) => PADDING.top + chartH - (v / maxY) * chartH;

  return (
    <div className="rounded-[10px] border border-white/[0.18] bg-[#190f23]/78 p-6 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
      <div className="mb-3.5 flex flex-wrap justify-end gap-5 text-[13px] text-[#aaaaaa]">
        <span><span className="mr-1.5 inline-block h-[10px] w-[10px] rounded-full" style={{ background: RATING_COLOR.good }} />Good (&lt;50ms)</span>
        <span><span className="mr-1.5 inline-block h-[10px] w-[10px] rounded-full" style={{ background: RATING_COLOR.moderate }} />Moderate (50-150ms)</span>
        <span><span className="mr-1.5 inline-block h-[10px] w-[10px] rounded-full" style={{ background: RATING_COLOR.poor }} />Poor (&gt;150ms)</span>
        <span><span className="mr-1.5 inline-block h-[10px] w-[10px] rounded-full" style={{ background: RATING_COLOR.filtered }} />Filtered</span>
      </div>
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} width="100%" role="img" aria-label="Live latency by hop">
        {yTicks.map((t) => (
          <g key={t}>
            <line x1={PADDING.left} x2={WIDTH - PADDING.right} y1={yFor(t)} y2={yFor(t)} stroke="rgba(255,255,255,0.08)" strokeWidth="1" />
            <text x={PADDING.left - 10} y={yFor(t) + 4} textAnchor="end" fontSize="10" fill="#aaaaaa">{t}</text>
          </g>
        ))}
        {path && <path d={path} fill="none" stroke="#ba9cff" strokeWidth="2" />}
        {dots.map((d, i) => (
          <circle key={i} cx={d.x} cy={d.y} r="4" fill={RATING_COLOR[d.rating]} />
        ))}
        {xTicks.map((hop, i) => (
          <text key={hop} x={PADDING.left + (i / Math.max(xTicks.length - 1, 1)) * (WIDTH - PADDING.left - PADDING.right)} y={HEIGHT - PADDING.bottom + 18} textAnchor="middle" fontSize="10" fill="#aaaaaa">{hop}</text>
        ))}
      </svg>
    </div>
  );
}
