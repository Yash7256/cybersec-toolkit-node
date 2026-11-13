import { useMemo } from 'react';

export default function InteractiveNetworkMap({ hops }) {
  const points = useMemo(() => {
    if (!hops || hops.length === 0) return [];
    const lats = hops.map((h) => h.lat);
    const lngs = hops.map((h) => h.lng);
    const minLat = Math.min(...lats);
    const maxLat = Math.max(...lats);
    const minLng = Math.min(...lngs);
    const maxLng = Math.max(...lngs);
    const latRange = maxLat - minLat || 1;
    const lngRange = maxLng - minLng || 1;
    const pad = 15;
    return hops.map((h) => ({
      ...h,
      xPct: pad + ((h.lng - minLng) / lngRange) * (100 - pad * 2),
      yPct: pad + (1 - (h.lat - minLat) / latRange) * (100 - pad * 2),
    }));
  }, [hops]);

  return (
    <div className="rounded-[10px] border border-white/[0.18] bg-[#190f23]/78 p-6 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
      <div className="mb-3 flex items-center gap-2.5 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]">
        <span className="flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full border border-[#ba9cff]">
          <span className="h-[7px] w-[7px] rounded-full bg-[#ba9cff]" />
        </span>
        INTERACTIVE NETWORK MAP
      </div>
      <div className="relative min-h-[220px] flex-1 rounded-[8px] bg-[radial-gradient(circle_at_30%_40%,rgba(186,156,255,0.12),transparent_60%)]">
        {points.length === 0 ? (
          <p className="m-0 px-6 py-16 text-center text-sm text-[#aaaaaa]">No resolvable hop geolocation for this scan.</p>
        ) : (
          <>
            <svg width="100%" height="100%" style={{ position: 'absolute', inset: 0 }}>
              {points.slice(1).map((p, i) => {
                const prev = points[i];
                return (
                  <line key={`${prev.city}-${p.city}`} x1={`${prev.xPct}%`} y1={`${prev.yPct}%`} x2={`${p.xPct}%`} y2={`${p.yPct}%`} stroke="#ba9cff" strokeOpacity="0.5" strokeWidth="1.5" />
                );
              })}
            </svg>
            {points.map((p) => (
              <div key={`${p.city}-${p.lat}-${p.lng}`} className="absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center gap-1" style={{ left: `${p.xPct}%`, top: `${p.yPct}%` }}>
                <span className="h-[9px] w-[9px] rounded-full bg-[#ba9cff]" />
                <span className="whitespace-nowrap text-[10px] text-white">{p.city}<br />{p.countryCode}</span>
              </div>
            ))}
          </>
        )}
      </div>
      <p className="mt-3 text-[11px] text-[#aaaaaa]">Positions are approximate, derived from per-hop GeoIP resolution.</p>
    </div>
  );
}
