import { useState } from 'react';

const VISIBLE_COUNT = 6;

export default function HopTimeline({ hops }) {
  const [expanded, setExpanded] = useState(false);

  if (!hops || hops.length === 0) {
    return (
      <div className="rounded-2xl border border-white/[0.18] bg-[#190f23]/78 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
        <div className="mb-3 flex items-center gap-2.5 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]">
          <span className="flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full border border-[#ba9cff]">
            <span className="h-[7px] w-[7px] rounded-full bg-[#ba9cff]" />
          </span>
          HOP TIMELINE
        </div>
        <p className="m-0 text-center text-sm text-[#aaaaaa]">No hop data available for this scan.</p>
      </div>
    );
  }

  const visibleHops = expanded ? hops : hops.slice(0, VISIBLE_COUNT);

  return (
    <div className="rounded-2xl border border-white/[0.18] bg-[#190f23]/78 p-8 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2.5 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]">
          <span className="flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full border border-[#ba9cff]">
            <span className="h-[7px] w-[7px] rounded-full bg-[#ba9cff]" />
          </span>
          HOP TIMELINE
        </div>
        {hops.length > VISIBLE_COUNT && (
          <button onClick={() => setExpanded((v) => !v)} className="cursor-pointer rounded-full border border-white/[0.18] bg-[#201330] px-[18px] py-2.5 text-[13px] text-white">
            {expanded ? 'Collapse' : 'Expand All'}
          </button>
        )}
      </div>

      {visibleHops.map((h) => (
        <div key={h.hop} className="grid grid-cols-[48px_24px_1fr_1fr_1fr_1.4fr] items-center gap-3 border-b border-white/[0.05] px-2 py-4 text-[15px] last:border-b-0 max-md:grid-cols-[32px_16px_1fr_1fr] max-md:gap-x-3 max-md:gap-y-1">
          <span className="text-[#aaaaaa]">{h.hop}</span>
          <span className={`h-4 w-4 rounded-full ${h.ok ? 'bg-[#7CFF9A]' : 'bg-[#FF4D4D]'}`} />
          <span>{h.ip}</span>
          <span className={h.ok ? '' : 'text-[#FF4D4D]'}>
            {h.latencyMs != null ? `${h.latencyMs.toFixed(3)} ms` : '* (no response)'}
          </span>
          <span className="max-md:col-span-2 max-md:col-start-3">{h.type}</span>
          <span className="max-md:col-span-2 max-md:col-start-3">
            {h.network}
            {h.deltaMs != null && h.deltaMs > 0 && (
              <span className="ml-1.5 text-[13px] text-[#FF4D4D]">\u2191 +{h.deltaMs.toFixed(3)} ms</span>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}
