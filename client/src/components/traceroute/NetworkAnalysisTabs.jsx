import { useState } from 'react';
import { Globe2 } from 'lucide-react';
import LiveLatencyChart from './LiveLatencyChart';
import RoutingIntelligence from './RoutingIntelligence';
import InteractiveNetworkMap from './InteractiveNetworkMap';
import SecurityInfoCard from './SecurityInfoCard';

const TABS = [
  { id: 'network', label: 'Network Analysis' },
  { id: 'monitoring', label: 'Monitoring & Reporting' },
];

export default function NetworkAnalysisTabs({ data, monitoringPanel, hopTimeline }) {
  const [activeTab, setActiveTab] = useState('network');

  return (
    <section>
      <div className="flex overflow-hidden rounded-t-xl" role="tablist">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            aria-selected={activeTab === tab.id}
            className={`flex flex-1 items-center justify-center gap-2.5 cursor-pointer px-0 py-[18px] text-[16px] border-[0.5px] border-white/20 ${
              activeTab === tab.id
                ? 'bg-[#534074] text-white'
                : 'bg-[#271b3c] text-[#aaaaaa]'
            }`}
            onClick={() => setActiveTab(tab.id)}
          >
            <Globe2 size={16} />
            {tab.label}
          </button>
        ))}
      </div>

      <div className="flex flex-col gap-5 rounded-b-xl border border-t-0 border-white/[0.14] bg-[#201330]/82 p-7 shadow-[0_18px_60px_rgba(0,0,0,0.18)] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
        {activeTab === 'network' ? (
          <>
            <div className="grid grid-cols-2 gap-5 max-md:grid-cols-1">
              <div>
                <div className="mb-3 flex items-center gap-2.5 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]">
                  <span className="flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full border border-[#ba9cff]">
                    <span className="h-[7px] w-[7px] rounded-full bg-[#ba9cff]" />
                  </span>
                  ROUTING INTELLIGENCE
                </div>
                <RoutingIntelligence insights={data?.routingInsights} />
              </div>
              <div>
                <div className="mb-3 flex items-center gap-2.5 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]">
                  <span className="flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full border border-[#ba9cff]">
                    <span className="h-[7px] w-[7px] rounded-full bg-[#ba9cff]" />
                  </span>
                  LIVE LATENCY GRAPH
                </div>
                <LiveLatencyChart points={data?.latencyPoints} />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-5 max-md:grid-cols-1">
              <InteractiveNetworkMap hops={data?.geoHops} />
              <div className="grid grid-cols-2 gap-4 max-md:grid-cols-1">
                <SecurityInfoCard info={{ ...data?.originSecurity, title: 'SECURITY INFORMATION \u2014 ORIGIN' }} />
                <SecurityInfoCard info={{ ...data?.destinationSecurity, title: 'SECURITY INFORMATION \u2014 DESTINATION' }} />
              </div>
            </div>
            {hopTimeline}
          </>
        ) : (
          monitoringPanel || (
            <div className="px-6 py-16 text-center text-sm text-[#aaaaaa]">Monitoring & Reporting is not configured for this account.</div>
          )
        )}
      </div>
    </section>
  );
}
