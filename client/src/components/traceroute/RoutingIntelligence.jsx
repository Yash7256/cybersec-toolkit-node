export default function RoutingIntelligence({ insights }) {
  if (!insights || insights.length === 0) {
    return (
      <div className="rounded-[10px] border border-white/[0.18] bg-[#190f23]/78 p-6 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
        <p className="m-0 text-center text-sm text-[#aaaaaa]">No routing insights generated for this scan.</p>
      </div>
    );
  }
  return (
    <div className="rounded-[10px] border border-white/[0.18] bg-[#190f23]/78 p-6 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
      <ul className="m-0 list-none p-0">
        {insights.map((insight) => (
          <li key={insight.id} className="border-b border-white/[0.11] py-3.5 text-sm leading-5 last:border-b-0">
            {insight.text}
          </li>
        ))}
      </ul>
    </div>
  );
}
