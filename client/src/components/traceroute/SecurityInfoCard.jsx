export default function SecurityInfoCard({ info }) {
  if (!info) return null;
  const rows = [
    ['CDN', info.cdn ? 'Yes' : 'No'],
    ['CDN Provider', info.cdnProvider || '\u2014'],
    ['Proxy', info.proxy ? 'Yes' : 'No'],
    ['Hosting', info.hosting ? 'Yes' : 'No'],
    ['Confidence', info.confidence || '\u2014'],
    ['Location Accuracy', info.locationAccuracy || '\u2014'],
  ];
  return (
    <div className="rounded-[10px] border border-white/[0.18] bg-[#190f23]/78 p-5 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
      <div className="mb-3 flex items-center gap-2.5 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]">
        <span className="flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full border border-[#ba9cff]">
          <span className="h-[7px] w-[7px] rounded-full bg-[#ba9cff]" />
        </span>
        {info.title || 'SECURITY INFORMATION'}
      </div>
      <table className="w-full border-collapse">
        <tbody>
          {rows.map(([label, value]) => (
            <tr key={label} className="border-b border-white/[0.26] last:border-b-0">
              <td className="w-[45%] py-3 text-sm text-[#aaaaaa]">{label}</td>
              <td className="py-3 text-right text-sm text-white">{value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
