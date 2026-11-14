const labelFor = (key) => String(key).replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
const empty = (value) => value === null || value === undefined || value === ''

function Primitive({ value }) {
  if (empty(value)) return <span className="text-[#777]">Not available</span>
  if (typeof value === 'boolean') return <span className={value ? 'text-[#7CFF9A]' : 'text-[#aaa]'}>{value ? 'Yes' : 'No'}</span>
  return <span className="break-words text-white">{String(value)}</span>
}

function Value({ value, depth = 0 }) {
  if (empty(value) || typeof value !== 'object') return <Primitive value={value} />
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-[#777]">None</span>
    return <div className="space-y-2">{value.map((entry, index) => <div className="rounded-lg border border-white/[0.08] bg-[#190f23]/60 p-3" key={index}><Value value={entry} depth={depth + 1} /></div>)}</div>
  }
  return <div className={`grid gap-x-5 gap-y-2 ${depth === 0 ? 'grid-cols-1 md:grid-cols-2' : 'grid-cols-1'}`}>{Object.entries(value).map(([key, entry]) => <div className="min-w-0" key={key}><div className="text-[10px] font-semibold uppercase tracking-wider text-[#ba9cff]">{labelFor(key)}</div><div className="mt-1 text-[11px] leading-5 text-[#ded4e9]"><Value value={entry} depth={depth + 1} /></div></div>)}</div>
}

export default function StructuredGeoIPDetails({ result }) {
  if (!result) return null
  const entries = Object.entries(result).filter(([key]) => !['mode', 'target', 'rows'].includes(key))
  return <section className="mt-4 rounded-xl border border-white/[0.14] bg-[#201330]/82 p-5"><div className="mb-4 flex items-center justify-between"><div><h2 className="text-sm font-semibold uppercase tracking-wider text-[#ba9cff]">Complete lookup details</h2><p className="mt-1 text-[11px] text-[#aaa]">All available results are grouped below in readable sections.</p></div><span className="rounded-full border border-[#ba9cff]/30 px-2 py-1 text-[10px] text-[#ba9cff]">{labelFor(result.mode ?? 'result')}</span></div><div className="grid gap-3 md:grid-cols-2">{entries.map(([key, value]) => <details className="rounded-xl border border-white/[0.1] bg-[#190f23]/65 p-4" key={key} open={['privacy', 'reputation', 'asn_lookup', 'cidr_prefixes', 'warnings'].includes(key)}><summary className="cursor-pointer text-xs font-semibold uppercase tracking-wider text-[#ded4e9]">{labelFor(key)}</summary><div className="mt-3"><Value value={value} /></div></details>)}</div>{Array.isArray(result.rows) && result.rows.length > 0 && <div className="mt-3 rounded-xl border border-white/[0.1] bg-[#190f23]/65 p-4"><h3 className="text-xs font-semibold uppercase tracking-wider text-[#ded4e9]">Per-target details</h3><div className="mt-3 space-y-2">{result.rows.map((row, index) => <details className="rounded-lg border border-white/[0.08] bg-[#201330]/70 p-3" key={`${row.input}-${index}`}><summary className="cursor-pointer text-[11px] font-semibold text-white">{row.input} · {row.status}</summary><div className="mt-3"><Value value={row} /></div></details>)}</div></div>}</section>
}
