import {
  Activity,
  ArrowRight,
  Building2,
  CheckCircle2,
  CircleDot,
  Database,
  Download,
  ExternalLink,
  FileText,
  Globe2,
  Info,
  MapPin,
  Network,
  Radio,
  Share2,
  ShieldCheck,
  Timer,
  X,
} from 'lucide-react';

const fallback = (value, empty = 'Unknown') => (
  value === null || value === undefined || value === '' ? empty : String(value)
);

const boolText = (value) => (value === true ? 'Yes' : value === false ? 'No' : 'Unknown');

const ipTypeFrom = (ip, explicit) => explicit || (String(ip || '').includes(':') ? 'IPv6' : 'IPv4');

const confidencePercent = (value) => {
  if (typeof value === 'number') return Math.max(0, Math.min(100, value));
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized.endsWith('%')) return Math.max(0, Math.min(100, Number(normalized.slice(0, -1)) || 0));
  if (normalized === 'high') return 88;
  if (normalized === 'medium') return 62;
  if (normalized === 'low') return 34;
  return 50;
};

const normalizeGeoIPResult = (raw = {}) => {
  const lat = raw.location?.latitude ?? raw.lat ?? raw.latitude;
  const lon = raw.location?.longitude ?? raw.lon ?? raw.longitude;
  const resolvedIp = raw.resolvedIp ?? raw.ip;
  const resolvedIps = raw.resolvedIps ?? raw.resolved_ips ?? (resolvedIp ? [resolvedIp] : []);
  const providerName = raw.provider?.name ?? raw.provider ?? 'ipwhois';
  const cached = raw.provider?.cached ?? raw.cached ?? false;
  const location = {
    country: raw.location?.country ?? raw.country,
    countryCode: raw.location?.countryCode ?? raw.country_code,
    continent: raw.location?.continent ?? raw.continent,
    continentCode: raw.location?.continentCode ?? raw.continent_code,
    region: raw.location?.region ?? raw.region,
    city: raw.location?.city ?? raw.city,
    postalCode: raw.location?.postalCode ?? raw.postal,
    latitude: lat,
    longitude: lon,
    timezone: raw.location?.timezone ?? raw.timezone,
    utcOffset: raw.location?.utcOffset ?? raw.timezone_utc,
    flagEmoji: raw.flag_emoji,
  };
  const network = {
    isp: raw.network?.isp ?? raw.isp,
    organization: raw.network?.organization ?? raw.organization ?? raw.org,
    asn: raw.network?.asn ?? raw.asn,
    asnDomain: raw.network?.asnDomain ?? raw.asn_domain,
    callingCode: raw.network?.callingCode ?? raw.calling_code,
  };
  const security = {
    cdn: raw.security?.cdn ?? raw.is_cdn,
    cdnProvider: raw.security?.cdnProvider ?? raw.cdn_provider,
    proxy: raw.security?.proxy ?? raw.is_proxy,
    hosting: raw.security?.hosting ?? raw.is_hosting,
    confidence: raw.security?.confidence ?? raw.confidence,
    locationAccuracy: raw.security?.locationAccuracy ?? raw.location_accuracy,
  };
  const dns = {
    target: raw.dns?.target ?? raw.target,
    resolvedIps,
    reverseDns: raw.dns?.reverseDns ?? raw.reverse_dns,
  };
  const rows = Array.isArray(raw.resolvedIps)
    ? raw.resolvedIps
    : Array.isArray(raw.ip_results) && raw.ip_results.length
      ? raw.ip_results
      : [raw];

  return {
    target: raw.target,
    status: raw.status ?? (raw.scanning ? 'running' : raw.error ? 'failed' : 'completed'),
    scanning: Boolean(raw.scanning),
    scanMessage: raw.scan_message,
    resolvedIp,
    ipType: ipTypeFrom(resolvedIp, raw.ipType),
    scanDurationSeconds: raw.scanDurationSeconds ?? raw.scan_duration_seconds,
    cacheSource: raw.cacheSource ?? providerName,
    asn: raw.asn,
    isp: raw.isp,
    organization: raw.organization ?? raw.org,
    proxyOrCdn: Boolean(raw.proxyOrCdn ?? raw.is_cdn ?? raw.is_proxy),
    confidenceScore: raw.confidenceScore ?? raw.confidence,
    aiSummary: raw.aiSummary ?? raw.infrastructure_note ?? raw.summary,
    location,
    network,
    security,
    dns,
    resolvedIps: rows.map((row) => ({
      ip: row.ip || row.target || resolvedIp,
      type: ipTypeFrom(row.ip || row.target || resolvedIp, row.type || row.asn_type),
      provider: row.provider || row.cdn_provider || raw.cdn_provider || providerName,
      edgeCdn: Boolean(row.edgeCdn ?? row.is_cdn ?? raw.is_cdn),
      country: row.country || location.country,
      countryCode: row.countryCode || row.country_code || location.countryCode,
      flagEmoji: row.flag_emoji || location.flagEmoji,
      asn: row.asn || raw.asn,
      org: row.org || row.organization || raw.org || raw.organization,
      city: row.city || location.city,
      reverseDns: row.reverseDns || row.reverse_dns || raw.reverse_dns,
      summary: row.summary || raw.summary || raw.infrastructure_note,
    })),
    provider: { name: providerName, cached },
    mapUrl: raw.map_url,
    raw,
  };
};

const SectionCard = ({ children, className = '' }) => (
  <section className={`rounded-xl border border-white/[0.14] bg-[#201330]/82 p-5 shadow-[0_18px_60px_rgba(0,0,0,0.18)] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)] ${className}`}>
    {children}
  </section>
);

const SectionHeading = ({ children }) => (
  <div className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]">{children}</div>
);

const InfoRow = ({ label, value }) => {
  if (value === null || value === undefined || value === '') return null;
  return (
    <div className="grid grid-cols-[108px_minmax(0,1fr)] gap-2 border-b border-white/[0.08] py-2 last:border-b-0">
      <span className="text-[10px] font-medium text-[#aaaaaa]">{label}</span>
      <span className="whitespace-pre-line text-[11px] font-semibold leading-5 text-white break-words">{fallback(value)}</span>
    </div>
  );
};

const Pill = ({ children, tone = 'neutral' }) => {
  const tones = {
    neutral: 'border-white/[0.14] bg-[#190f23]/85 text-[#d8cfea]',
    success: 'border-[#7CFF9A]/45 bg-[#132718] text-[#7CFF9A]',
    warning: 'border-[#76552a]/45 bg-[#46351e] text-[#ffd38a]',
    info: 'border-[#49668f]/45 bg-[#24324a] text-[#a9c7ff]',
  };
  return <span className={`inline-flex h-[26px] items-center gap-1.5 rounded-full border px-2.5 text-[10px] font-medium ${tones[tone] || tones.neutral}`}>{children}</span>;
};

const StatCard = ({ icon: Icon, label, value, subtext, children }) => (
  <div className="rounded-[10px] border border-white/[0.18] bg-[#190f23]/78 p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
    <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-[#ba9cff]">
      <Icon className="h-3 w-3 shrink-0" />
      <span>{label}</span>
    </div>
    <div className="mt-2 text-[13px] font-semibold leading-snug text-white break-words">{fallback(value)}</div>
    {subtext && <div className="mt-0.5 text-[10px] text-[#aaaaaa] break-words">{subtext}</div>}
    {children}
  </div>
);

export function ScanInputBar({ target, placeholder, loading, onTargetChange, onClear, onRun, runLabel = 'Run Scan' }) {
  return (
    <div className="scanner-control-shell">
      <div className="relative min-w-[320px] flex-1">
        <input
          type="text"
          className="scan-input"
          placeholder={placeholder}
          value={target}
          onChange={(event) => onTargetChange(event.target.value)}
          onKeyDown={(event) => event.key === 'Enter' && onRun()}
        />
        {target && (
          <button type="button" onClick={onClear} className="clear-input-btn" aria-label="Clear target">
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
      <button type="button" onClick={onRun} disabled={loading || !target} className="run-btn">
        <span>{loading ? 'Running' : runLabel}</span>
        {loading ? <span className="h-4 w-4 rounded-full border-2 border-white/35 border-t-white animate-spin" /> : <ArrowRight className="h-4 w-4" />}
      </button>
    </div>
  );
}

export function ScanSummaryHero({ result }) {
  const confidence = confidencePercent(result.confidenceScore);
  const statusLabel = result.scanning ? 'Lookup Running' : result.status === 'failed' ? 'Lookup Failed' : 'Lookup Completed';
  const duration = Number.isFinite(Number(result.scanDurationSeconds)) ? `${Number(result.scanDurationSeconds).toFixed(1)}s` : 'Live';
  return (
    <SectionCard>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-[22px] font-semibold leading-tight text-white">{fallback(result.target, 'GeoIP lookup')}</h2>
            {result.mapUrl && <a href={result.mapUrl} target="_blank" rel="noreferrer" aria-label="Open map"><ExternalLink className="h-3.5 w-3.5 text-[#ba9cff]" /></a>}
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            <Pill tone={result.scanning ? 'neutral' : 'success'}>{result.scanning ? <Activity className="h-3 w-3 animate-pulse" /> : <CheckCircle2 className="h-3 w-3" />}{statusLabel}</Pill>
            <Pill><MapPin className="h-3 w-3" />{fallback(result.resolvedIp)}</Pill>
            <Pill><Timer className="h-3 w-3" />{duration}</Pill>
            <Pill><Database className="h-3 w-3" />{result.provider.cached ? `Cached (${fallback(result.cacheSource).toUpperCase()})` : `Fresh (${fallback(result.cacheSource).toUpperCase()})`}</Pill>
          </div>
        </div>
      </div>

      {(result.scanning || result.aiSummary || result.scanMessage) && (
        <div className="mt-4 flex items-center gap-3 rounded-xl border border-[#ba9cff]/30 bg-[linear-gradient(180deg,rgba(186,156,255,.16),rgba(58,27,87,.10))] px-4 py-3 text-[#ded4e9]">
          {result.scanning ? <Activity className="h-4 w-4 shrink-0 animate-pulse text-[#ba9cff]" /> : <Info className="h-4 w-4 shrink-0 text-[#ba9cff]" />}
          <p className="text-[12px] leading-5">{result.scanning ? result.scanMessage || 'GeoIP lookup is running...' : result.aiSummary}</p>
        </div>
      )}

      <div className="mt-4 grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-6">
        <StatCard icon={Globe2} label="IP Address" value={result.resolvedIp} subtext={result.ipType} />
        <StatCard icon={Network} label="ASN" value={result.asn} subtext={result.organization} />
        <StatCard icon={Radio} label="ISP" value={result.isp} />
        <StatCard icon={Building2} label="Organization" value={result.organization} />
        <StatCard icon={MapPin} label="IP Type" value={result.proxyOrCdn ? 'Proxy/CDN' : result.ipType} subtext={result.security.cdnProvider} />
        <StatCard icon={ShieldCheck} label="Confidence Score" value={result.confidenceScore}>
          <div className="mt-2 h-1 rounded-full bg-white/[0.18]">
            <div className="h-full rounded-full bg-[#7CFF9A]" style={{ width: `${confidence}%` }} />
          </div>
        </StatCard>
      </div>
    </SectionCard>
  );
}

export function LocationSection({ result }) {
  const { location, network, security, dns } = result;
  const hasCoordinates = Number.isFinite(Number(location.latitude)) && Number.isFinite(Number(location.longitude));
  const coordinates = hasCoordinates ? `${location.latitude},${location.longitude}` : '';

  const mapEmbedUrl = hasCoordinates
    ? `https://maps.google.com/maps?q=${encodeURIComponent(coordinates)}&z=13&output=embed`
    : '';
  const mapUrl = result.mapUrl || (hasCoordinates ? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(coordinates)}` : null);
  const earthUrl = hasCoordinates ? `https://earth.google.com/web/search/${encodeURIComponent(coordinates)}` : null;

  return (
    <SectionCard>
      <SectionHeading>Location</SectionHeading>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(280px,372px)_minmax(0,1fr)]">
        <div className="min-w-0 rounded-xl border border-white/[0.14] bg-[#190f23]/76 p-5">
          <InfoRow label="Country" value={[location.country, location.countryCode && `(${location.countryCode})`, location.flagEmoji].filter(Boolean).join(' ')} />
          <InfoRow label="Continent" value={[location.continent, location.continentCode && `(${location.continentCode})`].filter(Boolean).join(' ')} />
          <InfoRow label="Region" value={location.region} />
          <InfoRow label="City" value={location.city} />
          <InfoRow label="Postal code" value={location.postalCode} />
          <InfoRow label="Coordinates" value={hasCoordinates ? coordinates : null} />
          <InfoRow label="Timezone" value={location.timezone} />
          <InfoRow label="UTC offset" value={location.utcOffset} />
          <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
            {mapUrl && <a className="inline-flex h-8 items-center justify-center gap-1.5 rounded-lg border border-white/[0.14] bg-[#201330]/80 px-3 text-[10px] font-medium text-[#ba9cff] transition hover:border-[#ba9cff]/70 hover:text-white" href={mapUrl} target="_blank" rel="noreferrer">Google Maps <ExternalLink className="h-3 w-3" /></a>}
            {earthUrl && <a className="inline-flex h-8 items-center justify-center gap-1.5 rounded-lg border border-white/[0.14] bg-[#201330]/80 px-3 text-[10px] font-medium text-[#ba9cff] transition hover:border-[#ba9cff]/70 hover:text-white" href={earthUrl} target="_blank" rel="noreferrer">Google Earth <ExternalLink className="h-3 w-3" /></a>}
          </div>
        </div>

        {/* Map preview */}
        <div className="relative min-h-[260px] overflow-hidden rounded-xl border border-white/[0.14] bg-[#190f23]">
          {hasCoordinates ? (
            <>
              <iframe
                title={`Google Maps — ${[location.city, location.region, location.country].filter(Boolean).join(', ') || coordinates}`}
                src={mapEmbedUrl}
                className="absolute inset-0 h-full w-full grayscale invert-[0.86] hue-rotate-[226deg] saturate-[2.1] brightness-[0.66] contrast-[1.18]"
                loading="lazy"
                referrerPolicy="no-referrer-when-downgrade"
                allowFullScreen
              />
              <div className="pointer-events-none absolute inset-0 bg-[#301052]/30 mix-blend-screen" />
              {/* Pin centered above the focal point */}
              <div className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-full">
                <div className="relative flex h-14 w-14 items-center justify-center rounded-full border border-[#ba9cff]/45 bg-[#8b5cf6]/20 shadow-[0_0_28px_rgba(186,156,255,0.65)]">
                  <div className="absolute inset-3 rounded-full border border-[#d6c5ff]/55 bg-[#8b5cf6]/30" />
                  <MapPin className="h-[18px] w-[18px] text-white drop-shadow" />
                </div>
                <div className="mx-auto h-3 w-0.5 bg-[#ba9cff]/60" />
              </div>
              <div className="pointer-events-none absolute right-3 top-3 max-w-[190px] rounded-xl border border-white/[0.14] bg-[#201330]/90 p-3 shadow-[0_14px_34px_rgba(0,0,0,0.35)] backdrop-blur">
                <div className="text-[11px] font-semibold leading-4 text-white">{fallback(location.city, location.region || location.country || 'Location')}</div>
                <div className="mt-0.5 text-[10px] leading-4 text-[#d8cfea]">{[location.region, location.country].filter(Boolean).join(', ')}</div>
                <div className="mt-0.5 font-mono text-[9px] leading-4 text-[#ba9cff]">{coordinates}</div>
              </div>
            </>
          ) : (
            <div className="absolute inset-0 grid place-items-center p-6 text-center">
              <div><MapPin className="mx-auto h-8 w-8 text-[#ba9cff]" /><p className="mt-3 text-sm text-[#d8cfea]">Coordinates unavailable for this lookup.</p></div>
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-3 xl:grid-cols-3">
        <InfoCard title="Network Information">
          <InfoRow label="ISP" value={network.isp} />
          <InfoRow label="Organization" value={network.organization} />
          <InfoRow label="ASN" value={network.asn} />
          <InfoRow label="ASN Domain" value={network.asnDomain} />
          <InfoRow label="Calling Code" value={network.callingCode} />
        </InfoCard>
        <InfoCard title="Security Information">
          <InfoRow label="CDN" value={boolText(security.cdn)} />
          <InfoRow label="CDN Provider" value={security.cdnProvider} />
          <InfoRow label="Proxy" value={boolText(security.proxy)} />
          <InfoRow label="Hosting" value={boolText(security.hosting)} />
          <InfoRow label="Confidence" value={security.confidence} />
          <InfoRow label="Location Accuracy" value={security.locationAccuracy} />
        </InfoCard>
        <InfoCard title="DNS Information">
          <InfoRow label="Target" value={dns.target} />
          <InfoRow label="Resolved IPs" value={Array.isArray(dns.resolvedIps) ? dns.resolvedIps.join('\n') : dns.resolvedIps} />
          <InfoRow label="Reverse DNS" value={dns.reverseDns || 'No PTR record'} />
        </InfoCard>
      </div>
    </SectionCard>
  );
}

function InfoCard({ title, children }) {
  return (
    <div className="rounded-[10px] border border-white/[0.14] bg-[#190f23]/78 p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
      <div className="mb-3 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-[#ba9cff]">
        <CircleDot className="h-3.5 w-3.5" />
        <span>{title}</span>
      </div>
      {children}
    </div>
  );
}

export function ResolvedIpsSection({ result }) {
  return (
    <SectionCard>
      <SectionHeading>All Resolved IPs</SectionHeading>
      <div className="space-y-3">
        {result.resolvedIps.map((item, index) => (
          <div key={`${item.ip}-${index}`} className="grid grid-cols-1 items-start gap-4 rounded-xl border border-white/[0.08] bg-[#190f23]/72 p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)] md:grid-cols-[minmax(180px,0.9fr)_minmax(220px,1.2fr)] xl:grid-cols-[minmax(190px,0.95fr)_minmax(240px,1.15fr)_repeat(4,minmax(82px,0.55fr))]">
            <div className="min-w-0 space-y-1.5">
              <div className="flex items-center gap-2 text-[17px] font-semibold leading-tight text-white">
                <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-[#7CFF9A] shadow-[0_0_12px_rgba(87,194,84,0.55)]" />
                <span className="truncate">{fallback(item.ip)}</span>
              </div>
              <div className="flex items-baseline gap-1.5 text-[11px] font-medium leading-5 text-[#d8cfea]">
                <span>{[item.country, item.countryCode && `(${item.countryCode})`].filter(Boolean).join(' ')}</span>
                <span>{item.flagEmoji}</span>
              </div>
              {item.edgeCdn && <span className="inline-flex h-5 items-center rounded-full border border-[#7CFF9A]/45 bg-[rgba(87,194,84,0.29)] px-2.5 text-[9px] font-semibold uppercase tracking-wide text-[#7CFF9A]">Edge/CDN</span>}
            </div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-1.5">
                <Pill tone="warning">{item.type}</Pill>
                <Pill tone="info">{fallback(item.provider)}</Pill>
              </div>
              <p className="mt-2 max-h-[36px] max-w-[360px] overflow-hidden text-[11px] leading-[18px] text-[#d8cfea]">{item.summary}</p>
            </div>
            {[
              ['ASN', item.asn],
              ['Org', item.org],
              ['City', item.city],
              ['Reverse DNS', item.reverseDns || 'No PTR record'],
            ].map(([label, value]) => (
              <div key={label} className="min-w-0 border-t border-white/[0.06] pt-3 md:border-t-0 md:pt-0">
                <div className="text-[12px] font-medium leading-4 text-[#aaaaaa]">{label}</div>
                <div className="mt-1 text-[11px] font-semibold leading-[18px] text-white break-words">{fallback(value)}</div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

export function ProviderInfoSection({ result }) {
  return (
    <SectionCard>
      <SectionHeading>Provider Information</SectionHeading>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <StatCard icon={Building2} label="Provider" value={fallback(result.provider.name).toUpperCase()} />
        <StatCard icon={Database} label="Cached" value={boolText(result.provider.cached)} />
      </div>
    </SectionCard>
  );
}

const csvEscape = (value) => `"${String(value ?? '').replaceAll('"', '""')}"`;

const toCsv = (result) => {
  const rows = [
    ['target', result.target],
    ['resolved_ip', result.resolvedIp],
    ['asn', result.asn],
    ['isp', result.isp],
    ['organization', result.organization],
    ['country', result.location.country],
    ['city', result.location.city],
    ['provider', result.provider.name],
    ['cached', result.provider.cached],
  ];
  const ipRows = result.resolvedIps.map((ip) => ['resolved_ip_row', ip.ip, ip.type, ip.provider, ip.country, ip.asn, ip.org, ip.city, ip.reverseDns]);
  return [...rows, [''], ['row_type', 'ip', 'type', 'provider', 'country', 'asn', 'org', 'city', 'reverse_dns'], ...ipRows]
    .map((row) => row.map(csvEscape).join(','))
    .join('\n');
};

export function ExportShareSection({ result, copied, onCopy, onDownload }) {
  const baseName = `${result.target || result.resolvedIp || 'geoip'}-geoip`;
  const shareText = `${fallback(result.target, 'GeoIP result')}: ${fallback(result.resolvedIp)} ${fallback(result.location.city, '')} ${fallback(result.location.country, '')}`.trim();
  const share = async () => {
    if (navigator.share) {
      await navigator.share({ title: 'GeoIP scan report', text: shareText });
      return;
    }
    await onCopy('geo-share', shareText);
  };
  return (
    <SectionCard>
      <SectionHeading>Export & Share</SectionHeading>
      <p className="text-[11px] text-[#aaaaaa]">Download or share your scan report.</p>
      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-4">
        <button type="button" onClick={() => window.print()} className="flex h-9 items-center justify-center gap-2 rounded-lg border border-white/[0.14] bg-[#190f23]/72 text-[12px] text-[#ded4e9] transition hover:border-[#ba9cff]"><FileText className="h-3.5 w-3.5" /> Export PDF</button>
        <button type="button" onClick={() => onDownload(`${baseName}.json`, JSON.stringify(result.raw, null, 2), 'application/json')} className="flex h-9 items-center justify-center gap-2 rounded-lg border border-white/[0.14] bg-[#190f23]/72 text-[12px] text-[#ded4e9] transition hover:border-[#ba9cff]"><FileText className="h-3.5 w-3.5" /> Export JSON</button>
        <button type="button" onClick={() => onDownload(`${baseName}.csv`, toCsv(result), 'text/csv')} className="flex h-9 items-center justify-center gap-2 rounded-lg border border-white/[0.14] bg-[#190f23]/72 text-[12px] text-[#ded4e9] transition hover:border-[#ba9cff]"><Download className="h-3.5 w-3.5" /> Export CSV</button>
        <button type="button" onClick={share} className="flex h-9 items-center justify-center gap-2 rounded-lg border border-white/[0.14] bg-[#190f23]/72 text-[12px] text-[#ded4e9] transition hover:border-[#ba9cff]"><Share2 className="h-3.5 w-3.5" /> {copied === 'geo-share' ? 'Copied' : 'Share report'}</button>
      </div>
    </SectionCard>
  );
}

export default function GeoIPResultsPage({ result: rawResult, copied, onCopy, onDownload }) {
  const result = normalizeGeoIPResult(rawResult);
  if (!rawResult) {
    return <div className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-8 text-center text-sm text-[#aaaaaa]">Run a GeoIP lookup to see the result dashboard.</div>;
  }
  return (
    <div className="space-y-4 p-1 md:p-2">
      <ScanSummaryHero result={result} />
      <LocationSection result={result} />
      <ResolvedIpsSection result={result} />
      <ProviderInfoSection result={result} />
      <ExportShareSection result={result} copied={copied} onCopy={onCopy} onDownload={onDownload} />
    </div>
  );
}
