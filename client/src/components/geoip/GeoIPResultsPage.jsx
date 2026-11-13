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
  const normalized = String(value ?? '').trim().toLowerCase();
  if (normalized.endsWith('%')) {
    const parsed = Number(normalized.slice(0, -1));
    return Number.isFinite(parsed) ? Math.max(0, Math.min(100, parsed)) : null;
  }
  if (normalized === 'high') return 88;
  if (normalized === 'medium') return 62;
  if (normalized === 'low') return 34;
  return null;
};

const familyLabel = (family) => (family === 4 ? 'IPv4' : family === 6 ? 'IPv6' : null);

const normalizeIpRow = (row = {}, fallbackIp, fallbackProvider) => {
  const ip = row.ip ?? fallbackIp;
  const reverseDns = row.reverse_dns ?? row.reverseDns;
  return {
    ip,
    type: ipTypeFrom(ip, familyLabel(row.family) ?? row.type),
    provider: row.provider ?? row.cdn_provider ?? fallbackProvider,
    edgeCdn: row.is_cdn === true,
    cdnProvider: row.cdn_provider ?? null,
    country: row.country ?? null,
    countryCode: row.country_code ?? null,
    flagEmoji: row.flag_emoji ?? null,
    asn: row.asn ?? null,
    org: row.org ?? null,
    isp: row.isp ?? null,
    city: row.city ?? null,
    region: row.region ?? null,
    latitude: row.latitude ?? null,
    longitude: row.longitude ?? null,
    reverseDns,
    error: row.error ?? null,
    summary:
      row.error
        ? `Error: ${row.error}`
        : [row.city, row.region, row.country].filter(Boolean).join(', '),
  };
};

const normalizeGeoIPResult = (raw = {}) => {
  const resolvedIp = raw.ip;
  const providerName = typeof raw.provider === 'string' ? raw.provider : null;
  const location = {
    country: raw.country,
    countryCode: raw.country_code,
    continent: raw.continent,
    continentCode: raw.continent_code,
    region: raw.region,
    city: raw.city,
    postalCode: raw.postal,
    latitude: raw.latitude,
    longitude: raw.longitude,
    timezone: raw.timezone,
    utcOffset: raw.utc_offset,
    flagEmoji: raw.flag_emoji,
  };
  const network = {
    isp: raw.isp,
    organization: raw.org,
    asn: raw.asn,
    asnDomain: raw.asn_domain,
    callingCode: raw.calling_code,
  };
  const security = {
    cdn: raw.is_cdn,
    cdnProvider: raw.cdn_provider,
    proxy: raw.privacy?.proxy ?? raw.is_proxy,
    hosting: raw.privacy?.hosting ?? raw.is_hosting,
    vpn: raw.privacy?.vpn ?? raw.is_vpn,
    tor: raw.privacy?.tor ?? raw.is_tor,
    confidence: raw.confidence,
    locationAccuracy: raw.location_accuracy,
    ipTypeBasis: raw.ip_type_basis ?? null,
    accuracyRadiusKm: raw.accuracy_radius_km ?? null,
    accuracyBasis: raw.accuracy_basis ?? null,
  };
  const resolvedIps = Array.isArray(raw.ip_results) && raw.ip_results.length
    ? raw.ip_results.map((row) => normalizeIpRow(row, resolvedIp, providerName))
    : [
        normalizeIpRow(
          {
            ip: resolvedIp,
            country: raw.country,
            country_code: raw.country_code,
            flag_emoji: raw.flag_emoji,
            asn: raw.asn,
            org: raw.org,
            isp: raw.isp,
            city: raw.city,
            region: raw.region,
            latitude: raw.latitude,
            longitude: raw.longitude,
            is_cdn: raw.is_cdn,
            cdn_provider: raw.cdn_provider,
            reverse_dns: raw.reverse_dns,
            provider: providerName,
            error: raw.error,
          },
          resolvedIp,
          providerName,
        ),
      ];
  const dns = {
    target: raw.target,
    resolvedIps: raw.resolved_ips ?? raw.addresses ?? (resolvedIp ? [resolvedIp] : []),
    reverseDns: raw.reverse_dns,
  };

  return {
    target: raw.target,
    status: raw.status ?? (raw.scanning ? 'running' : raw.error ? 'failed' : 'completed'),
    scanning: Boolean(raw.scanning),
    scanMessage: raw.scan_message,
    resolvedIp,
    ipType: ipTypeFrom(resolvedIp, raw.ipType ?? raw.ip_type),
    scanDurationSeconds: raw.scan_duration_seconds,
    cacheSource: providerName,
    asn: raw.asn,
    isp: raw.isp,
    organization: raw.org,
    proxyOrCdn: raw.is_cdn === true || raw.is_proxy === true,
    confidenceScore: raw.confidence,
    location,
    network,
    security,
    dns,
    resolvedIps,
    abuseContact: raw.abuse_contact,
    fallbackNote: raw.fallback_note,
    provider: { name: providerName, cached: Boolean(raw.cached) },
    mapUrl: raw.map_url,
    warnings: Array.isArray(raw.warnings) ? raw.warnings : [],
    freshness: raw.freshness ?? null,
    consensus: raw.consensus ?? null,
    anycast: raw.anycast ?? null,
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

const AbuseContactRow = ({ contact }) => {
  if (!contact?.email && !contact?.phone) return null;
  return (
    <div className="grid grid-cols-[108px_minmax(0,1fr)] gap-2 border-b border-white/[0.08] py-2 last:border-b-0">
      <span className="text-[10px] font-medium text-[#aaaaaa]">Abuse Contact</span>
      <span className="flex flex-col gap-0.5 text-[11px] font-semibold leading-5">
        {contact.email && <a href={`mailto:${contact.email}`} className="break-all text-[#ba9cff] hover:underline">{contact.email}</a>}
        {contact.phone && <a href={`tel:${String(contact.phone).replace(/[^+\d]/g, '')}`} className="break-all text-[#ba9cff] hover:underline">{contact.phone}</a>}
      </span>
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
  const durationValue = Number(result.scanDurationSeconds);
  const hasDuration = result.scanDurationSeconds !== null && result.scanDurationSeconds !== undefined && Number.isFinite(durationValue);
  const duration = result.scanning ? 'Live' : hasDuration ? `${durationValue.toFixed(1)}s` : '—';
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
            {result.fallbackNote && <Pill tone="warning"><Info className="h-3 w-3" />{result.fallbackNote}</Pill>}
          </div>
        </div>
      </div>

      {(result.scanning || result.scanMessage) && (
        <div className="mt-4 flex items-center gap-3 rounded-xl border border-[#ba9cff]/30 bg-[linear-gradient(180deg,rgba(186,156,255,.16),rgba(58,27,87,.10))] px-4 py-3 text-[#ded4e9]">
          {result.scanning ? <Activity className="h-4 w-4 shrink-0 animate-pulse text-[#ba9cff]" /> : <Info className="h-4 w-4 shrink-0 text-[#ba9cff]" />}
          <p className="text-[12px] leading-5">{result.scanning ? result.scanMessage || 'GeoIP lookup is running...' : result.scanMessage}</p>
        </div>
      )}

      <div className="mt-4 grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-6">
        <StatCard icon={Globe2} label="IP Address" value={result.resolvedIp} subtext={result.ipType} />
        <StatCard icon={Network} label="ASN" value={result.asn} subtext={result.organization} />
        <StatCard icon={Radio} label="ISP" value={result.isp} />
        <StatCard icon={Building2} label="Organization" value={result.organization} />
        <StatCard icon={MapPin} label="IP Type" value={result.proxyOrCdn ? 'Proxy/CDN' : result.ipType} subtext={result.security.cdnProvider} />
        <StatCard
          icon={ShieldCheck}
          label="Confidence Score"
          value={result.confidenceScore === null || result.confidenceScore === undefined || result.confidenceScore === '' ? 'Not available' : result.confidenceScore}
        >
          {confidence !== null && (
            <div className="mt-2 h-1 rounded-full bg-white/[0.18]">
              <div className="h-full rounded-full bg-[#7CFF9A]" style={{ width: `${confidence}%` }} />
            </div>
          )}
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
          <AbuseContactRow contact={result.abuseContact} />
        </InfoCard>
        <InfoCard title="Security Information">
          <InfoRow label="CDN" value={boolText(security.cdn)} />
          <InfoRow label="CDN Provider" value={security.cdnProvider} />
          <InfoRow label="Proxy" value={boolText(security.proxy)} />
          <InfoRow label="Hosting" value={boolText(security.hosting)} />
          <InfoRow label="VPN" value={boolText(security.vpn)} />
          <InfoRow label="Tor" value={boolText(security.tor)} />
          <InfoRow label="Confidence" value={security.confidence} />
          <InfoRow label="IP Type Basis" value={security.ipTypeBasis} />
          <InfoRow label="Location Accuracy" value={security.locationAccuracy} />
          <InfoRow label="Accuracy Radius" value={security.accuracyRadiusKm != null ? `${security.accuracyRadiusKm} km` : null} />
          <InfoRow label="Accuracy Basis" value={security.accuracyBasis} />
          <InfoRow label="Anycast" value={result.anycast?.likely === true ? `Likely (${result.anycast.basis})` : result.anycast?.likely === false ? 'No' : null} />
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
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Building2} label="Provider" value={fallback(result.provider.name).toUpperCase()} />
        <StatCard icon={Database} label="Cached" value={boolText(result.provider.cached)} />
        <StatCard icon={Timer} label="Fetched" value={result.freshness?.fetched_at ? new Date(result.freshness.fetched_at).toLocaleString() : null} />
        <StatCard icon={Network} label="Consensus" value={result.consensus?.agreement ? result.consensus.agreement.toUpperCase() : null} subtext={result.consensus?.max_distance_km != null ? `${result.consensus.max_distance_km} km spread` : null} />
      </div>
      {result.consensus?.providers?.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {result.consensus.providers.map((provider) => (
            <Pill key={`${provider.name}-${provider.latency_ms}`} tone="info">
              {fallback(provider.name)} {provider.latency_ms != null ? `${provider.latency_ms} ms` : ''}
            </Pill>
          ))}
        </div>
      )}
      {result.warnings.length > 0 && (
        <div className="mt-3 rounded-xl border border-[#76552a]/45 bg-[#46351e]/40 p-3 text-[11px] text-[#ffd38a]">
          <div className="mb-1 font-semibold uppercase tracking-wider">Source warnings</div>
          {result.warnings.map((warning, index) => (
            <div key={`${warning.source}-${index}`}>{warning.source}: {warning.message}</div>
          ))}
        </div>
      )}
    </SectionCard>
  );
}

const sanitizeCsvCell = (value) => {
  const text = String(value ?? '');
  return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
};

const csvEscape = (value) => `"${sanitizeCsvCell(value).replaceAll('"', '""')}"`;

const CSV_COLUMNS = [
  'record_type',
  'ip',
  'family',
  'country',
  'country_code',
  'flag_emoji',
  'region',
  'city',
  'postal',
  'latitude',
  'longitude',
  'timezone',
  'utc_offset',
  'asn',
  'org',
  'isp',
  'asn_domain',
  'calling_code',
  'is_cdn',
  'cdn_provider',
  'is_proxy',
  'is_hosting',
  'is_vpn',
  'is_tor',
  'confidence',
  'location_accuracy',
  'scan_duration_seconds',
  'provider',
  'cached',
  'reverse_dns',
  'abuse_email',
  'abuse_phone',
  'error',
];

const toCsv = (result) => {
  const summary = {
    record_type: 'summary',
    ip: result.resolvedIp,
    country: result.location.country,
    country_code: result.location.countryCode,
    flag_emoji: result.location.flagEmoji,
    region: result.location.region,
    city: result.location.city,
    postal: result.location.postalCode,
    latitude: result.location.latitude,
    longitude: result.location.longitude,
    timezone: result.location.timezone,
    utc_offset: result.location.utcOffset,
    asn: result.network.asn,
    org: result.network.organization,
    isp: result.network.isp,
    asn_domain: result.network.asnDomain,
    calling_code: result.network.callingCode,
    is_cdn: result.security.cdn,
    cdn_provider: result.security.cdnProvider,
    is_proxy: result.security.proxy,
    is_hosting: result.security.hosting,
    is_vpn: result.security.vpn,
    is_tor: result.security.tor,
    confidence: result.security.confidence,
    location_accuracy: result.security.locationAccuracy,
    scan_duration_seconds: result.scanDurationSeconds,
    provider: result.provider.name,
    cached: result.provider.cached,
    reverse_dns: Array.isArray(result.dns.reverseDns) ? result.dns.reverseDns.join('; ') : result.dns.reverseDns,
    abuse_email: result.abuseContact?.email,
    abuse_phone: result.abuseContact?.phone,
  };
  const rows = result.resolvedIps.map((ip) => ({
    record_type: 'ip',
    ip: ip.ip,
    family: ip.type,
    country: ip.country,
    country_code: ip.countryCode,
    flag_emoji: ip.flagEmoji,
    region: ip.region,
    city: ip.city,
    latitude: ip.latitude,
    longitude: ip.longitude,
    asn: ip.asn,
    org: ip.org,
    isp: ip.isp,
    is_cdn: ip.edgeCdn,
    cdn_provider: ip.cdnProvider,
    provider: ip.provider,
    reverse_dns: Array.isArray(ip.reverseDns) ? ip.reverseDns.join('; ') : ip.reverseDns,
    error: ip.error,
  }));
  return [summary, ...rows]
    .map((row) => CSV_COLUMNS.map((column) => csvEscape(row[column])).join(','))
    .reduce((lines, row) => `${lines}\n${row}`, CSV_COLUMNS.map(csvEscape).join(','));
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
