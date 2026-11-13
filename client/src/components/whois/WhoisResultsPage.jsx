import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Calendar,
  Check,
  CheckCircle2,
  CircleDot,
  Clock3,
  Copy,
  ExternalLink,
  Globe2,
  Info,
  Lock,
  Shield,
  X,
} from 'lucide-react';

const EMPTY = 'Unknown';

const fallback = (value, empty = EMPTY) => (
  value === null || value === undefined || value === '' ? empty : String(value)
);

const asArray = (value) => {
  if (!value) return [];
  return Array.isArray(value) ? value.filter(Boolean) : [value];
};

const yesNo = (value) => {
  if (value === true) return 'Yes';
  if (value === false) return 'No';
  return EMPTY;
};

const cleanStatus = (status) => String(status || '')
  .replace(/^.*?#/, '')
  .replace(/\s+https?:\/\/\S+/g, '')
  .trim();

const urlFromText = (value) => String(value || '').match(/https?:\/\/\S+/)?.[0]?.replace(/[),.]+$/, '');

const dateValue = (value, withTime = false) => {
  if (!value) return EMPTY;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, withTime
    ? { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }
    : { month: 'short', day: 'numeric', year: 'numeric' }).format(parsed);
};

const valueText = (value) => {
  if (value === null || value === undefined || value === '') return EMPTY;
  if (typeof value === 'boolean') return yesNo(value);
  if (Array.isArray(value)) return value.length ? value.join(', ') : EMPTY;
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
};

const privacyText = (value) => /privacy|redact|withheld|protected|gdpr/i.test(valueText(value));

const contactRedacted = (contact, privacyProtected) => {
  if (privacyProtected) return true;
  if (!contact) return false;
  return privacyText(Object.values(contact).join(' '));
};

const expiryLabel = (expiryStatus, daysUntilExpiry) => {
  if (String(expiryStatus || '').toLowerCase() === 'expired') return 'Critical';
  if (typeof daysUntilExpiry === 'number' && daysUntilExpiry <= 30) return 'Critical';
  if (typeof daysUntilExpiry === 'number' && daysUntilExpiry <= 90) return 'Warning';
  return 'Healthy';
};

const hasTransferLock = (statuses) => statuses.some((status) => status.toLowerCase().includes('transferprohibited'));

const computeHealth = (data) => {
  let score = 100;
  if (data.registration.available !== false) score -= 24;
  if (data.registration.expiryStatus === 'Critical') score -= 28;
  if (data.registration.expiryStatus === 'Warning') score -= 12;
  if (!data.registration.protected) score -= 8;
  if (!hasTransferLock(data.statuses)) score -= 8;
  score -= data.riskIndicators.filter((risk) => risk.severity === 'high').length * 18;
  score -= data.riskIndicators.filter((risk) => ['medium', 'warning'].includes(risk.severity)).length * 10;
  score = Math.max(0, Math.min(100, Math.round(score)));
  const label = score >= 75 ? 'Good' : score >= 30 ? 'Fair' : 'Poor';
  return {
    score,
    label,
    summary: score >= 75 ? 'Registration posture looks stable from available WHOIS/RDAP signals.' : 'Review registration signals before trusting this domain.',
    checks: [
      { label: 'Valid registration', passed: data.registration.available === false },
      { label: 'Domain is active', passed: data.registration.available === false },
      { label: 'Not expired', passed: data.registration.expiryStatus !== 'Critical' },
      { label: 'Transfer lock is enabled', passed: hasTransferLock(data.statuses) },
      { label: 'Privacy protection is enabled', passed: data.registration.protected === true },
    ],
  };
};

const computeRisk = (data) => {
  const hasHigh = data.riskIndicators.some((risk) => risk.severity === 'high');
  const hasMedium = data.riskIndicators.some((risk) => ['medium', 'warning'].includes(risk.severity));
  const level = hasHigh ? 'High Risk' : hasMedium ? 'Medium Risk' : 'Low Risk';
  const checks = data.riskIndicators.length
    ? data.riskIndicators.map((risk) => ({ label: risk.label || risk.id, passed: !['high', 'medium', 'warning'].includes(risk.severity) }))
    : [
      { label: 'Privacy protection enabled or no personal contact exposure detected', passed: true },
      { label: 'No suspicious domain status returned', passed: true },
      { label: 'Transfer lock is enabled', passed: hasTransferLock(data.statuses) },
      { label: 'Domain expiry is not imminent', passed: data.registration.expiryStatus === 'Healthy' },
      { label: 'Domain active and registration data retrieved', passed: data.registration.available === false },
    ];
  return {
    level,
    summary: level === 'Low Risk' ? 'No significant WHOIS risk indicators were returned.' : 'Review the returned WHOIS indicators before trusting this domain.',
    checks,
  };
};

const normalizeWhoisResult = (raw = {}) => {
  const domain = raw.domain || raw.target;
  const statuses = asArray(raw.status).map(cleanStatus).filter(Boolean);
  const statusExplanations = asArray(raw.status_explanations);
  const riskIndicators = asArray(raw.risk_indicators);
  const nameservers = asArray(raw.name_servers);
  const emails = asArray(raw.emails);
  const relatedData = [
    raw.historical_whois && { available: Boolean(raw.historical_whois.available), reason: raw.historical_whois.reason },
    raw.related_domains && { available: Boolean(raw.related_domains.available), reason: raw.related_domains.reason },
  ].filter(Boolean);
  const registration = {
    domain,
    available: raw.available,
    creationDate: raw.creation_date,
    updatedDate: raw.updated_date,
    expirationDate: raw.expiration_date,
    domainAgeDays: raw.domain_age_days,
    daysUntilExpiry: raw.days_until_expiry,
    expiryStatus: expiryLabel(raw.expiry_status, raw.days_until_expiry),
    protected: Boolean(raw.privacy_protected),
  };
  const data = {
    target: raw.target || domain,
    status: raw.scanning ? 'running' : raw.error ? 'failed' : 'completed',
    scanning: Boolean(raw.scanning),
    scanDurationSeconds: raw.scan_duration_seconds,
    retrievedAt: raw.retrievedAt || raw.retrieved_at || new Date().toISOString(),
    aiSummary: raw.scan_message || raw.summary,
    timeline: {
      domainAgeDays: raw.domain_age_days,
      registeredSince: raw.creation_date,
      updatedDate: raw.updated_date,
      expiresDate: raw.expiration_date,
      daysUntilExpiry: raw.days_until_expiry,
    },
    registrar: {
      name: raw.registrar,
      url: raw.registrar_url,
      registry: raw.registry,
      ianaId: raw.registrar_iana_id,
      abuseEmail: raw.registrar_abuse_email || emails[0],
      abusePhone: raw.registrar_abuse_phone,
    },
    registration,
    statusInfo: {
      domainStatus: statuses[0],
      domainStatusUrl: urlFromText(asArray(raw.status)[0]),
      dnssec: raw.dnssec,
      statusExplanation: statusExplanations[0]?.meaning || statusExplanations[0]?.description,
    },
    contactInfo: {
      registrantOrganization: raw.registrant_org,
      registrantCountry: raw.registrant_country,
      registrantEmail: emails[0],
      adminContactRedacted: contactRedacted(raw.admin_contact, raw.privacy_protected),
      techContactRedacted: contactRedacted(raw.tech_contact, raw.privacy_protected),
      adminContact: raw.admin_contact,
      techContact: raw.tech_contact,
    },
    serverNames: {
      nameservers,
      totalServers: nameservers.length,
    },
    rdap: {
      available: Boolean(raw.rdap_available),
      error: raw.normalized?.rdap_error,
      ianaTld: raw.iana?.tld || raw.tld,
      registry: raw.iana?.registry || raw.registry,
    },
    relatedData,
    rawRecord: raw.raw_text,
    termsUrl: raw.termsUrl || raw.terms_url,
    termsSummary: raw.termsSummary || raw.terms_summary,
    statuses,
    riskIndicators,
    cached: raw.cached,
    raw,
  };
  data.healthScore = computeHealth(data);
  data.riskOverview = computeRisk(data);
  return data;
};

function SectionCard({ children, className = '' }) {
  return <section className={`rounded-xl border border-white/[0.14] bg-[#201330]/82 p-5 shadow-[0_18px_60px_rgba(0,0,0,0.18)] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)] ${className}`}>{children}</section>;
}

function SectionHeading({ children }) {
  return <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold uppercase tracking-wider text-[#ba9cff]"><CircleDot className="h-3.5 w-3.5" />{children}</div>;
}

function DataRow({ label, value, tone = 'neutral', href, badge }) {
  const text = valueText(value);
  const toneClass = tone === 'danger' ? 'text-[#FF4D4D]' : tone === 'success' ? 'text-[#7CFF9A]' : 'text-white';
  return (
    <div className="grid grid-cols-[128px_minmax(0,1fr)] gap-3 border-b border-white/[0.08] py-2 last:border-b-0">
      <span className="text-[11px] font-medium text-[#aaaaaa]">{label}</span>
      <span className={`min-w-0 text-[12px] font-semibold leading-5 break-words ${toneClass}`}>
        {href && text !== EMPTY ? (
          <a className="inline-flex items-center gap-1 text-[#ba9cff] hover:text-white" href={href} target="_blank" rel="noopener noreferrer">{text}<ExternalLink className="h-3 w-3" /></a>
        ) : text}
        {badge}
      </span>
    </div>
  );
}

function PrivacyBadge() {
  return <span className="ml-2 inline-flex h-5 items-center gap-1 rounded-full bg-[rgba(253,192,120,0.2)] px-2 text-[9px] font-semibold uppercase tracking-wide text-[#F97316]"><Lock className="h-3 w-3" />Privacy Prohibited</span>;
}

function TimelinePoint({ icon: Icon, label, value, sub }) {
  return (
    <div className="relative z-10 flex min-w-0 flex-1 flex-col items-center text-center">
      <span className="grid h-10 w-10 place-items-center rounded-full border border-[#ba9cff]/45 bg-[#190f23] text-[#ba9cff] transition hover:shadow-[0_0_18px_rgba(186,156,255,0.55)]"><Icon className="h-4 w-4" /></span>
      <span className="mt-2 text-[11px] font-medium text-[#aaaaaa]">{label}</span>
      <strong className="mt-0.5 text-[15px] font-semibold text-white">{valueText(value)}</strong>
      {sub && <small className="mt-0.5 text-[10px] text-[#8f839b]">{sub}</small>}
    </div>
  );
}

export function DomainTimeline({ result }) {
  const { timeline, registration } = result;
  return (
    <SectionCard>
      <SectionHeading>Domain Timeline</SectionHeading>
      <div className="relative px-4 pb-4 pt-2">
        <div className="absolute left-10 right-10 top-[30px] h-px bg-white/[0.14]" />
        <div className="grid grid-cols-4 gap-4">
          <TimelinePoint icon={Globe2} label="Domain Age" value={typeof timeline.domainAgeDays === 'number' ? `${timeline.domainAgeDays} days` : EMPTY} sub={timeline.registeredSince ? `Since ${dateValue(timeline.registeredSince)}` : null} />
          <TimelinePoint icon={Calendar} label="Updated" value={dateValue(timeline.updatedDate)} />
          <TimelinePoint icon={Clock3} label="Expires" value={dateValue(timeline.expiresDate)} />
          <TimelinePoint icon={Calendar} label="Until Expiry" value={typeof timeline.daysUntilExpiry === 'number' ? `${timeline.daysUntilExpiry} days` : EMPTY} />
        </div>
      </div>
      <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
        <StatusCard icon={Globe2} label="Status" value={registration.available === false ? 'Registered' : registration.available === true ? 'Available' : 'Unknown'} note={registration.expiryStatus} tone={registration.expiryStatus === 'Healthy' ? 'success' : 'danger'} />
        <StatusCard icon={Shield} label="Privacy" value={registration.protected ? 'Protected' : 'Visible'} note={registration.protected ? 'Contact privacy detected' : 'No privacy marker returned'} tone={registration.protected ? 'success' : 'neutral'} />
        <StatusCard icon={Lock} label="Transfer Lock" value={hasTransferLock(result.statuses) ? 'Enabled' : 'Unknown'} note={result.statuses[0] || 'No status code'} tone={hasTransferLock(result.statuses) ? 'success' : 'neutral'} />
      </div>
    </SectionCard>
  );
}

function StatusCard({ icon: Icon, label, value, note, tone }) {
  return (
    <article className="rounded-[10px] border border-white/[0.14] bg-[#190f23]/78 p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
      <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-[#ba9cff]"><Icon className="h-3.5 w-3.5" />{label}</div>
      <strong className={`text-[18px] font-semibold ${tone === 'success' ? 'text-[#7CFF9A]' : tone === 'danger' ? 'text-[#FF4D4D]' : 'text-white'}`}>{valueText(value)}</strong>
      <p className="mt-1 text-[11px] leading-4 text-[#aaaaaa]">{valueText(note)}</p>
    </article>
  );
}

export function RegistrarInfoCard({ result }) {
  return (
    <InfoCard title="Registrar Information">
      <DataRow label="Registrar" value={result.registrar.name} />
      <DataRow label="Registrar URL" value={result.registrar.url} href={result.registrar.url} />
      <DataRow label="Registry" value={result.registrar.registry} />
      <DataRow label="IANA ID" value={result.registrar.ianaId} />
      <DataRow label="Abuse Email" value={result.registrar.abuseEmail} href={result.registrar.abuseEmail ? `mailto:${result.registrar.abuseEmail}` : null} />
      <DataRow label="Abuse Phone" value={result.registrar.abusePhone} />
    </InfoCard>
  );
}

export function RegistrationInfoCard({ result }) {
  const availableTone = result.registration.available === false ? 'danger' : result.registration.available === true ? 'success' : 'neutral';
  return (
    <InfoCard title="Registration Information">
      <DataRow label="Domain" value={result.registration.domain} />
      <DataRow label="Available" value={yesNo(result.registration.available)} tone={availableTone} />
      <DataRow label="Creation Date" value={dateValue(result.registration.creationDate)} />
      <DataRow label="Updated Date" value={dateValue(result.registration.updatedDate)} />
      <DataRow label="Expiration Date" value={dateValue(result.registration.expirationDate)} />
      <DataRow label="Domain Age" value={typeof result.registration.domainAgeDays === 'number' ? `${result.registration.domainAgeDays} days` : null} />
      <DataRow label="Days Until Expiry" value={typeof result.registration.daysUntilExpiry === 'number' ? `${result.registration.daysUntilExpiry} days` : null} />
      <DataRow label="Expiry Status" value={result.registration.expiryStatus} tone={result.registration.expiryStatus === 'Healthy' ? 'success' : 'danger'} />
      <DataRow label="Protected" value={yesNo(result.registration.protected)} />
    </InfoCard>
  );
}

function InfoCard({ title, children }) {
  return (
    <article className="rounded-xl border border-white/[0.14] bg-[#190f23]/78 p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">
      <SectionHeading>{title}</SectionHeading>
      {children}
    </article>
  );
}

export function DomainHealthScoreCard({ result }) {
  const { score, label, summary, checks } = result.healthScore;
  const [displayScore, setDisplayScore] = useState(result.scanning ? 0 : score);
  const prevScanning = useRef(result.scanning);

  useEffect(() => {
    if (!result.scanning && prevScanning.current) {
      setDisplayScore(0);
      const start = performance.now();
      const duration = 800;
      const animate = (now) => {
        const t = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - t, 3);
        setDisplayScore(Math.round(eased * score));
        if (t < 1) requestAnimationFrame(animate);
      };
      requestAnimationFrame(animate);
    }
    prevScanning.current = result.scanning;
  }, [result.scanning, score]);

  const radius = 48;
  const circumference = 2 * Math.PI * radius;
  const dash = (displayScore / 100) * circumference;
  const barColor = score >= 75 ? '#7CFF9A' : score >= 30 ? '#F97316' : '#FF4D4D';
  return (
    <SectionCard>
      <SectionHeading>Domain Health Score</SectionHeading>
      <div className="flex flex-col items-start">
        <svg width="132" height="132" viewBox="0 0 132 132" role="img" aria-label={`Health score ${displayScore} out of 100`} className="self-center">
          <circle cx="66" cy="66" r={radius} fill="none" stroke="rgba(255,255,255,.12)" strokeWidth="12" />
          <circle cx="66" cy="66" r={radius} fill="none" stroke={barColor} strokeWidth="12" strokeLinecap="round" strokeDasharray={`${dash} ${circumference - dash}`} transform="rotate(-90 66 66)" />
          <text x="66" y="65" textAnchor="middle" fill="#fff" fontSize="27" fontWeight="700">{displayScore}</text>
          <text x="66" y="83" textAnchor="middle" fill="#aaa" fontSize="13">/100</text>
        </svg>
        <strong className="mt-2 text-[28px] font-bold" style={{ color: barColor }}>{label}</strong>
        <p className="mt-1 text-left text-[12px] leading-5 text-[#aaaaaa]">{summary}</p>
      </div>
      <Checklist items={checks} />
    </SectionCard>
  );
}

export function RiskOverviewCard({ result }) {
  const { level, summary, checks } = result.riskOverview;
  const tone = level === 'High Risk' ? 'text-[#FF4D4D]' : level === 'Medium Risk' ? 'text-[#F97316]' : 'text-[#7CFF9A]';
  const icon = level === 'High Risk' ? '/assets/risk score whois red.png' : level === 'Medium Risk' ? '/assets/risk score whois orange.png' : '/assets/risk score whois.png';
  return (
    <SectionCard>
      <SectionHeading>Risk Overview</SectionHeading>
      <div className="flex flex-col items-start">
        <img src={icon} alt={`${level} icon`} className="h-[132px] w-[132px] self-center" />
        <strong className={`mt-2 text-[28px] font-bold ${tone}`}>{level}</strong>
        <p className="mt-1 text-left text-[12px] leading-5 text-[#aaaaaa]">{summary}</p>
      </div>
      <Checklist items={checks} />
    </SectionCard>
  );
}

function Checklist({ items }) {
  return (
    <div className="mt-4 space-y-2">
      {items.map((item) => (
        <div key={item.label} className="flex items-center gap-2 text-[12px] text-[#ded4e9]">
          {item.passed ? <Check className="h-4 w-4 shrink-0 text-[#7CFF9A]" /> : <X className="h-4 w-4 shrink-0 text-[#FF4D4D]" />}
          <span>{item.label}</span>
        </div>
      ))}
    </div>
  );
}

export function StatusInfoCard({ result }) {
  return (
    <InfoCard title="Status Information">
      <DataRow label="Domain Status" value={result.statusInfo.domainStatus} href={result.statusInfo.domainStatusUrl} />
      <DataRow label="DNSSEC" value={result.statusInfo.dnssec} />
      <p className="mt-3 text-[12px] leading-5 text-[#aaaaaa]">{fallback(result.statusInfo.statusExplanation, 'No registry status explanation was returned.')}</p>
    </InfoCard>
  );
}

export function ContactInfoCard({ result }) {
  const { contactInfo } = result;
  return (
    <InfoCard title="Contact Information">
      <DataRow label="Registrant Org" value={contactInfo.registrantOrganization} />
      <DataRow label="Registrant Country" value={contactInfo.registrantCountry} />
      <DataRow label="Registrant Email" value={contactInfo.registrantEmail} href={contactInfo.registrantEmail ? `mailto:${contactInfo.registrantEmail}` : null} />
      <DataRow label="Admin Contact" value={contactInfo.adminContactRedacted ? 'Redacted' : contactInfo.adminContact?.name || contactInfo.adminContact?.organization || contactInfo.adminContact?.email} badge={contactInfo.adminContactRedacted ? <PrivacyBadge /> : null} />
      <DataRow label="Tech Contact" value={contactInfo.techContactRedacted ? 'Redacted' : contactInfo.techContact?.name || contactInfo.techContact?.organization || contactInfo.techContact?.email} badge={contactInfo.techContactRedacted ? <PrivacyBadge /> : null} />
    </InfoCard>
  );
}

export function ServerNamesCard({ result }) {
  const servers = result.serverNames.nameservers;
  return (
    <InfoCard title="Server Names">
      {(servers.length ? servers : [EMPTY]).map((server) => (
        <div key={server} className="flex items-center gap-2 border-b border-white/[0.08] py-2 text-[12px] font-semibold text-white last:border-b-0">
          {server !== EMPTY && <CheckCircle2 className="h-4 w-4 shrink-0 text-[#7CFF9A]" />}
          <span className="break-all">{server}</span>
        </div>
      ))}
      <DataRow label="Total Servers" value={result.serverNames.totalServers || null} />
    </InfoCard>
  );
}

export function RdapInfoCard({ result }) {
  return (
    <InfoCard title="RDAP/IANA Information">
      <DataRow label="RDAP Available" value={yesNo(result.rdap.available)} tone={result.rdap.available ? 'success' : 'danger'} />
      <DataRow label="RDAP Error" value={result.rdap.error} />
      <DataRow label="IANA TLD" value={result.rdap.ianaTld} />
      <DataRow label="Registry" value={result.rdap.registry} />
    </InfoCard>
  );
}

export function RelatedDataCard({ result }) {
  return (
    <InfoCard title="Related Data">
      {(result.relatedData.length ? result.relatedData : [{ available: false, reason: 'No related data provider returned enrichment for this lookup.' }]).map((item, index) => (
        <div key={`${item.reason}-${index}`} className="border-b border-white/[0.08] py-2 last:border-b-0">
          <DataRow label="Available" value={yesNo(item.available)} tone={item.available ? 'success' : 'danger'} />
          <p className="mt-1 text-[12px] leading-5 text-[#aaaaaa]">Reason: {fallback(item.reason)}</p>
        </div>
      ))}
    </InfoCard>
  );
}

const formattedRows = (result) => [
  ['Domain Name', result.registration.domain],
  ['Registrar URL', result.registrar.url],
  ['Updated Date', result.registration.updatedDate],
  ['Creation Date', result.registration.creationDate],
  ['Expiry Date', result.registration.expirationDate],
  ['Registrar', result.registrar.name],
  ['IANA ID', result.registrar.ianaId],
  ['Abuse Contact Email', result.registrar.abuseEmail],
  ['Abuse Contact Phone', result.registrar.abusePhone],
  ['Domain Status', result.statuses.join(', ')],
  ...result.serverNames.nameservers.map((server, index) => [`Name Server ${index + 1}`, server]),
  ['DNSSEC', result.statusInfo.dnssec],
];

export function RawWhoisRecordPanel({ result, copied, onCopy }) {
  const [mode, setMode] = useState('formatted');
  const hasRaw = Boolean(result.rawRecord);
  const rows = formattedRows(result);
  return (
    <SectionCard>
      <div className="mb-3 flex items-center justify-between gap-3">
        <SectionHeading>Raw WHOIS Record</SectionHeading>
        <div className="flex rounded-full border border-white/[0.14] bg-[#190f23] p-1">
          {['formatted', 'raw'].map((item) => (
            <button key={item} type="button" onClick={() => setMode(item)} className={`h-7 rounded-full px-3 text-[11px] font-semibold transition ${mode === item ? 'bg-[#ba9cff] text-[#190f23]' : 'text-[#ded4e9] hover:text-white'}`}>
              {item === 'formatted' ? 'Formatted' : 'Raw Text'}
            </button>
          ))}
        </div>
      </div>
      <div className="max-h-[330px] overflow-auto rounded-xl border border-white/[0.08] bg-[#201330] p-4 font-mono text-[11px] leading-5">
        {mode === 'raw' ? (
          hasRaw ? <pre className="whitespace-pre-wrap text-[#aaaaaa]">{result.rawRecord}</pre> : <p className="text-[#aaaaaa]">Raw WHOIS text was not returned by the endpoint.</p>
        ) : (
          <div className="space-y-1">
            {rows.map(([label, value]) => (
              <div key={label} className="grid grid-cols-[190px_minmax(0,1fr)] gap-3">
                <span className="font-bold text-[#F97316]">{label}:</span>
                <span className="break-words text-[#aaaaaa]">{valueText(value)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="mt-3 flex items-center justify-between gap-3 rounded-xl border border-white/[0.08] bg-[#190f23]/80 p-3">
        <div className="flex min-w-0 items-start gap-2">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-[#ba9cff]" />
          <p className="text-[11px] leading-5 text-[#aaaaaa]">{fallback(result.termsSummary, 'WHOIS data is provided by registries and registrars and may be subject to their terms of use.')}</p>
        </div>
        <div className="flex shrink-0 gap-2">
          <button type="button" onClick={() => onCopy('whois-json', JSON.stringify(result.raw, null, 2))} className="inline-flex h-8 items-center gap-1.5 rounded-full border border-white/[0.14] px-3 text-[11px] text-[#ded4e9] hover:border-[#ba9cff]"><Copy className="h-3 w-3" />{copied === 'whois-json' ? 'Copied' : 'Copy JSON'}</button>
          {result.termsUrl && <a href={result.termsUrl} target="_blank" rel="noopener noreferrer" className="inline-flex h-8 items-center gap-1.5 rounded-full bg-white px-3 text-[11px] font-semibold text-[#190f23]">View Full Terms <ExternalLink className="h-3 w-3" /></a>}
        </div>
      </div>
    </SectionCard>
  );
}

export function WhoisSummaryHero({ result }) {
  return (
    <SectionCard>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-[22px] font-semibold leading-tight text-white">{fallback(result.registration.domain || result.target, 'WHOIS lookup')}</h2>
          <div className="mt-2 flex flex-wrap gap-2">
            <Pill tone={result.scanning ? 'neutral' : 'success'}>{result.scanning ? <Clock3 className="h-3 w-3 animate-pulse" /> : <Check className="h-3 w-3" />}{result.scanning ? 'WHOIS Running' : 'WHOIS Retrieved'}</Pill>
            <Pill><Clock3 className="h-3 w-3" />{result.cached ? 'Cached' : 'Fresh'}</Pill>
            <Pill><Calendar className="h-3 w-3" />{dateValue(result.retrievedAt, true)}</Pill>
          </div>
        </div>
      </div>
      {(result.aiSummary || result.scanning) && (
        <div className="mt-4 flex items-center gap-3 rounded-xl border border-[#ba9cff]/30 bg-[linear-gradient(180deg,rgba(186,156,255,.16),rgba(58,27,87,.10))] px-4 py-3 text-[#ded4e9]">
          <Info className="h-4 w-4 shrink-0 text-[#ba9cff]" />
          <p className="text-[12px] leading-5">{fallback(result.aiSummary, 'WHOIS lookup is running...')}</p>
        </div>
      )}
    </SectionCard>
  );
}

function Pill({ children, tone = 'neutral' }) {
  const toneClass = tone === 'success' ? 'border-[#7CFF9A]/45 bg-[#132718] text-[#7CFF9A]' : 'border-white/[0.14] bg-[#190f23]/85 text-[#d8cfea]';
  return <span className={`inline-flex h-[26px] items-center gap-1.5 rounded-full border px-2.5 text-[10px] font-medium ${toneClass}`}>{children}</span>;
}

export default function WhoisResultsPage({ result: rawResult, copied, onCopy }) {
  const result = useMemo(() => normalizeWhoisResult(rawResult), [rawResult]);
  if (!rawResult) {
    return         <div className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-8 text-center text-sm text-[#aaaaaa] transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]">Run a WHOIS lookup to see the result dashboard.</div>;
  }
  return (
    <div className="space-y-4 p-1 md:p-2">
      <WhoisSummaryHero result={result} />
      <DomainTimeline result={result} />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <RegistrarInfoCard result={result} />
        <RegistrationInfoCard result={result} />
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <DomainHealthScoreCard result={result} />
        <RiskOverviewCard result={result} />
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <StatusInfoCard result={result} />
        <ContactInfoCard result={result} />
        <ServerNamesCard result={result} />
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <RdapInfoCard result={result} />
        <RelatedDataCard result={result} />
      </div>
      <RawWhoisRecordPanel result={result} copied={copied} onCopy={onCopy} />
    </div>
  );
}
