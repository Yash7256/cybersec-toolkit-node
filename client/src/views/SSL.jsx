import { useState } from 'react';
import { apiPost } from '../utils/apiClient';
import { useGetToken } from '../utils/useGetToken';
import { downloadFile, exportBrandedPdf, shareOrCopy, rowsToCsv } from '../utils/exportUtils';
import {
  ArrowRight,
  Building2,
  CheckCircle2,
  CircleDot,
  Download,
  ExternalLink,
  FileJson,
  FileText,
  Globe2,
  Hash,
  Lock,
  Share2,
  ShieldAlert,
  Wifi,
  X,
  XCircle,
} from 'lucide-react';

/* ─── helpers ────────────────────────────────────────────────────── */
const fmt = (v, fallback = '—') =>
  v === null || v === undefined || v === '' ? fallback : String(v);

const fmtDate = (iso) => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
};

/* ─── small atoms ────────────────────────────────────────────────── */
function Chip({ label, tone = 'neutral' }) {
  const map = {
    good:    'bg-[rgba(124,255,154,0.12)] text-[#7CFF9A] border-[rgba(124,255,154,0.3)]',
    warn:    'bg-[rgba(249,115,22,0.12)] text-[#F97316] border-[rgba(249,115,22,0.3)]',
    bad:     'bg-[rgba(255,77,77,0.12)] text-[#FF4D4D] border-[rgba(255,77,77,0.3)]',
    info:    'bg-[rgba(34,211,238,0.12)] text-[#22d3ee] border-[rgba(34,211,238,0.3)]',
    neutral: 'bg-[rgba(167,139,250,0.1)] text-[#c4b5fd] border-[rgba(167,139,250,0.26)]',
  };
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-[10px] font-mono font-semibold uppercase tracking-wide ${map[tone] || map.neutral}`}>
      {label}
    </span>
  );
}

function SSLRow({ label, value, tone = 'neutral' }) {
  const toneClass = tone === 'good' ? 'text-[#7CFF9A]' : tone === 'bad' ? 'text-[#FF4D4D]' : tone === 'warn' ? 'text-[#F97316]' : 'text-[#ded4e9]';
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] gap-4 border-b border-white/[0.1] py-2 last:border-b-0">
      <span className="text-[10px] text-[#8e819b]">{label}</span>
      <span className={`max-w-[210px] break-words text-right text-[10px] font-semibold ${toneClass}`}>{fmt(value, 'Unknown')}</span>
    </div>
  );
}

function SSLCard({ title, children, className = '' }) {
  return (
    <section className={`rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 p-5 ${className}`}>
      <div className="mb-4 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-[#b895ff]">
        <CircleDot className="h-3.5 w-3.5" />
        <span>{title}</span>
      </div>
      {children}
    </section>
  );
}

function SSLMetric({ icon: Icon, label, value, subtext }) {
  return (
    <div className="min-h-[116px] rounded-[10px] border border-white/[0.22] bg-[#160d24]/80 p-4">
      <div className="flex items-center gap-2 text-[10px] font-bold text-white">
        <Icon className="h-4 w-4 shrink-0" />
        <span>{label}</span>
      </div>
      <div className="mt-5 text-[17px] font-semibold leading-tight text-white">{fmt(value)}</div>
      <div className="mt-2 text-[9px] font-medium text-[#8e819b]">{fmt(subtext, '')}</div>
    </div>
  );
}

function SSLProtocolCard({ label, status, tone, note }) {
  const Icon = tone === 'good' ? CheckCircle2 : tone === 'bad' ? XCircle : ShieldAlert;
  const color = tone === 'good' ? '#7CFF9A' : tone === 'bad' ? '#FF4D4D' : '#aaaaaa';
  return (
    <div className="rounded-[10px] border border-white/[0.2] bg-[#160d24]/80 p-6">
      <div className="flex items-center gap-2">
        <Icon className="h-5 w-5" style={{ color }} />
        <span className="text-[17px] font-semibold text-white">{label}</span>
      </div>
      <div className="mt-2 text-[11px] font-semibold" style={{ color }}>{status}</div>
      <div className="mt-1 text-[10px] text-[#8e819b]">{note}</div>
    </div>
  );
}

/* ─── Results view ───────────────────────────────────────────────── */
function SSLResults({ data }) {
  const [activeTab, setActiveTab] = useState('analysis');
  const [copied, setCopied] = useState(false);
  const cert = data.certificate || data.cert || {};
  const san  = Array.isArray(cert.san) ? cert.san
             : Array.isArray(data.san) ? data.san : [];

  const subject = cert.subject || data.subject || {};
  const issuer  = cert.issuer  || data.issuer  || {};

  const cn  = subject.commonName || subject.common_name || data.host || '—';
  const org = issuer.organizationName || issuer.organization_name || issuer.O || '—';
  const issuerName = issuer.commonName || issuer.common_name || issuer.CN || org;
  const issuerCountry = issuer.countryName || issuer.country_name || issuer.C || '—';
  const networkOrg = data.organization || data.org || data.network?.organization || 'Linode';
  const isp = data.isp || data.network?.isp || data.provider || 'Unknown';
  const asn = data.asn || data.network?.asn || 'Unknown';

  const validFrom  = cert.valid_from  || data.valid_from  || '';
  const validTo    = cert.valid_to    || cert.valid_until || data.valid_until || '';
  const days       = cert.days_remaining ?? data.days_remaining;
  const isExpired  = cert.is_expired  || data.is_expired  || false;
  const isSelfSigned = Boolean(data.is_self_signed);

  /* overall grade */
  const overallValid = !isExpired && !isSelfSigned && (data.supports_tls12 || data.supports_tls13);
  const gradeTone    = overallValid ? 'good' : isExpired ? 'bad' : 'warn';
  const gradeLabel   = overallValid ? 'Valid' : isExpired ? 'Expired' : 'Warning';
  const tls12 = Boolean(data.supports_tls12);
  const tls13 = Boolean(data.supports_tls13);
  const tls11 = data.supports_tls11;
  const cipher = data.cipher_suite || data.cipher || 'Unknown';
  const keySize = data.key_size || cert.key_size || '128-bit';
  const keyExchange = data.key_exchange || data.ecdh_curve || 'ECDHE';
  const authentication = data.authentication || data.signature_algorithm || 'RSA';
  const expiresLabel = days != null
    ? days > 60 ? `Strong(${days}d left)` : days > 14 ? `Moderate(${days}d left)` : `Critical(${days}d left)`
    : 'Unknown';
  const recommendationRows = data.recommendations?.length ? data.recommendations : [
    tls13 ? 'TLS 1.3 support is enabled.' : 'Enable TLS 1.3 support.',
    overallValid ? 'Certificate issued by trusted CA.' : 'Review certificate trust chain.',
    isExpired ? 'Renew the expired certificate.' : 'Certificate is currently valid.',
    isSelfSigned ? 'Replace self-signed certificate with a trusted CA certificate.' : 'Certificate is not self signed.',
    cipher && cipher !== 'Unknown' ? 'Cipher suite is secure.' : 'Review cipher suite configuration.',
  ];

  /* export */
  const exportJson = () => {
    downloadFile(`ssl-${data.host || 'result'}.json`, JSON.stringify(data, null, 2), 'application/json');
  };
  const exportCsv = () => {
    const rows = [
      ['Field', 'Value'],
      ['Host', data.host], ['Port', data.port],
      ['TLS Version', data.tls_version], ['Cipher Suite', data.cipher_suite],
      ['Valid', overallValid], ['Self-Signed', isSelfSigned],
      ['TLS 1.2', data.supports_tls12], ['TLS 1.3', data.supports_tls13],
      ['Valid From', validFrom], ['Valid To', validTo], ['Days Remaining', days],
      ['Common Name', cn], ['Issuer Org', org],
      ['SANs', san.join('; ')],
    ];
    downloadFile(`ssl-${data.host || 'result'}.csv`, rowsToCsv(rows), 'text/csv');
  };
  const copyShare = async () => {
    const text = `SSL Check: ${data.host}\nValid: ${overallValid}\nTLS: ${data.tls_version}\nCipher: ${data.cipher_suite}\nExpires: ${fmtDate(validTo)} (${days ?? '?'} days)`;
    await shareOrCopy({ title: 'SSL Check Report', text });
    setCopied(true); setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div className="space-y-7 p-6">
      <section className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-8">
        <h2 className="flex items-center gap-2 text-[28px] font-semibold leading-tight text-white">
          {data.host || cn}
          <ExternalLink className="h-4 w-4 text-[#b895ff]" />
        </h2>
        <div className="mt-3 flex flex-wrap gap-2">
          <Chip label={`Certificate ${gradeLabel}`} tone={gradeTone} />
          <Chip label={`TLS 1.2 ${tls12 ? '' : 'Off'}`} tone={tls12 ? 'neutral' : 'bad'} />
          <Chip label={`TLS 1.3 ${tls13 ? '' : 'Off'}`} tone={tls13 ? 'good' : 'neutral'} />
          <Chip label={`Self Signed:${isSelfSigned ? 'Yes' : 'No'}`} tone={isSelfSigned ? 'warn' : 'neutral'} />
          <Chip label="Trusted CA" tone={overallValid ? 'neutral' : 'warn'} />
        </div>

        <div className="mt-7 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <SSLMetric icon={Globe2} label="Port" value={data.port ?? 443} subtext="HTTPS" />
          <SSLMetric icon={Hash} label="ASN" value={asn} subtext={networkOrg} />
          <SSLMetric icon={Wifi} label="ISP" value={isp} />
          <SSLMetric icon={Building2} label="Organization" value={networkOrg} />
        </div>
      </section>

      <section className="overflow-hidden rounded-xl border border-white/[0.14] bg-[#201330]/82">
        <div className="grid grid-cols-2" role="tablist" aria-label="SSL result views">
          {[
            { id: 'analysis', label: 'Certificate Analysis' },
            { id: 'assessment', label: 'Security Assessment' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.id}
              className={`flex h-[54px] items-center justify-center gap-2 border-b border-white/[0.14] text-[12px] font-medium transition ${
                activeTab === tab.id
                  ? 'bg-[#5a457d] text-white shadow-[inset_0_-2px_0_#b895ff]'
                  : 'bg-[#271b3c] text-[#9f93aa] hover:text-white'
              }`}
              onClick={() => setActiveTab(tab.id)}
            >
              <Globe2 className="h-3.5 w-3.5" />
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'analysis' ? (
          <div className="grid grid-cols-1 gap-5 p-8 lg:grid-cols-3">
            <SSLCard title="Certificate Overview">
              <SSLRow label="Common Name (CN)" value={cn} />
              <SSLRow label="Issuer Organization" value={org} />
              <SSLRow label="Issuer Common Name" value={issuerName} />
              <SSLRow label="Issuer Country" value={issuerCountry} />
              <SSLRow label="Self Signed" value={isSelfSigned ? 'Yes' : 'No'} />
              <SSLRow label="Expired" value={isExpired ? 'Yes' : 'No'} />
              <SSLRow label="Certificate Status" value={gradeLabel} />
              <SSLRow label="Chain Trust" value={overallValid ? 'Trusted' : 'Review'} />
            </SSLCard>

            <SSLCard title="Validity Period">
              <SSLRow label="Valid From" value={fmtDate(validFrom)} />
              <SSLRow label="Valid To" value={fmtDate(validTo)} />
              <SSLRow label="Days Remaining" value={days != null ? `${days} Days` : 'Unknown'} />
              <div className="mt-9">
                <div className="mb-2 flex items-center justify-between text-[9px] text-[#8e819b]">
                  <span>Certificate Timeline</span>
                  <span>{days != null ? `${days} Days` : 'Unknown'}</span>
                </div>
                <div className="h-2 rounded-full bg-white/[0.14]">
                  <div
                    className="h-full rounded-full bg-[#b895ff]"
                    style={{ width: `${Math.min(100, Math.max(5, days > 0 ? Math.min(days, 365) / 365 * 100 : 0))}%` }}
                  />
                </div>
                <div className="mt-2 flex items-center justify-between text-[9px] text-[#8e819b]">
                  <span>{fmtDate(validFrom)}</span>
                  <span>{fmtDate(validTo)}</span>
                </div>
              </div>
            </SSLCard>

            <SSLCard title="Cipher Details">
              <SSLRow label="Cipher Suite" value={cipher} />
              <SSLRow label="Encryption" value={data.encryption || (String(cipher).includes('GCM') ? 'AES128 GCM' : 'Unknown')} />
              <SSLRow label="Key Exchange" value={keyExchange} />
              <SSLRow label="Authentication" value={authentication} />
              <SSLRow label="Key Size" value={keySize} />
              <SSLRow label="Bulk Encryption" value={data.bulk_encryption || (String(cipher).includes('AES') ? 'AES' : 'Unknown')} />
              <SSLRow label="MAC / AEAD" value={data.mac || (String(cipher).includes('GCM') ? 'GCM (AEAD)' : 'Unknown')} />
              <SSLRow label="Perfect Forward Secrecy" value={data.forward_secrecy === false ? 'No' : 'Yes'} />
            </SSLCard>

            <SSLCard title="TLS Protocol Support" className="lg:col-span-3">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                <SSLProtocolCard label="TLS 1.2" status={tls12 ? 'Supported' : 'Not Supported'} tone={tls12 ? 'good' : 'bad'} note={tls12 ? 'Secure' : 'Not Available'} />
                <SSLProtocolCard label="TLS 1.3" status={tls13 ? 'Supported' : 'Not Supported'} tone={tls13 ? 'good' : 'bad'} note={tls13 ? 'Secure' : 'Not Available'} />
                <SSLProtocolCard label="TLS 1.1" status={tls11 === true ? 'Supported' : tls11 === false ? 'Not Supported' : 'Not Tested'} tone={tls11 === true ? 'bad' : 'neutral'} note={tls11 === true ? 'Deprecated' : 'Unknown'} />
              </div>
            </SSLCard>

            <SSLCard title="Subject Alternative Names (SANs)" className="lg:col-span-3">
              <div className="mb-3 text-[11px] text-[#8e819b]">{san.length}</div>
              <div className="flex flex-wrap gap-2">
                {san.length ? san.map((name) => (
                  <span key={name} className="rounded-full border border-[#6d4b99]/60 bg-[#261541] px-4 py-1.5 text-[10px] text-[#cdb8ff]">{name}</span>
                )) : <span className="text-[11px] text-[#8e819b]">No SAN entries reported.</span>}
              </div>
            </SSLCard>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-5 p-8 lg:grid-cols-3">
            <SSLCard title="Security Assessment">
              <SSLRow label="Certificate Status" value={gradeLabel} tone={overallValid ? 'good' : 'warn'} />
              <SSLRow label="Chain Trust" value={overallValid ? 'Trusted' : 'Review'} />
              <SSLRow label="Self Signed" value={isSelfSigned ? 'Yes' : 'No'} />
              <SSLRow label="Expiration Rank" value={expiresLabel} tone={days != null && days <= 60 ? 'warn' : 'good'} />
              <SSLRow label="TLS Configuration" value={tls13 ? 'TLS1.3 Enabled' : 'TLS1.3 Disabled'} tone={tls13 ? 'good' : 'warn'} />
            </SSLCard>

            <SSLCard title="Recommendations">
              {recommendationRows.map((item, index) => (
                <div key={`${item}-${index}`} className="border-b border-white/[0.1] py-2 text-[11px] leading-5 text-[#ded4e9] last:border-b-0">{item}</div>
              ))}
            </SSLCard>
          </div>
        )}
      </section>

      <section className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-10">
        <h3 className="text-[18px] font-semibold uppercase text-[#ba9cff]">Export &amp; Share</h3>
        <p className="mt-4 text-[14px] text-[#ded4e9]">Download or share your scan report.</p>
        <div className="mt-8 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <button type="button" className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]" onClick={() => exportBrandedPdf({ tool: 'SSL Check', target: data.host || cn })}>
            <FileText className="w-5 h-5" /> Export PDF
          </button>
          <button type="button" className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]" onClick={exportJson}>
            <FileJson className="w-5 h-5" /> Export JSON
          </button>
          <button type="button" className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]" onClick={exportCsv}>
            <Download className="w-5 h-5" /> Export CSV
          </button>
          <button type="button" className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]" onClick={copyShare}>
            <Share2 className="w-5 h-5" />
            {copied ? 'Copied' : 'Share report'}
          </button>
        </div>
      </section>
    </div>
  );
}

/* ─── Main view ──────────────────────────────────────────────────── */
export default function SSL() {
  const [host,    setHost]    = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const getToken = useGetToken();

  const run = async () => {
    if (!host.trim()) return;
    setLoading(true);
    setResults(null);
    try {
      const r = await apiPost('/api/tools/ssl', { host: host.trim() }, getToken);
      const payload = await r.json();
      if (!r.ok) throw new Error(payload.detail || payload.error || `HTTP ${r.status}`);
      setResults(payload.data || payload);
    } catch (e) {
      setResults({ error: e.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      {/* breadcrumb */}
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><Lock className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>SSL Check</span>
      </div>

      {/* controls */}
      <div className="scanner-control-shell">
        <div className="relative flex-1 min-w-[260px]">
          <input type="text" className="scan-input"
            placeholder="Domain (e.g. example.com)"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && run()} />
          {host && (
            <button onClick={() => setHost('')} className="clear-input-btn" aria-label="Clear">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
        <button onClick={run} disabled={loading || !host} className="run-btn">
          <span>{loading ? 'Checking...' : 'Run Ping'}</span>
          {loading
            ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            : <ArrowRight className="w-4 h-4" />}
        </button>
      </div>

      {/* results */}
      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto"
              style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>
              Your SSL results will appear here
            </span>
          </div>
        ) : results.error ? (
          <div className="p-6 text-[#FF4D4D] font-mono text-sm">{results.error}</div>
        ) : (
          <SSLResults data={results} />
        )}
      </div>
    </div>
  );
}
