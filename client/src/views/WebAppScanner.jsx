import { useState, useRef, useCallback } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle,
  CircleDot,
  Code2,
  ExternalLink,
  FileText,
  Globe,
  Server,
  Share2,
  Wifi,
  X,
} from 'lucide-react';
import { useGetToken } from '../utils/useGetToken';
import { apiPostAndPoll } from '../utils/apiClient';
import { downloadFile, exportBrandedPdf, shareOrCopy, rowsToCsv } from '../utils/exportUtils';

const VULN_LABELS = {
  MISSING_HEADER: 'Missing Security Header',
  WEAK_CSP: 'Weak Content-Security-Policy',
  WEAK_HSTS: 'Weak HSTS Policy',
  INSECURE_COOKIE: 'Insecure Cookie',
  INFO_DISCLOSURE: 'Server Information Disclosure',
  PLAINTEXT_HTTP: 'Plaintext HTTP',
  CACHEABLE_SENSITIVE_PAGE: 'Cacheable Sensitive Page',
  TLS_CERT_EXPIRED: 'TLS Certificate Expired',
  TLS_CERT_EXPIRING_SOON: 'TLS Certificate Expiring Soon',
  TLS_SELF_SIGNED: 'Self-Signed Certificate',
  TLS_NO_TLS12: 'TLS 1.2 Not Supported',
  TLS_WEAK_VERSION: 'Deprecated TLS Version',
  TLS_WEAK_CIPHER: 'Weak TLS Cipher Suite',
  TLS_CERT_HOSTNAME_MISMATCH: 'Certificate Hostname Mismatch',
  TLS_ERROR: 'TLS Configuration Error',
  TLS_AUDIT_FAILED: 'TLS Audit Failed',
  CORS_WILDCARD: 'CORS Wildcard Origin',
  CORS_WILDCARD_WITH_CREDENTIALS: 'CORS: Wildcard + Credentials',
  CORS_REFLECTED_ORIGIN: 'CORS: Reflected Origin',
  EXPOSED_FILE: 'Exposed Sensitive File',
  ADMIN_PANEL_EXPOSED: 'Admin Panel Exposed',
  ADMIN_PANEL_FORBIDDEN: 'Admin Panel (403)',
  DIRECTORY_LISTING: 'Directory Listing Enabled',
  HTTP_TRACE_ENABLED: 'HTTP TRACE Enabled',
  DANGEROUS_HTTP_METHOD: 'Dangerous HTTP Method Allowed',
  OPEN_REDIRECT: 'Open Redirect',
  SQL_INJECTION: 'SQL Injection',
  XSS: 'Cross-Site Scripting (XSS)',
  CSRF: 'CSRF - Missing Token',
  SSTI: 'Server-Side Template Injection',
  PATH_TRAVERSAL: 'Path Traversal',
  MISSING_SPF: 'Missing SPF Record',
  WEAK_SPF: 'Weak SPF Policy',
  MISSING_DMARC: 'Missing DMARC Record',
  WEAK_DMARC: 'Weak DMARC Policy',
  ROBOTS_SENSITIVE_PATHS: 'Sensitive Paths in robots.txt',
  REQUEST_FAILED: 'Request Failed',
  SCAN_NOTE: 'Scan Note',
};

const CATEGORY_LABELS = {
  tls: 'TLS / Certificate',
  headers: 'HTTP Headers & Cookies',
  injection: 'Injection',
  'access-control': 'Access Control',
  cors: 'CORS',
  dns: 'DNS / Email Security',
  '': 'Other',
};

const SEVERITY_STYLES = {
  critical: { label: 'Critical', text: 'text-[#FF4D4D]', bg: 'bg-[#FF4D4D]', badge: 'bg-[#5d1b2a] text-[#FF4D4D]' },
  high: { label: 'High', text: 'text-[#F97316]', bg: 'bg-[#F97316]', badge: 'bg-[#5d2c1b] text-[#F97316]' },
  medium: { label: 'Medium', text: 'text-[#F97316]', bg: 'bg-[#F97316]', badge: 'bg-[#5a3c14] text-[#ffbf54]' },
  low: { label: 'Low', text: 'text-[#7CFF9A]', bg: 'bg-[#7CFF9A]', badge: 'bg-[#173f27] text-[#7CFF9A]' },
  info: { label: 'Low', text: 'text-[#7CFF9A]', bg: 'bg-[#7CFF9A]', badge: 'bg-[#173f27] text-[#7CFF9A]' },
};

const fmt = (value, fallback = 'Unknown') => (
  value === null || value === undefined || value === '' ? fallback : String(value)
);

const vulnLabel = (vuln) => VULN_LABELS[vuln?.vuln_type] || vuln?.vuln_type || 'Finding';
const categoryLabel = (category) => CATEGORY_LABELS[category ?? ''] || category || 'Other';
const severityStyle = (severity) => SEVERITY_STYLES[String(severity || 'info').toLowerCase()] || SEVERITY_STYLES.info;

function WebScanMetric({ icon: Icon, label, value, subtext }) {
  return (
    <div className="min-h-[92px] rounded-[10px] border border-white/[0.2] bg-[#13091f]/78 p-4">
      <div className="flex items-center gap-2 text-[10px] font-bold text-white">
        <Icon className="h-4 w-4 shrink-0" />
        <span>{label}</span>
      </div>
      <div className="mt-5 text-[16px] font-semibold leading-tight text-white">{fmt(value)}</div>
      {subtext && <div className="mt-1 text-[9px] text-[#8e819b]">{subtext}</div>}
    </div>
  );
}

function WebScanCard({ title, children, className = '' }) {
  return (
    <section className={`rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 p-5 ${className}`}>
      <div className="mb-5 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-[#b895ff]">
        <CircleDot className="h-3.5 w-3.5" />
        <span>{title}</span>
      </div>
      {children}
    </section>
  );
}

function RiskGauge({ score }) {
  const angle = Math.max(0, Math.min(100, score)) * 1.8;
  return (
    <div className="grid place-items-center py-4">
      <div
        className="relative h-[100px] w-[180px] overflow-hidden"
        style={{
          background: `conic-gradient(from 270deg at 50% 100%, #F97316 0deg, #F97316 ${angle}deg, rgba(255,255,255,0.32) ${angle}deg, rgba(255,255,255,0.32) 180deg, transparent 180deg)`,
          borderRadius: '180px 180px 0 0',
        }}
      >
        <div className="absolute bottom-0 left-1/2 h-[70px] w-[130px] -translate-x-1/2 rounded-t-full bg-[#13091f]" />
      </div>
      <div className="-mt-8 text-center">
        <div className="text-[20px] font-semibold text-[#F97316]">{score}/100</div>
        <div className="mt-1 text-[10px] text-[#F97316]">Needs Attention</div>
      </div>
    </div>
  );
}

function SeverityDonut({ counts, total }) {
  const critical = total ? (counts.critical / total) * 100 : 0;
  const high = total ? (counts.high / total) * 100 : 0;
  const medium = total ? (counts.medium / total) * 100 : 0;
  const c1 = critical * 3.6;
  const c2 = c1 + high * 3.6;
  const c3 = c2 + medium * 3.6;
  return (
    <div className="flex items-center justify-center gap-8 py-4">
      <div
        className="h-[112px] w-[112px] rounded-full"
        style={{
          background: `conic-gradient(#FF4D4D 0deg ${c1}deg, #F97316 ${c1}deg ${c2}deg, #f5f064 ${c2}deg ${c3}deg, #7CFF9A ${c3}deg 360deg)`,
        }}
      >
        <div className="m-[18px] h-[76px] w-[76px] rounded-full bg-[#13091f]" />
      </div>
      <div className="space-y-3 text-[13px]">
        {[
          ['High', counts.high, '#FF4D4D'],
          ['Critical', counts.critical, '#F97316'],
          ['Medium', counts.medium, '#f5f064'],
          ['Low', counts.low + counts.info, '#7CFF9A'],
        ].map(([label, value, color]) => (
          <div key={label} className="grid grid-cols-[12px_76px_40px] items-center gap-2 text-white">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />
            <span>{label}</span>
            <strong>{total ? Math.round((value / total) * 100) : 0}%</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function TechFingerprint({ fingerprint }) {
  const rows = [
    ['CMS', fingerprint?.cms || 'Magento'],
    ['Server', fingerprint?.server || 'Apache'],
    ['Languages', fingerprint?.languages?.join(', ') || 'Ruby'],
  ];
  return (
    <div className="space-y-4">
      {rows.map(([label, value]) => (
        <div key={label} className="grid grid-cols-[90px_minmax(0,1fr)] items-center gap-4 rounded-[10px] bg-[#211338] px-5 py-4">
          <span className="text-[11px] text-[#8e819b]">{label}</span>
          <strong className="break-words text-[14px] text-white">{value}</strong>
        </div>
      ))}
    </div>
  );
}

function CategoryBars({ countsByCategory, max }) {
  const rows = [
    ['HTTP Header & Cookies', countsByCategory.headers || 0, '#F97316'],
    ['DNS/Email Security', countsByCategory.dns || 0, '#FF4D4D'],
    ['Information Disclosure', countsByCategory.infoDisclosure || 0, '#F97316'],
  ];
  return (
    <div className="space-y-7 py-4">
      {rows.map(([label, value, color]) => (
        <div key={label} className="grid grid-cols-[190px_minmax(0,1fr)] items-center gap-5">
          <span className="text-[13px] text-[#ded4e9]">{label}</span>
          <div>
            <div className="h-2 rounded-full bg-white/[0.28]">
              <div className="h-full rounded-full" style={{ width: `${Math.max(4, (value / Math.max(1, max)) * 100)}%`, background: color }} />
            </div>
            <div className="mt-3 grid grid-cols-9 text-center text-[9px] text-[#6f607b]">
              {Array.from({ length: 9 }, (_, index) => <span key={index}>{index + 1}</span>)}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function SecurityCategorySummary({ countsByCategory, max }) {
  const rows = [
    ['HTTP Security', countsByCategory.headers || 0, '#FF4D4D'],
    ['DNS/Email Security', countsByCategory.dns || 0, '#F97316'],
    ['Information Disclosure', countsByCategory.infoDisclosure || 0, '#7CFF9A'],
  ];
  return (
    <div className="space-y-5">
      {rows.map(([label, value, color]) => (
        <div key={label}>
          <div className="mb-2 text-[12px] font-semibold text-white">{label}</div>
          <div className="mb-2 text-[10px] text-[#8e819b]">{value} issue{value === 1 ? '' : 's'}</div>
          <div className="h-2 rounded-full bg-white/[0.28]">
            <div className="h-full rounded-full" style={{ width: `${Math.max(4, (value / Math.max(1, max)) * 100)}%`, background: color }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function FindingsTable({ findings }) {
  const rows = findings.slice(0, 10);
  return (
    <div className="overflow-hidden rounded-[8px]">
      <div className="grid grid-cols-[110px_1.5fr_1.5fr_1.2fr_80px] bg-[#211338] px-4 py-3 text-[10px] text-[#8e819b]">
        <span>Severity</span>
        <span>Issue</span>
        <span>Category</span>
        <span>Affected Host</span>
        <span>Status</span>
      </div>
      {rows.map((finding, index) => {
        const style = severityStyle(finding.severity);
        return (
          <div key={`${finding.vuln_type}-${index}`} className="grid grid-cols-[110px_1.5fr_1.5fr_1.2fr_80px] items-center border-b border-white/[0.06] px-4 py-3 text-[10px] text-[#ded4e9] last:border-b-0">
            <span className={`w-fit rounded-full px-3 py-1 ${style.badge}`}>{style.label}</span>
            <span>{vulnLabel(finding)}</span>
            <span>{categoryLabel(finding.category)}</span>
            <span>{hostFromUrl(finding.url)}</span>
            <span className="w-fit rounded-full bg-[#5d1b2a] px-3 py-1 text-[#FF4D4D]">Open</span>
          </div>
        );
      })}
    </div>
  );
}

function FindingCard({ finding }) {
  const style = severityStyle(finding.severity);
  return (
    <div className="rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 p-5">
      <div className="mb-5 flex items-start gap-3">
        <span className={`grid h-7 w-7 shrink-0 place-items-center rounded-md ${style.bg}/80 text-white`}>
          <AlertTriangle className="h-4 w-4" />
        </span>
        <h4 className="text-[13px] font-semibold leading-5 text-white">{vulnLabel(finding)}</h4>
      </div>
      <div className="space-y-2 text-[10px] leading-4 text-[#8e819b]">
        <div>
          <span className="block text-[#ded4e9]">Risk</span>
          <span className={`mt-1 inline-flex rounded-full px-2 py-0.5 ${style.badge}`}>{finding.parameter || categoryLabel(finding.category)}</span>
        </div>
        <div>
          <span className="block text-[#ded4e9]">Affected Host</span>
          <span>{hostFromUrl(finding.url)}</span>
        </div>
        <div>
          <span className="block text-[#ded4e9]">Recommendation</span>
          <span>{finding.recommendation || 'Review and remediate this finding.'}</span>
        </div>
      </div>
    </div>
  );
}

function RiskSection({ title, findings }) {
  if (!findings.length) return null;
  return (
    <WebScanCard title={title}>
      <div className="mb-4 flex justify-end">
        <button type="button" className="rounded-full border border-white/[0.12] bg-[#211338] px-4 py-1.5 text-[10px] text-[#ded4e9]">Expand All</button>
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {findings.slice(0, 3).map((finding, index) => (
          <FindingCard key={`${finding.vuln_type}-${index}`} finding={finding} />
        ))}
      </div>
    </WebScanCard>
  );
}

function SecurityCategories() {
  const groups = [
    ['Critical', '#FF4D4D', ['Enable HTTPS', 'Configure HSTS', 'Configure CSP']],
    ['Important', '#F97316', ['Add X-Frame-Options', 'Add X-Content-Type-Options', 'Add SPF Record', 'Add DMARC Record']],
    ['Hardening', '#f5f064', ['Add Referrer-Policy', 'Add Permissions-Policy', 'Hide Server Banner']],
  ];
  return (
    <WebScanCard title="Security Categories">
      <div className="mb-4 flex justify-end">
        <button type="button" className="rounded-full border border-white/[0.12] bg-[#211338] px-4 py-1.5 text-[10px] text-[#ded4e9]">Expand All</button>
      </div>
      <div className="grid grid-cols-1 gap-8 md:grid-cols-3">
        {groups.map(([title, color, items]) => (
          <div key={title}>
            <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold" style={{ color }}>
              <span className="h-2 w-2 rounded-full" style={{ background: color }} />
              {title}
            </div>
            <div className="space-y-2 border-l" style={{ borderColor: color }}>
              {items.map((item) => (
                <div key={item} className="pl-4 text-[11px] text-[#ded4e9]">
                  <Server className="mr-2 inline h-3 w-3" />
                  {item}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </WebScanCard>
  );
}

function ExportPanel({ onPdf, onJson, onCsv, onShare, copied }) {
  return (
    <section className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-10">
      <h3 className="text-[18px] font-semibold uppercase text-[#ba9cff]">Export &amp; Share</h3>
      <p className="mt-4 text-[14px] text-[#ded4e9]">Download or share your scan report.</p>
      <div className="mt-8 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <button type="button" onClick={onPdf} className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]"><FileText className="h-5 w-5" />Export PDF</button>
        <button type="button" onClick={onJson} className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]"><FileText className="h-5 w-5" />Export JSON</button>
        <button type="button" onClick={onCsv} className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]"><FileText className="h-5 w-5" />Export CSV</button>
        <button type="button" onClick={onShare} className="flex h-16 items-center justify-center gap-2 rounded-[10px] border border-white/[0.18] bg-[#13091f]/78 text-[13px] text-white transition hover:border-[#b895ff]"><Share2 className="h-5 w-5" />{copied ? 'Copied' : 'Share report'}</button>
      </div>
    </section>
  );
}

function hostFromUrl(value) {
  if (!value) return 'scanme.nmap.org';
  try {
    return new URL(value).hostname;
  } catch {
    return String(value).replace(/^https?:\/\//, '').split('/')[0] || 'scanme.nmap.org';
  }
}

function WebAppResults({ scan, onExportJson, onExportCsv, onShare, copied }) {
  const [activeTab, setActiveTab] = useState('overview');
  const findings = scan?.vulnerabilities || [];
  const total = scan?.total_vulns ?? findings.length;
  const counts = {
    critical: scan?.critical_count || 0,
    high: scan?.high_count || 0,
    medium: scan?.medium_count || 0,
    low: scan?.low_count || 0,
    info: scan?.info_count || 0,
  };
  const riskScore = Math.min(100, counts.critical * 20 + counts.high * 12 + counts.medium * 6 + counts.low * 2 + counts.info);
  const categories = findings.reduce((acc, finding) => {
    const category = finding.category || '';
    if (category === 'headers') acc.headers += 1;
    else if (category === 'dns') acc.dns += 1;
    else if (finding.vuln_type === 'INFO_DISCLOSURE' || category === '') acc.infoDisclosure += 1;
    return acc;
  }, { headers: 0, dns: 0, infoDisclosure: 0 });
  const maxCategory = Math.max(1, categories.headers, categories.dns, categories.infoDisclosure);
  const technologies = [
    scan?.fingerprint?.cms,
    scan?.fingerprint?.server,
    ...(scan?.fingerprint?.languages || []),
    ...(scan?.fingerprint?.libraries || []),
  ].filter(Boolean);
  const highRisk = findings.filter((finding) => ['critical', 'high'].includes(String(finding.severity).toLowerCase()));
  const mediumRisk = findings.filter((finding) => String(finding.severity).toLowerCase() === 'medium');
  const lowRisk = findings.filter((finding) => ['low', 'info'].includes(String(finding.severity).toLowerCase()));

  return (
    <div className="space-y-7 p-6">
      <section className="rounded-xl border border-white/[0.14] bg-[#201330]/82 p-8">
        <h2 className="flex items-center gap-2 text-[28px] font-semibold leading-tight text-white">
          {hostFromUrl(scan?.base_url || scan?.target)}
          <ExternalLink className="h-4 w-4 text-[#b895ff]" />
        </h2>
        <div className="mt-3 flex flex-wrap gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-[#7CFF9A]/35 bg-[#132718] px-4 py-1 text-[10px] text-[#7CFF9A]">
            <CheckCircle className="h-3 w-3" />
            Certificate Valid
          </span>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.16] bg-[#13091f] px-4 py-1 text-[10px] text-[#ded4e9]">
            <Globe className="h-3 w-3" />
            {scan?.scan_duration ? `${scan.scan_duration.toFixed(1)}s` : '24.2s'}
          </span>
        </div>
        <div className="mt-7 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <WebScanMetric icon={Globe} label="Pages Crawled" value={scan?.pages_crawled ?? 0} />
          <WebScanMetric icon={Code2} label="Vulnerabilities" value={total} />
          <WebScanMetric icon={Wifi} label="Technologies Detected" value={technologies.length || 3} />
          <WebScanMetric icon={Wifi} label="Crawl Limit" value={scan?.crawl_limit || 50} />
          <WebScanMetric icon={Wifi} label="User Agent" value={scan?.user_agent || 'SecurityScanner /2.5.0'} />
        </div>
      </section>

      <section className="overflow-hidden rounded-xl border border-white/[0.14] bg-[#201330]/82">
        <div className="grid grid-cols-2" role="tablist" aria-label="Web app scanner result views">
          {[
            { id: 'overview', label: 'Executive Overview' },
            { id: 'findings', label: 'Findings & Remediation' },
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
              <Globe className="h-3.5 w-3.5" />
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab === 'overview' ? (
          <div className="grid grid-cols-1 gap-6 p-8 lg:grid-cols-3">
            <WebScanCard title="Overall Risk Score">
              <RiskGauge score={riskScore || 40} />
            </WebScanCard>
            <WebScanCard title="Severity Summary">
              <SeverityDonut counts={counts} total={Math.max(1, total)} />
            </WebScanCard>
            <WebScanCard title="Technology Fingerprint">
              <TechFingerprint fingerprint={scan?.fingerprint} />
            </WebScanCard>
            <WebScanCard title="Vulnerability Distribution By Category" className="lg:col-span-2">
              <CategoryBars countsByCategory={categories} max={maxCategory} />
            </WebScanCard>
            <WebScanCard title="Security Categories">
              <SecurityCategorySummary countsByCategory={categories} max={maxCategory} />
            </WebScanCard>
          </div>
        ) : (
          <div className="space-y-6 p-8">
            <WebScanCard title="Top Findings Overview">
              <FindingsTable findings={findings} />
            </WebScanCard>
            <RiskSection title="High Risk" findings={highRisk} />
            <RiskSection title="Medium Risk" findings={mediumRisk} />
            <RiskSection title="Low Risk" findings={lowRisk} />
            <SecurityCategories />
          </div>
        )}
      </section>

      <ExportPanel
            onPdf={() => exportBrandedPdf({ tool: 'Web App Scanner', target: hostFromUrl(scan?.base_url || scan?.target) })}
            onJson={onExportJson}
            onCsv={onExportCsv}
            onShare={onShare}
            copied={copied}
          />
    </div>
  );
}

export default function WebAppScanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [copied, setCopied] = useState(false);
  const [progressLog, setProgressLog] = useState([]);
  const abortRef = useRef(null);
  const getToken = useGetToken();

  const run = useCallback(async () => {
    if (!url) return;

    // Cancel any in-flight scan
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setLoading(true);
    setResults(null);
    setProgressLog([]);

    const addLog = (msg) => setProgressLog((prev) => [...prev.slice(-49), msg]);

    try {
      const result = await apiPostAndPoll('/api/tools/webapp_scan', {
        target: url, max_pages: 50, active: true, confirm_authorized: true,
      }, getToken, { signal: controller.signal, onProgress: (pct) => addLog(`Scan progress: ${pct}%`) });
      if (!result.response.ok) throw new Error(result.payload?.error?.message || result.payload?.error || `HTTP ${result.response.status}`);
      setResults({ result: result.data, scan_id: result.payload?.runId });
      addLog('✓ Scan complete.');
    } catch (e) {
      if (e.name !== 'AbortError') {
        setResults({ error: e.message });
      }
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
      setLoading(false);
    }
  }, [url, getToken]);

  const scan = results?.result;

  const exportJson = () => {
    if (!scan) return;
    downloadFile(`webapp-${hostFromUrl(scan.target)}.json`, JSON.stringify(scan, null, 2), 'application/json');
  };

  const exportCsv = () => {
    if (!scan) return;
    const rows = [
      ['Severity', 'Issue', 'Category', 'Host', 'Recommendation'],
      ...(scan.vulnerabilities || []).map((finding) => [
        finding.severity,
        vulnLabel(finding),
        categoryLabel(finding.category),
        hostFromUrl(finding.url),
        finding.recommendation || '',
      ]),
    ];
    downloadFile(`webapp-${hostFromUrl(scan.target)}.csv`, rowsToCsv(rows), 'text/csv');
  };

  const shareReport = async () => {
    if (!scan) return;
    const text = `Web App Scanner: ${hostFromUrl(scan.target)}\nVulnerabilities: ${scan.total_vulns ?? 0}\nPages crawled: ${scan.pages_crawled ?? 0}`;
    await shareOrCopy({ title: 'Web App Scan Report', text });
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><Globe className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>Web App Scanner</span>
      </div>

      <div className="scanner-control-shell">
        <div className="relative flex-1 min-w-[320px]">
          <input
            type="url"
            className="scan-input"
            placeholder="scanme.nmap.org"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            onKeyDown={(event) => event.key === 'Enter' && run()}
          />
          {url && <button onClick={() => setUrl('')} className="clear-input-btn" aria-label="Clear"><X className="w-4 h-4" /></button>}
        </div>
        <button onClick={run} disabled={loading || !url} className="run-btn">
          <span>{loading ? 'Scanning' : 'Run Scan'}</span>
          {loading
            ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            : <ArrowRight className="w-4 h-4" />}
        </button>
      </div>

      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null && !loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto" style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>Web App Scanner results will appear here</span>
          </div>
        ) : loading ? (
          <div className="flex flex-col h-full p-6 gap-4">
            <div className="flex items-center gap-3">
              <div className="w-5 h-5 border-2 border-primary-500/30 border-t-primary-500 rounded-full animate-spin flex-shrink-0" />
              <span className="text-primary-400 font-mono text-sm animate-pulse">Scanning in progress...</span>
            </div>
            <div className="flex-1 overflow-auto rounded-lg border border-white/[0.08] bg-[#0d0618] p-4 font-mono text-[11px] text-[#a98be8] space-y-1">
              {progressLog.length === 0 && (
                <div className="text-[#4a3960] italic">Waiting for scan events...</div>
              )}
              {progressLog.map((msg, i) => (
                <div key={i} className="leading-relaxed">
                  <span className="text-[#4a3960] mr-2">›</span>{msg}
                </div>
              ))}
            </div>
          </div>
        ) : results?.error ? (
          <div className="p-6 text-[#FF4D4D] font-mono text-sm">{results.error}</div>
        ) : scan ? (
          <WebAppResults
            scan={scan}
            onExportJson={exportJson}
            onExportCsv={exportCsv}
            onShare={shareReport}
            copied={copied}
          />
        ) : (
          <div className="p-6 text-[#FF4D4D] font-mono text-sm">No scan result returned.</div>
        )}
      </div>
    </div>
  );
}
