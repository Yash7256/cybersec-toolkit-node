import { useMemo } from 'react';
import {
  ShieldAlert, ShieldCheck, CheckCircle2, XCircle, AlertTriangle,
  Lock, Network, Eye, BarChart3, Share2, Download, FileText, FileJson,
  ArrowRight, Sparkles, Link2, Timer, Shield, Target, ListChecks,
  Cookie, ShieldBan, Search, Cpu,
} from 'lucide-react';

/* ─── helpers ─────────────────────────────────────────────────────── */
const chip = (label, tone = 'neutral') => {
  const tones = {
    good: 'border-[#7CFF9A]/25 bg-[#7CFF9A]/10 text-[#7CFF9A]',
    bad: 'border-[#FF4D4D]/25 bg-[#FF4D4D]/10 text-[#FF4D4D]',
    warn: 'border-[#F97316]/25 bg-[#F97316]/10 text-[#F97316]',
    info: 'border-cyan-400/25 bg-cyan-500/10 text-[#22d3ee]',
    critical: 'border-[#FF4D4D]/35 bg-[#FF4D4D]/15 text-[#FF4D4D]',
    neutral: 'border-white/[0.14] bg-[#190f23]/85 text-[#d8cfea]',
  };
  return (
    <span className={`inline-flex h-[26px] items-center gap-1.5 rounded-full border px-2.5 text-[10px] font-medium ${tones[tone] || tones.neutral}`}>
      {label}
    </span>
  );
};

const severityColor = (sev) => {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return { text: '#FF4D4D', bg: 'rgba(255,77,77,0.12)', border: 'rgba(255,77,77,0.3)' };
  if (s === 'high') return { text: '#FF4D4D', bg: 'rgba(255,77,77,0.12)', border: 'rgba(255,77,77,0.28)' };
  if (s === 'medium') return { text: '#F97316', bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.22)' };
  if (s === 'low') return { text: '#94a3b8', bg: 'rgba(148,163,184,0.1)', border: 'rgba(148,163,184,0.22)' };
  return { text: '#64748b', bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.2)' };
};

const SectionCard = ({ title, icon: Icon, children, className = '' }) => (
  <div className={`rounded-[10px] border p-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)] ${className}`} style={{ borderColor: 'rgba(124,58,237,0.18)', background: 'rgba(15,8,27,0.6)' }}>
    <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest mb-3.5" style={{ color: '#7a6d8a' }}>
      {Icon && <Icon className="w-4 h-4" />}
      <span>{title}</span>
    </div>
    {children}
  </div>
);

const scoreColor = (s) => {
  if (s >= 90) return '#7CFF9A';
  if (s >= 75) return '#22d3ee';
  if (s >= 55) return '#F97316';
  if (s >= 35) return '#F97316';
  return '#FF4D4D';
};

const scoreTone = (s) => {
  if (s >= 90) return 'good';
  if (s >= 75) return 'info';
  if (s >= 55) return 'warn';
  if (s >= 35) return 'warn';
  return 'bad';
};

const ratingLetter = (s) => {
  if (s >= 90) return 'A';
  if (s >= 75) return 'B';
  if (s >= 55) return 'C';
  if (s >= 35) return 'D';
  return 'F';
};

/* ─── 1. Executive Summary ────────────────────────────────────────── */
function ExecutiveSummary({ data }) {
  const score = data?.security_score ?? 50;
  const riskLevel = data?.risk_level || 'Unknown';
  const rating = ratingLetter(score);
  const sColor = scoreColor(score);
  const sc = useMemo(() => {
    const present = data?.security_headers?.present || [];
    const missing = data?.security_headers?.missing || [];
    const disclosures = data?.information_disclosure || [];
    const recs = data?.recommendations || [];
    const positives = [];
    const risks = [];
    const findings = [];

    if (missing.length === 0 && disclosures.length === 0) {
      positives.push('All critical security headers are present and properly configured.');
    }
    if (data?.clickjacking?.protected) positives.push('Clickjacking protection is active.');
    if (data?.csp?.strength === 'strong') positives.push('CSP is well-configured with strong directives.');
    if (data?.cors?.risk === 'low' || data?.cors?.risk === 'none') positives.push('CORS policy is properly restricted.');
    if (data?.cdn) positives.push(`Protected by ${data.cdn}.`);
    if (data?.waf) positives.push(`WAF detected: ${data.waf}.`);
    if (data?.technologies?.length) positives.push(`${data.technologies.length} technology stack identified.`);

    const hstsMissing = missing.find((m) => m.header === 'Strict-Transport-Security');
    if (hstsMissing) risks.push({ issue: 'HSTS missing', impact: 'high', action: 'Enable HSTS header' });
    const cspMissing = missing.find((m) => m.header === 'Content-Security-Policy');
    if (cspMissing) risks.push({ issue: 'CSP missing', impact: 'critical', action: 'Implement Content-Security-Policy' });
    if (data?.server && !['cloudflare', 'akamai', 'fastly'].includes((data.server || '').toLowerCase())) {
      risks.push({ issue: 'Server banner exposed', impact: 'medium', action: 'Obfuscate server header' });
    }
    disclosures.forEach((d) => {
      risks.push({ issue: `${d.header} discloses ${d.value}`, impact: d.severity, action: 'Remove information disclosure' });
    });
    if (data?.cors?.risk === 'high') risks.push({ issue: 'Permissive CORS policy', impact: 'high', action: 'Restrict CORS origins' });
    if (data?.dangerous_methods?.length) risks.push({ issue: 'Dangerous HTTP methods allowed', impact: 'high', action: 'Disable unused methods' });

    const priorityRecs = recs.slice(0, 3);
    findings.push(`${present.length}/${present.length + missing.length} security headers configured.`);
    if (disclosures.length) findings.push(`${disclosures.length} information disclosure${disclosures.length > 1 ? 's' : ''} detected.`);
    if (data?.cookies?.length) {
      const risky = data.cookies.filter((c) => c.risk !== 'low').length;
      findings.push(`${data.cookies.length} cookie${data.cookies.length > 1 ? 's' : ''} set, ${risky} with security issues.`);
    }

    return { positives, risks, priorityRecs, findings };
  }, [data]);

  return (
    <SectionCard title="Executive Summary" icon={Shield} className="relative overflow-hidden">
      <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${sColor}88, transparent)` }} />
      <div className="flex flex-wrap items-start gap-6">
        <div className="flex items-center gap-4 shrink-0">
          <div className="w-[80px] h-[80px] rounded-2xl grid place-items-center relative" style={{ background: `radial-gradient(circle at 35% 30%, ${sColor}22, transparent 70%), ${sColor}15`, border: `2px solid ${sColor}44` }}>
            <span className="text-[36px] font-bold font-mono leading-none" style={{ color: sColor }}>{rating}</span>
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="text-[22px] font-bold" style={{ color: '#e9d5ff' }}>Overall Security Rating</span>
              {chip(riskLevel === 'Low' ? 'Low Risk' : riskLevel === 'Medium' ? 'Medium Risk' : 'High Risk', riskLevel === 'Low' ? 'good' : riskLevel === 'Medium' ? 'warn' : 'bad')}
              {chip(`Score: ${score}/100`, scoreTone(score))}
            </div>
            <div className="flex items-center gap-2 mt-2">
              <div className="h-2 rounded-full flex-1 min-w-[160px]" style={{ background: 'rgba(124,58,237,0.12)' }}>
                <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, background: sColor }} />
              </div>
              <span className="text-[11px] font-mono shrink-0" style={{ color: '#7a6d8a' }}>{score}/100</span>
            </div>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-5">
        <div className="rounded-lg p-3.5 border transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]" style={{ borderColor: 'rgba(124,255,154,0.15)', background: 'rgba(124,255,154,0.04)' }}>
          <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest mb-2.5" style={{ color: '#7CFF9A' }}>
            <CheckCircle2 className="w-3 h-3" /> Positive Findings
          </div>
          <ul className="m-0 p-0 list-none flex flex-col gap-1.5">
            {sc.positives.length ? sc.positives.slice(0, 4).map((p, i) => (
              <li key={i} className="text-[11px] leading-[1.5]" style={{ color: '#c4b5fd' }}>{p}</li>
            )) : <li className="text-[11px]" style={{ color: '#7a6d8a' }}>No notable security controls detected.</li>}
          </ul>
        </div>
        <div className="rounded-lg p-3.5 border transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]" style={{ borderColor: 'rgba(255,77,77,0.15)', background: 'rgba(255,77,77,0.04)' }}>
          <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest mb-2.5" style={{ color: '#FF4D4D' }}>
            <AlertTriangle className="w-3 h-3" /> Largest Risks
          </div>
          <ul className="m-0 p-0 list-none flex flex-col gap-1.5">
            {sc.risks.slice(0, 5).map((r, i) => (
              <li key={i} className="flex items-start gap-1.5 text-[11px] leading-[1.5]" style={{ color: '#c4b5fd' }}>
                <span className="w-1.5 h-1.5 rounded-full shrink-0 mt-1" style={{ background: r.impact === 'critical' || r.impact === 'high' ? '#FF4D4D' : '#F97316' }} />
                <span>{r.issue}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className="rounded-lg p-3.5 border transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]" style={{ borderColor: 'rgba(249,115,22,0.15)', background: 'rgba(249,115,22,0.04)' }}>
          <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest mb-2.5" style={{ color: '#F97316' }}>
            <Target className="w-3 h-3" /> Priority Actions
          </div>
          <ul className="m-0 p-0 list-none flex flex-col gap-1.5">
            {sc.priorityRecs.length ? sc.priorityRecs.map((r, i) => (
              <li key={i} className="flex items-start gap-1.5 text-[11px] leading-[1.5]" style={{ color: '#c4b5fd' }}>
                <ArrowRight className="w-3 h-3 shrink-0 mt-0.5" style={{ color: '#F97316' }} />
                <span>{r}</span>
              </li>
            )) : <li className="text-[11px]" style={{ color: '#7a6d8a' }}>No critical actions required.</li>}
          </ul>
        </div>
      </div>
    </SectionCard>
  );
}

/* ─── 2. Security Score Card ──────────────────────────────────────── */
function SecurityScoreCard({ data }) {
  const score = data?.security_score ?? 50;
  const sColor = scoreColor(score);
  const rating = ratingLetter(score);
  const categories = useMemo(() => {
    const present = data?.security_headers?.present || [];
    const missing = data?.security_headers?.missing || [];
    const headerScore = present.length ? Math.round((present.length / (present.length + missing.length)) * 100) : 0;
    const disclosureScore = data?.information_disclosure?.length ? Math.max(0, 100 - data.information_disclosure.length * 25) : 100;
    const cookieScore = data?.cookies?.length ? Math.round(data.cookies.filter((c) => c.risk === 'low').length / data.cookies.length * 100) : 100;
    const tlsScore = data?.protocol?.startsWith('HTTP/2') || data?.protocol === 'HTTP/1.1' ? (data?.status_code === 200 ? 85 : 70) : 50;
    const browserScore = [];
    if (data?.clickjacking?.protected) browserScore.push(20);
    if (data?.csp?.strength === 'strong') browserScore.push(25);
    if (present.find((h) => h.header === 'X-Content-Type-Options')) browserScore.push(15);
    if (present.find((h) => h.header === 'Referrer-Policy')) browserScore.push(15);
    if (present.find((h) => h.header === 'Permissions-Policy')) browserScore.push(15);
    if (present.find((h) => h.header === 'Strict-Transport-Security')) browserScore.push(10);
    const browserProtectionScore = Math.min(100, browserScore.reduce((a, b) => a + b, 0));
    const cacheScore = data?.caching?.cache_control ? 90 : 50;

    return [
      { label: 'Security Headers', score: headerScore, icon: ShieldCheck },
      { label: 'Info Disclosure', score: disclosureScore, icon: Eye },
      { label: 'Cookie Security', score: cookieScore, icon: Cookie },
      { label: 'TLS / Transport', score: tlsScore, icon: Lock },
      { label: 'Browser Protection', score: browserProtectionScore, icon: ShieldBan },
      { label: 'Cache Configuration', score: cacheScore, icon: Timer },
    ];
  }, [data]);

  return (
    <SectionCard title="Security Score Breakdown" icon={BarChart3}>
      <div className="flex items-center gap-4 mb-5">
        <div className="w-[88px] h-[88px] rounded-2xl grid place-items-center shrink-0" style={{ background: `radial-gradient(circle at 35% 30%, ${sColor}22, transparent 70%), ${sColor}12`, border: `2px solid ${sColor}33` }}>
          <div className="text-center">
            <div className="text-[32px] font-bold font-mono leading-none" style={{ color: sColor }}>{score}</div>
            <div className="text-[10px] font-bold mt-0.5" style={{ color: '#7a6d8a' }}>/ 100</div>
          </div>
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[20px] font-bold font-mono" style={{ color: sColor }}>{rating}</span>
            <span className="text-[13px]" style={{ color: '#e9d5ff' }}>{score >= 90 ? 'Excellent' : score >= 75 ? 'Good' : score >= 55 ? 'Moderate' : score >= 35 ? 'Weak' : 'Poor'} Security Posture</span>
          </div>
          <div className="h-2.5 rounded-full" style={{ background: 'rgba(124,58,237,0.12)' }}>
            <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, background: `linear-gradient(90deg, ${sColor}88, ${sColor})` }} />
          </div>
        </div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {categories.map((cat) => (
          <div key={cat.label} className="flex items-center gap-2.5 rounded-lg px-3 py-2 border" style={{ borderColor: 'rgba(124,58,237,0.1)', background: 'rgba(13,7,24,0.4)' }}>
            <cat.icon className="w-3.5 h-3.5 shrink-0" style={{ color: scoreColor(cat.score) }} />
            <span className="text-[10px] font-semibold uppercase tracking-wider flex-1" style={{ color: '#7a6d8a' }}>{cat.label}</span>
            <div className="w-[72px] h-1.5 rounded-full" style={{ background: 'rgba(124,58,237,0.12)' }}>
              <div className="h-full rounded-full transition-all" style={{ width: `${cat.score}%`, background: scoreColor(cat.score) }} />
            </div>
            <span className="text-[11px] font-mono w-8 text-right" style={{ color: scoreColor(cat.score) }}>{cat.score}</span>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

/* ─── 3. Risk Breakdown ───────────────────────────────────────────── */
function RiskBreakdown({ data }) {
  const risks = useMemo(() => {
    const present = data?.security_headers?.present || [];
    const missing = data?.security_headers?.missing || [];
    const infoD = data?.information_disclosure || [];

    const authScore = data?.cors?.risk === 'low' || !data?.cors?.risk ? 90 : data?.cors?.risk === 'medium' ? 50 : 20;
    const headers = present.length ? Math.round((present.length / (present.length + missing.length)) * 100) : 0;
    const disclosureScore = infoD.length ? Math.max(0, 100 - infoD.length * 30) : 100;
    const cookieScore = data?.cookies?.length ? Math.round(data.cookies.filter((c) => c.risk === 'low').length / data.cookies.length * 100) : 100;
    const transportScore = data?.clickjacking?.protected ? 85 : 40;
    const browserScore = (present.find((h) => h.header === 'X-Frame-Options') ? 20 : 0) + (data?.csp?.strength !== 'missing' ? 25 : 0) + (present.find((h) => h.header === 'X-Content-Type-Options') ? 15 : 0) + (present.find((h) => h.header === 'Permissions-Policy') ? 15 : 0) + (present.find((h) => h.header === 'Referrer-Policy') ? 15 : 0) + (present.find((h) => h.header === 'Strict-Transport-Security') ? 10 : 0);

    return [
      { label: 'Authentication & CORS', score: authScore, desc: data?.cors?.risk === 'high' ? 'Permissive cross-origin policy' : data?.cors?.risk === 'medium' ? 'Moderate CORS restrictions' : 'CORS properly configured' },
      { label: 'Security Headers', score: headers, desc: `${present.length} configured, ${missing.length} missing` },
      { label: 'Information Disclosure', score: disclosureScore, desc: infoD.length ? `${infoD.length} exposures detected` : 'Minimal fingerprinting surface' },
      { label: 'Cookie Security', score: cookieScore, desc: data?.cookies?.length ? `${data.cookies.filter((c) => c.risk !== 'low').length} insecure cookies` : 'No cookies set' },
      { label: 'Transport Security', score: transportScore, desc: data?.clickjacking?.protected ? 'Clickjacking protected' : 'Frame protection missing' },
      { label: 'Browser Protection', score: browserScore, desc: browserScore >= 80 ? 'Strong client-side defenses' : browserScore >= 50 ? 'Partial browser protections' : 'Weak browser security' },
    ];
  }, [data]);

  return (
    <SectionCard title="Risk Breakdown" icon={AlertTriangle}>
      <div className="flex flex-col gap-2">
        {risks.map((r) => {
          const color = scoreColor(r.score);
          const tone = r.score >= 75 ? 'good' : r.score >= 50 ? 'warn' : 'bad';
          return (
            <div key={r.label} className="flex items-center gap-3 rounded-lg px-3 py-2.5 border" style={{ borderColor: 'rgba(124,58,237,0.1)', background: 'rgba(13,7,24,0.4)' }}>
              <div className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[12px] font-semibold" style={{ color: '#e9d5ff' }}>{r.label}</span>
                  {chip(tone === 'good' ? 'Low Risk' : tone === 'warn' ? 'Medium Risk' : 'High Risk', tone)}
                </div>
                <div className="text-[10px] mt-0.5" style={{ color: '#7a6d8a' }}>{r.desc}</div>
              </div>
              <div className="text-[14px] font-bold font-mono shrink-0" style={{ color }}>{r.score}</div>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ─── 4. Information Disclosure Analysis ──────────────────────────── */
function InfoDisclosureAnalysis({ data }) {
  const disclosures = useMemo(() => {
    const all = [];
    const raw = data?.headers || {};
    const known = [
      { header: 'Server', field: 'server', critical: ['nginx/', 'apache/', 'microsoft-iis/', 'openresty/', 'caddy/'] },
      { header: 'X-Powered-By', field: 'x-powered-by' },
      { header: 'X-AspNet-Version', field: 'x-aspnet-version' },
      { header: 'X-AspNetMvc-Version', field: 'x-aspnetmvc-version' },
      { header: 'Via', field: 'via' },
      { header: 'X-Cache', field: 'x-cache' },
      { header: 'X-Forwarded-For', field: 'x-forwarded-for' },
      { header: 'X-Real-IP', field: 'x-real-ip' },
      { header: 'X-Debug', field: 'x-debug' },
      { header: 'X-Drupal-Cache', field: 'x-drupal-cache' },
      { header: 'X-Drupal-Dynamic-Cache', field: 'x-drupal-dynamic-cache' },
      { header: 'X-Generator', field: 'x-generator' },
      { header: 'X-Pingback', field: 'x-pingback' },
      { header: 'X-Runtime', field: 'x-runtime' },
      { header: 'X-Varnish', field: 'x-varnish' },
    ];

    known.forEach(({ header, field, critical }) => {
      const val = raw[field] || raw[field.toLowerCase()];
      if (val) {
        const isCritical = critical ? critical.some((p) => val.toLowerCase().startsWith(p)) : false;
        const hasVersion = /\d+\.\d+/.test(val);
        all.push({
          header,
          value: val,
          severity: isCritical ? 'critical' : hasVersion ? 'high' : 'medium',
          issue: `${header} header exposes implementation details${hasVersion ? ' including version numbers' : ''}.`,
        });
      }
    });

    (data?.information_disclosure || []).forEach((d) => {
      if (!all.find((a) => a.header.toLowerCase() === d.header.toLowerCase())) {
        all.push(d);
      }
    });

    if (data?.server) {
      const s = data.server.toLowerCase();
      const frameworkHints = [];
      if (s.includes('nginx')) frameworkHints.push({ label: 'nginx', version: s.match(/nginx\/([\d.]+)/)?.[1] });
      if (s.includes('apache')) frameworkHints.push({ label: 'Apache', version: s.match(/Apache\/([\d.]+)/i)?.[1] });
      if (s.includes('iis') || s.includes('microsoft')) frameworkHints.push({ label: 'IIS', version: s.match(/\/([\d.]+)/)?.[1] });
      if (s.includes('openresty')) frameworkHints.push({ label: 'OpenResty', version: s.match(/openresty\/([\d.]+)/i)?.[1] });
      if (s.includes('caddy')) frameworkHints.push({ label: 'Caddy', version: s.match(/caddy\/([\d.]+)/i)?.[1] });
      if (s.includes('cloudflare')) frameworkHints.push({ label: 'Cloudflare', version: null });

      if (frameworkHints.length && !all.find((a) => a.header.toLowerCase() === 'server')) {
        all.push({
          header: 'Server',
          value: data.server,
          severity: frameworkHints.some((f) => f.version) ? 'high' : 'medium',
          issue: `Server header reveals: ${frameworkHints.map((f) => f.label + (f.version ? ` ${f.version}` : '')).join(', ')}.`,
        });
      }
    }

    if (raw['x-powered-by']) {
      const pb = raw['x-powered-by'];
      const frameworks = [];
      if (pb.toLowerCase().includes('php')) frameworks.push('PHP');
      if (pb.toLowerCase().includes('asp.net')) frameworks.push('ASP.NET');
      if (pb.toLowerCase().includes('express')) frameworks.push('Express');
      if (pb.toLowerCase().includes('django')) frameworks.push('Django');
      if (pb.toLowerCase().includes('flask')) frameworks.push('Flask');
      if (pb.toLowerCase().includes('ruby')) frameworks.push('Ruby on Rails');
      if (frameworks.length && !all.find((a) => a.header === 'X-Powered-By')) {
        all.push({
          header: 'X-Powered-By',
          value: pb,
          severity: 'high',
          issue: `Framework disclosed: ${frameworks.join(', ')}.`,
        });
      }
    }

    return all;
  }, [data]);

  const criticalCount = disclosures.filter((d) => d.severity === 'critical').length;
  const highCount = disclosures.filter((d) => d.severity === 'high').length;

  return (
    <SectionCard title="Information Disclosure" icon={Eye}>
      <div className="flex items-center gap-2 mb-3.5 flex-wrap">
        {criticalCount > 0 && chip(`Critical: ${criticalCount}`, 'critical')}
        {highCount > 0 && chip(`High: ${highCount}`, 'bad')}
        {disclosures.length === 0 && chip('No disclosures', 'good')}
      </div>
      {disclosures.length === 0 ? (
        <p className="text-[12px] text-center py-6" style={{ color: '#7a6d8a' }}>Server metadata disclosure is minimal, reducing the fingerprinting surface.</p>
      ) : (
        <div className="flex flex-col gap-1.5">
          {disclosures.map((d, i) => {
            const sc = severityColor(d.severity);
            return (
              <div key={i} className="flex items-center gap-2.5 rounded-lg px-3 py-2 border" style={{ borderColor: `${sc.border}`, background: `${sc.bg}` }}>
                <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: sc.text }} />
                <span className="text-[11px] font-mono font-semibold shrink-0" style={{ color: '#e9d5ff' }}>{d.header}:</span>
                <span className="text-[10px] font-mono truncate flex-1" style={{ color: '#c4b5fd' }}>{d.value}</span>
                <span className="text-[9px] font-bold uppercase shrink-0" style={{ color: sc.text }}>{d.severity}</span>
              </div>
            );
          })}
        </div>
      )}
    </SectionCard>
  );
}

/* ─── 5. Missing Security Headers ─────────────────────────────────── */
function MissingSecurityHeaders({ data }) {
  const missing = useMemo(() => {
    const items = data?.security_headers?.missing || [];
    const extra = [];
    if (!items.find((h) => h.header === 'Cross-Origin-Embedder-Policy')) extra.push({ header: 'Cross-Origin-Embedder-Policy', severity: 'MEDIUM', description: 'Prevents cross-origin resource loading', recommendation: 'Add COEP: require-corp' });
    if (!items.find((h) => h.header === 'Cross-Origin-Opener-Policy')) extra.push({ header: 'Cross-Origin-Opener-Policy', severity: 'MEDIUM', description: 'Isolates cross-origin windows', recommendation: 'Add COOP: same-origin' });
    if (!items.find((h) => h.header === 'Cross-Origin-Resource-Policy')) extra.push({ header: 'Cross-Origin-Resource-Policy', severity: 'MEDIUM', description: 'Controls cross-origin resource loading', recommendation: 'Add CORP: same-origin' });
    return [...items, ...extra.filter((e) => !items.find((i) => i.header === e.header))];
  }, [data]);

  const attacks = {
    'Strict-Transport-Security': { attack: 'SSL Stripping / MITM', why: 'Ensures HTTPS-only connections, preventing protocol downgrade attacks.' },
    'Content-Security-Policy': { attack: 'XSS / Data Injection', why: 'Restricts which resources can be loaded, blocking inline scripts and unauthorized origins.' },
    'X-Frame-Options': { attack: 'Clickjacking', why: 'Prevents your site from being embedded in iframes on malicious pages.' },
    'X-Content-Type-Options': { attack: 'MIME Sniffing', why: 'Prevents browsers from interpreting files as a different MIME type.' },
    'Referrer-Policy': { attack: 'Information Leakage', why: 'Controls how much referrer information is sent with cross-origin requests.' },
    'Permissions-Policy': { attack: 'Feature Abuse', why: 'Restricts browser API access (camera, mic, geolocation) for your origin.' },
    'Cross-Origin-Embedder-Policy': { attack: 'Cross-Origin Leaks', why: 'Ensures documents from different origins cannot load your resources without explicit permission.' },
    'Cross-Origin-Opener-Policy': { attack: 'Cross-Origin Window Attacks', why: 'Prevents cross-origin windows from accessing your window object via window.opener.' },
    'Cross-Origin-Resource-Policy': { attack: 'Cross-Origin Data Exfiltration', why: 'Controls which origins can load your resources, preventing data theft.' },
  };

  if (!missing.length) {
    return <SectionCard title="Missing Security Headers" icon={XCircle}>
      <p className="text-[12px] text-center py-6" style={{ color: '#7CFF9A' }}>
        <CheckCircle2 className="w-4 h-4 inline mr-1.5" />All tracked security headers are present.
      </p>
    </SectionCard>;
  }

  return (
    <SectionCard title="Missing Security Headers" icon={XCircle}>
      <div className="flex flex-col gap-2">
        {missing.map((h) => {
          const severity = (h.severity || 'medium').toLowerCase();
          const sc = severityColor(severity);
          const impact = severity === 'critical' || severity === 'high' ? 'High Impact' : severity === 'medium' ? 'Medium Impact' : 'Low Impact';
          const attackInfo = attacks[h.header] || { attack: 'Security Degradation', why: 'This header provides important security controls for modern web applications.' };
          return (
            <div key={h.header} className="rounded-lg p-3 border" style={{ borderColor: `${sc.border}`, background: `${sc.bg}` }}>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[13px] font-mono font-semibold" style={{ color: '#e9d5ff' }}>{h.header}</span>
                    <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded-full" style={{ background: sc.bg, color: sc.text, border: `1px solid ${sc.border}` }}>{impact}</span>
                  </div>
                  <div className="text-[10px] mt-1.5 leading-[1.5]" style={{ color: '#c4b5fd' }}>
                    <span className="font-semibold" style={{ color: '#F97316' }}>Attack prevented: </span>{attackInfo.attack}
                  </div>
                  <div className="text-[10px] mt-0.5 leading-[1.5]" style={{ color: '#7a6d8a' }}>{attackInfo.why}</div>
                </div>
              </div>
              <div className="mt-2 text-[10px] p-2 rounded" style={{ background: 'rgba(124,58,237,0.08)', color: '#F97316' }}>
                Fix: {h.recommendation || `Add the ${h.header} response header.`}
              </div>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ─── 6. Existing Security Headers ────────────────────────────────── */
function ExistingSecurityHeaders({ data }) {
  const rows = useMemo(() => {
    const items = [];
    (data?.security_analysis || []).forEach((a) => {
      if (a.present) {
        const quality = a.strength === 'strong' ? { label: 'Excellent', color: '#7CFF9A' } : a.strength === 'moderate' ? { label: 'Adequate', color: '#F97316' } : a.strength === 'weak' ? { label: 'Weak', color: '#F97316' } : { label: 'Configured', color: '#22d3ee' };
        items.push({ header: a.header, value: a.value, quality });
      }
    });
    return items;
  }, [data]);

  if (!rows.length) {
    return <SectionCard title="Existing Security Headers" icon={CheckCircle2}>
      <p className="text-[12px] text-center py-6" style={{ color: '#7a6d8a' }}>No security headers are currently configured.</p>
    </SectionCard>;
  }

  return (
    <SectionCard title="Existing Security Headers" icon={CheckCircle2}>
      <div className="flex flex-col gap-1.5">
        {rows.map((r) => (
          <div key={r.header} className="flex items-center gap-3 rounded-lg px-3 py-2 border" style={{ borderColor: 'rgba(124,255,154,0.12)', background: 'rgba(124,255,154,0.04)' }}>
            <CheckCircle2 className="w-4 h-4 shrink-0" style={{ color: '#7CFF9A' }} />
            <div className="flex-1 min-w-0">
              <div className="text-[12px] font-mono font-semibold" style={{ color: '#e9d5ff' }}>{r.header}</div>
              {r.value && <div className="text-[10px] font-mono truncate mt-0.5" style={{ color: '#7a6d8a' }}>{r.value}</div>}
            </div>
            <div className="text-[9px] font-bold uppercase px-2 py-0.5 rounded-full shrink-0" style={{ background: `${r.quality.color}15`, color: r.quality.color, border: `1px solid ${r.quality.color}33` }}>
              {r.quality.label}
            </div>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

/* ─── 7. Attack Surface Analysis ──────────────────────────────────── */
function AttackSurfaceAnalysis({ data }) {
  const findings = useMemo(() => {
    const f = [];
    const present = data?.security_headers?.present || [];

    const xfo = present.find((h) => h.header === 'X-Frame-Options');
    const csp = data?.csp;
    const xcto = present.find((h) => h.header === 'X-Content-Type-Options');
    const rp = present.find((h) => h.header === 'Referrer-Policy');
    const discl = data?.information_disclosure || [];

    f.push({
      label: 'Clickjacking', status: data?.clickjacking?.protected ? 'Mitigated' : 'Vulnerable', severity: data?.clickjacking?.protected ? 'low' : 'critical',
      desc: data?.clickjacking?.protected ? `Protected via ${xfo?.value || 'CSP frame-ancestors'}` : 'X-Frame-Options or CSP frame-ancestors required',
    });
    f.push({
      label: 'XSS Protection', status: csp?.strength === 'strong' ? 'Mitigated' : csp?.strength === 'moderate' ? 'Partial' : 'Weak', severity: csp?.strength === 'strong' ? 'low' : csp?.strength === 'moderate' ? 'medium' : 'high',
      desc: csp?.strength === 'strong' ? 'CSP provides strong XSS mitigation' : csp?.strength === 'moderate' ? 'CSP present but has weaknesses' : 'No strong CSP to prevent inline script injection',
    });
    f.push({
      label: 'MIME Sniffing', status: xcto ? 'Mitigated' : 'Vulnerable', severity: xcto ? 'low' : 'high',
      desc: xcto ? 'X-Content-Type-Options: nosniff is set' : 'Browser may MIME-sniff, enabling script injection via manipulated content types',
    });
    f.push({
      label: 'CSRF Hardening', status: rp ? 'Partial' : 'Weak', severity: rp ? 'medium' : 'high',
      desc: rp ? `Referrer-Policy: ${rp.value} provides some CSRF protection` : 'No Referrer-Policy; CSRF token validation should be enforced server-side',
    });
    f.push({
      label: 'Cross-Origin Isolation', status: 'Needs Review', severity: 'medium',
      desc: 'COOP + COEP required for cross-origin isolation to enable SharedArrayBuffer and prevent Spectre-based attacks',
    });
    f.push({
      label: 'Cross-Origin Leaks', status: 'Needs Review', severity: 'medium',
      desc: 'CORP header prevents cross-origin resource loading; missing without explicit configuration',
    });
    f.push({
      label: 'Information Disclosure', status: discl.length ? `${discl.length} exposure${discl.length > 1 ? 's' : ''}` : 'Minimal', severity: discl.length > 2 ? 'high' : discl.length > 0 ? 'medium' : 'low',
      desc: discl.length ? `Server exposes: ${discl.map((d) => d.header).join(', ')}` : 'Server metadata disclosure is minimal',
    });
    f.push({
      label: 'Cache Poisoning', status: data?.caching?.cache_control ? 'Controlled' : 'Needs Review', severity: data?.caching?.cache_control ? 'low' : 'medium',
      desc: data?.caching?.cache_control ? `Cache-Control present: ${data.caching.cache_control}` : 'No Cache-Control header; sensitive responses may be cached',
    });
    f.push({
      label: 'Open Redirect', status: 'Not Tested', severity: 'low',
      desc: 'Redirect chain analysis may reveal open redirect vectors; review redirect URLs for unvalidated parameters',
    });
    f.push({
      label: 'Debug Headers', status: 'Needs Review', severity: 'high',
      desc: 'X-Debug, X-Drupal-Cache, X-Generator headers can leak internal state and framework information',
    });
    f.push({
      label: 'Technology Fingerprinting', status: 'Exposed', severity: 'medium',
      desc: data?.technologies?.length ? `Fingerprintable: ${data.technologies.slice(0, 5).join(', ')}` : 'Server header version exposed',
    });

    return f;
  }, [data]);

  return (
    <SectionCard title="Attack Surface Analysis" icon={Target}>
      <div className="grid grid-cols-1 gap-1.5">
        {findings.map((f) => {
          const sc = severityColor(f.severity);
          const statusColor = f.status === 'Mitigated' || f.status === 'Controlled' || f.status === 'Minimal' ? '#7CFF9A' : f.status === 'Partial' || f.status === 'Needs Review' || f.status === 'Not Tested' ? '#F97316' : '#FF4D4D';
          return (
            <div key={f.label} className="flex items-start gap-2.5 rounded-lg px-3 py-2 border" style={{ borderColor: 'rgba(124,58,237,0.08)', background: 'rgba(13,7,24,0.3)' }}>
              <div className="w-2 h-2 rounded-full shrink-0 mt-1" style={{ background: sc.text }} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] font-semibold" style={{ color: '#e9d5ff' }}>{f.label}</span>
                  <span className="text-[9px] font-bold uppercase" style={{ color: statusColor }}>{f.status}</span>
                  <span className="text-[9px] font-bold uppercase" style={{ color: sc.text }}>({f.severity})</span>
                </div>
                <div className="text-[10px] mt-0.5 leading-[1.4]" style={{ color: '#7a6d8a' }}>{f.desc}</div>
              </div>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ─── 8. Security Recommendations ─────────────────────────────────── */
const owaspMap = {
  'Strict-Transport-Security': 'A05 Security Misconfiguration',
  'Content-Security-Policy': 'A03 Injection',
  'X-Frame-Options': 'A05 Security Misconfiguration',
  'X-Content-Type-Options': 'A05 Security Misconfiguration',
  'Referrer-Policy': 'A05 Security Misconfiguration',
  'Permissions-Policy': 'A01 Broken Access Control',
  'Cross-Origin-Embedder-Policy': 'A05 Security Misconfiguration',
  'Cross-Origin-Opener-Policy': 'A05 Security Misconfiguration',
  'Cross-Origin-Resource-Policy': 'A05 Security Misconfiguration',
  'CORS': 'A01 Broken Access Control',
  'Server Banner': 'A05 Security Misconfiguration',
  'Information Disclosure': 'A05 Security Misconfiguration',
  'Cookie Security': 'A02 Cryptographic Failures',
};

function SecurityRecommendations({ data }) {
  const recs = useMemo(() => {
    const items = [];
    const missing = data?.security_headers?.missing || [];

    missing.forEach((h) => {
      const severity = (h.severity || 'MEDIUM').toLowerCase();
      const priority = severity === 'critical' ? 'Critical' : severity === 'high' ? 'High' : severity === 'medium' ? 'Medium' : 'Low';
      const effort = h.header === 'Strict-Transport-Security' || h.header === 'X-Frame-Options' || h.header === 'X-Content-Type-Options' ? 'Easy' : h.header === 'Content-Security-Policy' ? 'Complex' : 'Moderate';
      const impact = severity === 'critical' ? '+25' : severity === 'high' ? '+18' : severity === 'medium' ? '+12' : '+5';
      items.push({
        priority,
        title: `Implement ${h.header}`,
        desc: h.recommendation || `Add the ${h.header} response header to your server configuration.`,
        effort,
        impact,
        owasp: owaspMap[h.header] || 'A05 Security Misconfiguration',
      });
    });

    if (data?.cors?.risk === 'high') {
      items.push({
        priority: 'High', title: 'Restrict CORS Policy',
        desc: 'Replace wildcard Access-Control-Allow-Origin with a specific origin whitelist.',
        effort: 'Easy', impact: '+15', owasp: 'A01 Broken Access Control',
      });
    }
    if (data?.dangerous_methods?.length) {
      items.push({
        priority: 'High', title: 'Disable Dangerous HTTP Methods',
        desc: `Disable unused methods: ${data.dangerous_methods.join(', ')}.`,
        effort: 'Easy', impact: '+10', owasp: 'A05 Security Misconfiguration',
      });
    }
    if (data?.server) {
      items.push({
        priority: 'Medium', title: 'Obfuscate Server Banner',
        desc: 'Configure your server to return a generic Server header without version details.',
        effort: 'Easy', impact: '+8', owasp: 'A05 Security Misconfiguration',
      });
    }
    (data?.recommendations || []).forEach((r) => {
      if (!items.find((i) => i.title === r)) {
        items.push({
          priority: 'Medium', title: r, desc: r, effort: 'Moderate', impact: '+10', owasp: 'A05 Security Misconfiguration',
        });
      }
    });

    const order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    items.sort((a, b) => (order[a.priority] || 99) - (order[b.priority] || 99));
    return items;
  }, [data]);

  if (!recs.length) {
    return <SectionCard title="Recommendations" icon={ListChecks}>
      <p className="text-[12px] text-center py-6" style={{ color: '#7CFF9A' }}>
        <CheckCircle2 className="w-4 h-4 inline mr-1.5" />No recommendations — all checks passed.
      </p>
    </SectionCard>;
  }

  return (
    <SectionCard title="Prioritized Recommendations" icon={ListChecks}>
      <div className="flex flex-col gap-2">
        {recs.map((r, i) => {
          const pColor = r.priority === 'Critical' ? '#FF4D4D' : r.priority === 'High' ? '#FF4D4D' : r.priority === 'Medium' ? '#F97316' : '#94a3b8';
          return (
            <div key={i} className="rounded-lg p-3 border" style={{ borderColor: 'rgba(124,58,237,0.1)', background: 'rgba(13,7,24,0.4)' }}>
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[12px] font-semibold" style={{ color: '#e9d5ff' }}>{r.title}</span>
                    <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded-full" style={{ background: `${pColor}18`, color: pColor, border: `1px solid ${pColor}33` }}>{r.priority}</span>
                  </div>
                  <div className="text-[10px] mt-1 leading-[1.4]" style={{ color: '#c4b5fd' }}>{r.desc}</div>
                  <div className="flex items-center gap-3 mt-1.5 text-[9px]">
                    <span style={{ color: '#7a6d8a' }}>OWASP: <span style={{ color: '#c4b5fd' }}>{r.owasp}</span></span>
                    <span style={{ color: '#7a6d8a' }}>Effort: <span style={{ color: r.effort === 'Easy' ? '#7CFF9A' : r.effort === 'Moderate' ? '#F97316' : '#FF4D4D' }}>{r.effort}</span></span>
                    <span style={{ color: '#7a6d8a' }}>Impact: <span style={{ color: '#7CFF9A' }}>{r.impact} pts</span></span>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ─── 9. OWASP Mapping ────────────────────────────────────────────── */
function OwasMapping({ data }) {
  const mappings = useMemo(() => {
    const m = [];
    const missing = data?.security_headers?.missing || [];

    if (data?.csp?.strength !== 'strong') m.push({ id: 'A03', title: 'Injection', severity: data?.csp?.strength === 'missing' ? 'high' : 'medium', finding: data?.csp?.strength === 'missing' ? 'CSP missing — XSS risk' : 'Weak CSP configuration' });
    if (missing.find((h) => h.header === 'Strict-Transport-Security')) m.push({ id: 'A05', title: 'Security Misconfiguration', severity: 'high', finding: 'HSTS not enabled for HTTPS enforcement' });
    if (missing.find((h) => h.header === 'X-Frame-Options') && !data?.clickjacking?.protected) m.push({ id: 'A05', title: 'Security Misconfiguration', severity: 'medium', finding: 'Clickjacking protection missing' });
    if (data?.cors?.risk === 'high') m.push({ id: 'A01', title: 'Broken Access Control', severity: 'high', finding: `Permissive CORS: ${data.cors.allow_origin}` });
    if (data?.server) m.push({ id: 'A05', title: 'Security Misconfiguration', severity: 'medium', finding: `Server banner exposes: ${data.server}` });
    if (data?.dangerous_methods?.length) m.push({ id: 'A05', title: 'Security Misconfiguration', severity: 'high', finding: `Dangerous HTTP methods: ${data.dangerous_methods.join(', ')}` });
    if (data?.information_disclosure?.length) m.push({ id: 'A05', title: 'Security Misconfiguration', severity: data.information_disclosure.some((d) => d.severity === 'high' || d.severity === 'critical') ? 'high' : 'medium', finding: `${data.information_disclosure.length} information disclosure(s)` });
    const unsecuredCookies = (data?.cookies || []).filter((c) => !c.secure || !c.httponly);
    if (unsecuredCookies.length) m.push({ id: 'A02', title: 'Cryptographic Failures', severity: 'medium', finding: `${unsecuredCookies.length} cookie(s) missing Secure/HttpOnly flags` });

    if (missing.length === 0 && m.length === 0) m.push({ id: '—', title: 'All Clear', severity: 'low', finding: 'No OWASP Top 10 findings detected.' });
    return m;
  }, [data]);

  return (
    <SectionCard title="OWASP Top 10 Mapping" icon={ShieldAlert}>
      <div className="flex flex-col gap-1.5">
        {mappings.map((m) => {
          const sc = severityColor(m.severity);
          return (
            <div key={m.id + m.title} className="flex items-center gap-2.5 rounded-lg px-3 py-2 border" style={{ borderColor: `${sc.border}`, background: `${sc.bg}` }}>
              <span className="text-[10px] font-bold font-mono shrink-0 px-2 py-0.5 rounded" style={{ background: `${sc.text}22`, color: sc.text, border: `1px solid ${sc.text}44` }}>{m.id}</span>
              <div className="flex-1 min-w-0">
                <div className="text-[11px] font-semibold" style={{ color: '#e9d5ff' }}>{m.title}</div>
                <div className="text-[10px]" style={{ color: '#c4b5fd' }}>{m.finding}</div>
              </div>
              <span className="text-[9px] font-bold uppercase shrink-0" style={{ color: sc.text }}>{m.severity}</span>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ─── 10. MITRE ATT&CK Mapping ────────────────────────────────────── */
function MitreAttackMapping({ data }) {
  const mappings = useMemo(() => {
    const m = [];
    const missing = data?.security_headers?.missing || [];

    if (missing.find((h) => h.header === 'Content-Security-Policy')) m.push({ id: 'T1190', name: 'Exploit Public-Facing Application', technique: 'Drive-by Compromise / XSS', desc: 'Weak or missing CSP enables XSS and script injection attacks.' });
    if (data?.server) m.push({ id: 'T1592', name: 'Gather Victim Host Information', technique: 'Fingerprinting', desc: `Server banner exposes: ${data.server}.` });
    if (data?.information_disclosure?.length) m.push({ id: 'T1592', name: 'Gather Victim Host Information', technique: 'Information Disclosure', desc: `${data.information_disclosure.length} headers leak implementation details.` });
    if (data?.cors?.risk === 'high') m.push({ id: 'T1046', name: 'Network Service Discovery', technique: 'CORS Probing', desc: 'Permissive CORS policy allows cross-origin probing by malicious origins.' });
    if (!data?.clickjacking?.protected) m.push({ id: 'T1189', name: 'Drive-by Compromise', technique: 'Clickjacking', desc: 'Missing X-Frame-Options enables clickjacking attacks.' });
    if (data?.dangerous_methods?.length) m.push({ id: 'T1505', name: 'Server Software Component', technique: 'Method Abuse', desc: `Dangerous methods: ${data.dangerous_methods.join(', ')}.` });

    return m;
  }, [data]);

  if (!mappings.length) return null;

  return (
    <SectionCard title="MITRE ATT&CK Mapping" icon={Search}>
      <div className="flex flex-col gap-1.5">
        {mappings.map((m) => (
          <div key={m.id} className="rounded-lg px-3 py-2 border" style={{ borderColor: 'rgba(124,58,237,0.1)', background: 'rgba(13,7,24,0.4)' }}>
            <div className="flex items-center gap-2 mb-0.5">
              <span className="text-[10px] font-bold font-mono text-[#22d3ee]">{m.id}</span>
              <span className="text-[11px]" style={{ color: '#e9d5ff' }}>{m.name}</span>
            </div>
            <div className="text-[10px]" style={{ color: '#c4b5fd' }}>{m.technique}</div>
            <div className="text-[10px] mt-0.5" style={{ color: '#7a6d8a' }}>{m.desc}</div>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

/* ─── 11. Compliance Dashboard ────────────────────────────────────── */
function ComplianceDashboard({ data }) {
  const standards = useMemo(() => {
    const c = data?.compliance || {};
    const owasp = c.owasp_secure_headers || { passed: 0, total: 6, score: 0 };
    const mozilla = c.mozilla_baseline || { passed: 0, total: 4, score: 0 };
    const mozillaScore = mozilla.total ? Math.round((mozilla.passed / mozilla.total) * 100) : mozilla.score || 0;
    const present = data?.security_headers?.present || [];

    const pciHeaders = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy'];
    const pciPassed = pciHeaders.filter((h) => present.find((p) => p.header === h)).length;
    const pciScore = Math.round((pciPassed / pciHeaders.length) * 100);

    const nistHeaders = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy'];
    const nistPassed = nistHeaders.filter((h) => present.find((p) => p.header === h)).length;
    const nistScore = Math.round((nistPassed / nistHeaders.length) * 100);

    const cisHeaders = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy', 'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy'];
    const cisPassed = cisHeaders.filter((h) => present.find((p) => p.header === h)).length;
    const cisScore = Math.round((cisPassed / cisHeaders.length) * 100);

    return [
      { name: 'OWASP Secure Headers', score: owasp.score || Math.round((owasp.passed / (owasp.total || 6)) * 100), passed: owasp.passed, total: owasp.total || 6 },
      { name: 'Mozilla Observatory', score: mozillaScore, passed: mozilla.passed, total: mozilla.total || 4 },
      { name: 'PCI DSS 6.5/12.4', score: pciScore, passed: pciPassed, total: pciHeaders.length },
      { name: 'NIST SP 800-53', score: nistScore, passed: nistPassed, total: nistHeaders.length },
      { name: 'CIS Controls 4.1', score: cisScore, passed: cisPassed, total: cisHeaders.length },
    ];
  }, [data]);

  const overall = Math.round(standards.reduce((s, st) => s + st.score, 0) / standards.length);

  return (
    <SectionCard title="Compliance Dashboard" icon={ListChecks}>
      <div className="flex items-center gap-3 mb-4">
        <div className="w-[60px] h-[60px] rounded-xl grid place-items-center shrink-0" style={{ background: `radial-gradient(circle at 35% 30%, ${scoreColor(overall)}22, transparent 70%), ${scoreColor(overall)}12`, border: `2px solid ${scoreColor(overall)}33` }}>
          <span className="text-[22px] font-bold font-mono" style={{ color: scoreColor(overall) }}>{overall}</span>
        </div>
        <div className="text-[11px]" style={{ color: '#7a6d8a' }}>Average compliance across industry standards</div>
      </div>
      <div className="grid grid-cols-1 gap-2">
        {standards.map((st) => {
          const sc = scoreColor(st.score);
          return (
            <div key={st.name} className="rounded-lg px-3 py-2 border" style={{ borderColor: 'rgba(124,58,237,0.1)', background: 'rgba(13,7,24,0.4)' }}>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] font-semibold" style={{ color: '#c4b5fd' }}>{st.name}</span>
                <span className="text-[10px] font-mono" style={{ color: sc }}>{st.score}%</span>
              </div>
              <div className="h-1.5 rounded-full" style={{ background: 'rgba(124,58,237,0.12)' }}>
                <div className="h-full rounded-full transition-all" style={{ width: `${st.score}%`, background: `linear-gradient(90deg, ${sc}66, ${sc})` }} />
              </div>
              <div className="text-[9px] mt-0.5" style={{ color: '#5a4d72' }}>{st.passed}/{st.total} controls satisfied</div>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ─── 12. AI Recommendations ──────────────────────────────────────── */
function AiRecommendations({ data }) {
  const score = data?.security_score ?? 50;
  const recs = useMemo(() => {
    const items = [];
    const missing = data?.security_headers?.missing || [];

    missing.forEach((h) => {
      const sev = (h.severity || '').toLowerCase();
      const impact = sev === 'critical' ? 25 : sev === 'high' ? 18 : sev === 'medium' ? 12 : 5;
      items.push({
        title: `Implement ${h.header}`,
        improvement: `+${Math.min(impact, 100 - score)}`,
        riskReduction: sev === 'critical' || sev === 'high' ? 'High' : 'Medium',
        difficulty: h.header === 'Content-Security-Policy' ? 'Complex' : 'Easy',
      });
    });

    if (data?.cors?.risk === 'high') items.push({ title: 'Restrict CORS origins', improvement: '+15', riskReduction: 'High', difficulty: 'Easy' });
    if (data?.information_disclosure?.length) items.push({ title: 'Remove information-disclosing headers', improvement: `+${Math.min(data.information_disclosure.length * 5, 20)}`, riskReduction: 'Medium', difficulty: 'Easy' });

    return items.sort((a, b) => parseInt(b.improvement) - parseInt(a.improvement));
  }, [data, score]);

  if (!recs.length) return null;

  return (
    <SectionCard title="AI Recommendations" icon={Sparkles}>
      <div className="flex flex-col gap-2">
        {recs.slice(0, 4).map((r, i) => {
          const diffColor = r.difficulty === 'Easy' ? '#7CFF9A' : r.difficulty === 'Moderate' ? '#F97316' : '#FF4D4D';
          const riskColor = r.riskReduction === 'High' ? '#FF4D4D' : r.riskReduction === 'Medium' ? '#F97316' : '#94a3b8';
          return (
            <div key={i} className="flex items-center gap-3 rounded-lg px-3 py-2.5 border" style={{ borderColor: 'rgba(124,58,237,0.1)', background: 'rgba(13,7,24,0.4)' }}>
              <div className="w-5 h-5 rounded-full grid place-items-center text-[10px] font-bold shrink-0" style={{ background: `${scoreColor(score)}22`, color: scoreColor(score), border: `1px solid ${scoreColor(score)}44` }}>{i + 1}</div>
              <div className="flex-1 min-w-0">
                <div className="text-[12px] font-semibold" style={{ color: '#e9d5ff' }}>{r.title}</div>
                <div className="flex items-center gap-3 mt-0.5 text-[9px]">
                  <span style={{ color: '#7a6d8a' }}>Improvement: <span style={{ color: '#7CFF9A' }}>{r.improvement} pts</span></span>
                  <span style={{ color: '#7a6d8a' }}>Risk: <span style={{ color: riskColor }}>{r.riskReduction}</span></span>
                  <span style={{ color: '#7a6d8a' }}>Effort: <span style={{ color: diffColor }}>{r.difficulty}</span></span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </SectionCard>
  );
}

/* ─── 13. Ai Security Summary (enhanced) ──────────────────────────── */
function AiSecuritySummary({ data }) {
  const { lines, confidence } = useMemo(() => {
    if (data?.ai_summary) {
      const splitLines = data.ai_summary.split(/\.\s+/).filter(Boolean).map((s) => s.replace(/\.$/, '') + '.');
      return { lines: splitLines, confidence: { label: 'High', color: '#22d3ee' } };
    }

    const ls = [];
    const score = data?.security_score ?? (data?.risk_score != null ? 100 - data.risk_score : 50);
    const riskLevel = data?.risk_level || (score >= 70 ? 'Low' : score >= 40 ? 'Moderate' : 'High');
    const present = data?.security_headers?.present || [];
    const missing = data?.security_headers?.missing || [];

    ls.push(`Security Score: ${score}/100 — ${score >= 90 ? 'Excellent' : score >= 75 ? 'Good' : score >= 55 ? 'Moderate' : score >= 35 ? 'Weak' : 'Poor'} posture. Rating: ${ratingLetter(score)}.`);

    if (missing.length > 0) ls.push(`${missing.length} critical header${missing.length > 1 ? 's' : ''} missing: ${missing.map((m) => m.header).join(', ')}.`);
    if (present.length > 0) ls.push(`${present.length} security header${present.length > 1 ? 's' : ''} properly configured.`);

    const disclosures = data?.information_disclosure || [];
    if (disclosures.length > 0) {
      ls.push(`${disclosures.length} information disclosure${disclosures.length > 1 ? 's' : ''} detected: ${disclosures.map((d) => d.header).join(', ')}.`);
    } else {
      ls.push('No information disclosures detected — server fingerprinting surface is minimal.');
    }

    if (data?.cookies?.length) {
      const risky = data.cookies.filter((c) => c.risk !== 'low').length;
      ls.push(`Cookie security: ${data.cookies.length} cookie${data.cookies.length > 1 ? 's' : ''} set, ${risky} with security issue${risky !== 1 ? 's' : ''}.`);
    }

    if (data?.csp?.strength === 'strong') ls.push('Content-Security-Policy is well-configured with strong directives.');
    else if (data?.csp?.strength === 'moderate') ls.push('CSP is present but contains unsafe directives (unsafe-inline/unsafe-eval).');
    else ls.push('Content-Security-Policy is missing — XSS protection is significantly weakened.');

    if (data?.clickjacking?.protected) ls.push('Clickjacking protection is active via X-Frame-Options or CSP frame-ancestors.');
    else ls.push('Clickjacking protection is missing — users could be tricked into interacting with your site in hidden iframes.');

    if (data?.cdn) ls.push(`Infrastructure protected by ${data.cdn}${data?.waf ? ` with ${data.waf} WAF` : ''}.`);
    if (data?.cloud_provider) ls.push(`Hosted on ${data.cloud_provider}.`);

    ls.push(`Overall risk: ${riskLevel}. ${score < 70 ? 'Priority actions: implement missing security headers and restrict CORS/CSP policies.' : 'Continue monitoring for configuration drift and emerging vulnerabilities.'}`);

    const dataCompleteness = score != null ? 'High' : 'Medium';
    return { lines: ls, confidence: { label: dataCompleteness, color: dataCompleteness === 'High' ? '#22d3ee' : '#F97316' } };
  }, [data]);

  return (
    <div className="rounded-[10px] border p-[18px_20px] relative overflow-hidden transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]" style={{ borderColor: 'rgba(124,58,237,0.3)', background: 'linear-gradient(135deg, rgba(52,20,80,0.72) 0%, rgba(28,12,50,0.8) 100%)' }}>
      <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(167,139,250,0.55), transparent)' }} />
      <div className="flex items-center gap-2.5 mb-3.5">
        <div className="w-7 h-7 rounded-lg grid place-items-center shrink-0" style={{ background: 'rgba(124,58,237,0.25)', border: '1px solid rgba(167,139,250,0.35)' }}>
          <Sparkles className="w-4 h-4" style={{ color: '#c4b5fd' }} />
        </div>
        <span className="text-[13px] font-bold uppercase tracking-wide" style={{ color: '#c4b5fd' }}>AI Security Summary</span>
        <span className="ml-auto inline-flex items-center rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-wider" style={{ background: `${confidence.color}18`, color: confidence.color, border: `1px solid ${confidence.color}33` }}>
          {confidence.label} Confidence
        </span>
      </div>
      <ul className="m-0 p-0 list-none flex flex-col gap-[7px]">
        {lines.map((line, i) => (
          <li key={i} className="flex items-start gap-2 text-[12px] leading-[1.65]" style={{ color: '#c4b5fd' }}>
            <span className="w-[5px] h-[5px] rounded-full shrink-0 mt-[6px]" style={{ background: 'rgba(167,139,250,0.6)' }} />
            <span>{line}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ─── 14. Header Relationships (enhanced) ─────────────────────────── */
function HeaderRelationships({ data }) {
  const chain = useMemo(() => {
    const links = [];
    const headerNames = new Set(Object.keys(data?.headers || {}).map((k) => k.toLowerCase()));
    const has = (name) => headerNames.has(name.toLowerCase());

    links.push({ id: 'https', label: 'HTTPS', type: 'foundation', status: data?.protocol?.startsWith('HTTP/') ? 'configured' : 'unknown', icon: Lock });
    links.push({ id: 'hsts', label: 'Strict-Transport-Security', type: 'transport', status: has('strict-transport-security') ? 'configured' : 'missing', icon: ShieldCheck, depends: 'https' });
    links.push({ id: 'csp', label: 'Content-Security-Policy', type: 'defense', status: has('content-security-policy') ? 'configured' : 'missing', icon: ShieldCheck, depends: 'https' });
    links.push({ id: 'xfo', label: 'Frame Protection (X-Frame-Options)', type: 'defense', status: data?.clickjacking?.protected ? 'configured' : 'missing', icon: ShieldAlert, depends: 'csp' });
    links.push({ id: 'coop', label: 'Cross-Origin-Opener-Policy', type: 'isolation', status: has('cross-origin-opener-policy') ? 'configured' : 'missing', icon: Network, depends: 'csp' });
    links.push({ id: 'coep', label: 'Cross-Origin-Embedder-Policy', type: 'isolation', status: has('cross-origin-embedder-policy') ? 'configured' : 'missing', icon: Network, depends: 'coop' });
    links.push({ id: 'corp', label: 'Cross-Origin-Resource-Policy', type: 'isolation', status: has('cross-origin-resource-policy') ? 'configured' : 'missing', icon: Network, depends: 'coep' });

    return links;
  }, [data]);

  const missingLinks = chain.filter((l) => l.status === 'missing');

  return (
    <SectionCard title="Header Relationship Graph" icon={Link2}>
      <div className="flex flex-col items-stretch gap-0">
        {chain.map((l, i) => {
          const Icon = l.icon;
          const statusColor = l.status === 'configured' ? '#7CFF9A' : '#FF4D4D';
          return (
            <div key={l.id} className="flex flex-col items-center">
              <div className="w-full rounded-lg px-3.5 py-2.5 flex items-center gap-3 border transition duration-150 hover:-translate-y-px" style={{
                borderColor: l.status === 'configured' ? 'rgba(124,255,154,0.25)' : 'rgba(255,77,77,0.25)',
                background: l.status === 'configured' ? 'rgba(124,255,154,0.06)' : 'rgba(255,77,77,0.06)',
                cursor: 'default',
              }}>
                <Icon className="w-4 h-4 shrink-0" style={{ color: statusColor }} />
                <span className="text-[12px] flex-1" style={{ color: '#e9d5ff' }}>{l.label}</span>
                <span className="text-[9px] font-bold uppercase tracking-wider" style={{ color: statusColor }}>
                  {l.status}
                </span>
              </div>
              {i < chain.length - 1 && (
                <div className="flex flex-col items-center py-0.5">
                  <ArrowRight className="w-3 h-3" style={{ color: '#5a4d72' }} />
                  {chain[i + 1].depends === l.id && l.status === 'missing' && (
                    <span className="text-[8px] mt-0.5 text-center" style={{ color: '#FF4D4D' }}>broken link</span>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
      {missingLinks.length > 0 && (
        <div className="mt-3 p-3 rounded-lg text-[11px] leading-4" style={{ background: 'rgba(255,77,77,0.06)', border: '1px solid rgba(255,77,77,0.2)', color: '#F97316' }}>
          {missingLinks.length} header{missingLinks.length !== 1 ? 's' : ''} missing — the protection chain is incomplete. Each missing header reduces the overall depth-of-defense.
        </div>
      )}
    </SectionCard>
  );
}

/* ─── 15. Export & Share ──────────────────────────────────────────── */
function ExportSection({ onExportPdf, onExportJson, onExportCsv, onShare }) {
  return (
    <div className="rounded-[10px] border p-[18px_20px] flex flex-wrap items-center justify-between gap-4 transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]" style={{ borderColor: 'rgba(124,58,237,0.18)', background: 'rgba(13,7,24,0.55)' }}>
      <div>
        <h3 className="text-[13px] font-bold uppercase tracking-wide m-0 mb-0.5" style={{ color: '#c4b5fd' }}>Export &amp; Share</h3>
        <p className="text-[11px] m-0" style={{ color: '#7a6d8a' }}>Download or share your scan report.</p>
      </div>
      <div className="flex flex-wrap gap-2">
        <button onClick={onExportPdf} className="inline-flex items-center gap-[7px] px-4 py-2.5 rounded-lg text-[12px] font-medium cursor-pointer whitespace-nowrap transition duration-150 hover:-translate-y-px" style={{ color: '#c4b5fd', background: 'rgba(124,58,237,0.12)', border: '1px solid rgba(167,139,250,0.28)' }}>
          <FileText className="w-4 h-4" /> Export PDF
        </button>
        <button onClick={onExportJson} className="inline-flex items-center gap-[7px] px-4 py-2.5 rounded-lg text-[12px] font-medium cursor-pointer whitespace-nowrap transition duration-150 hover:-translate-y-px" style={{ color: '#c4b5fd', background: 'rgba(124,58,237,0.12)', border: '1px solid rgba(167,139,250,0.28)' }}>
          <FileJson className="w-4 h-4" /> Export JSON
        </button>
        <button onClick={onExportCsv} className="inline-flex items-center gap-[7px] px-4 py-2.5 rounded-lg text-[12px] font-medium cursor-pointer whitespace-nowrap transition duration-150 hover:-translate-y-px" style={{ color: '#c4b5fd', background: 'rgba(124,58,237,0.12)', border: '1px solid rgba(167,139,250,0.28)' }}>
          <Download className="w-4 h-4" /> Export CSV
        </button>
        <button onClick={onShare} className="inline-flex items-center gap-[7px] px-4 py-2.5 rounded-lg text-[12px] font-medium cursor-pointer whitespace-nowrap transition duration-150 hover:-translate-y-px" style={{ color: '#e9d5ff', background: 'rgba(124,58,237,0.2)', border: '1px solid rgba(167,139,250,0.4)' }}>
          <Share2 className="w-4 h-4" /> Share Report
        </button>
      </div>
    </div>
  );
}

/* ─── Main ────────────────────────────────────────────────────────── */
export default function HttpHeadersMonitoringPanel({
  data,
  onExportPdf,
  onExportJson,
  onExportCsv,
  onShare,
}) {
  return (
    <div className="flex flex-col gap-4">
      {/* Row 0: Quick Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
        {[
          { label: 'Security Score', value: data?.security_score != null ? `${data.security_score}/100` : '\u2014', color: scoreColor(data?.security_score ?? 50), icon: Shield },
          { label: 'Risk Level', value: data?.risk_level || '\u2014', color: data?.risk_level === 'Low' ? '#7CFF9A' : data?.risk_level === 'Medium' ? '#F97316' : '#FF4D4D', icon: ShieldAlert },
          { label: 'Headers Present', value: `${data?.security_headers?.present?.length || 0}/${(data?.security_headers?.present?.length || 0) + (data?.security_headers?.missing?.length || 0)}`, icon: CheckCircle2, color: '#22d3ee' },
          { label: 'Missing', value: data?.security_headers?.missing?.length ?? 0, icon: XCircle, color: (data?.security_headers?.missing?.length || 0) > 0 ? '#FF4D4D' : '#7CFF9A' },
          { label: 'Disclosures', value: data?.information_disclosure?.length || 0, icon: Eye, color: (data?.information_disclosure?.length || 0) > 0 ? '#F97316' : '#7CFF9A' },
          { label: 'Technologies', value: data?.technologies?.length || 0, icon: Cpu, color: '#c4b5fd' },
        ].map((s) => (
          <div key={s.label} className="flex flex-col gap-1 p-2.5 rounded-[10px] border transition hover:-translate-y-0.5 hover:border-[#ba9cff]/45 hover:shadow-[0_16px_42px_rgba(0,0,0,0.22)]" style={{ borderColor: 'rgba(124,58,237,0.2)', background: 'rgba(13,7,24,0.65)' }}>
            <div className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-widest" style={{ color: '#7a6d8a' }}>
              <s.icon className="w-3 h-3" />
              {s.label}
            </div>
            <div className="text-[20px] font-bold font-mono leading-tight" style={{ color: s.color || '#e9d5ff' }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Row 1: Executive Summary (full width) */}
      <ExecutiveSummary data={data} />

      {/* Row 2: Score Card + Risk Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <SecurityScoreCard data={data} />
        <RiskBreakdown data={data} />
      </div>

      {/* Row 3: Info Disclosure + Missing Headers */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <InfoDisclosureAnalysis data={data} />
        <MissingSecurityHeaders data={data} />
      </div>

      {/* Row 4: Existing Headers + Attack Surface */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ExistingSecurityHeaders data={data} />
        <AttackSurfaceAnalysis data={data} />
      </div>

      {/* Row 5: Recommendations + OWASP */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <SecurityRecommendations data={data} />
        <OwasMapping data={data} />
      </div>

      {/* Row 6: Compliance + MITRE */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ComplianceDashboard data={data} />
        <MitreAttackMapping data={data} />
      </div>

      {/* Row 7: Header Relationship Graph */}
      <HeaderRelationships data={data} />

      {/* Row 8: AI Recommendations */}
      <AiRecommendations data={data} />

      {/* Row 9: AI Security Summary */}
      <AiSecuritySummary data={data} />

      {/* Row 10: Export & Share */}
      <ExportSection
        onExportPdf={onExportPdf}
        onExportJson={onExportJson}
        onExportCsv={onExportCsv}
        onShare={onShare}
      />
    </div>
  );
}
