import { useState, useEffect, useRef } from 'react';
import { useGetToken } from '../utils/useGetToken';
import { apiPostAndPoll } from '../utils/apiClient';
import {
  Activity,
  ArrowRight,
  Bug,
  CheckCircle2,
  CircleDot,
  Database,
  FileText,
  Globe2,
  Radio,
  ScanLine,
  Server,
  Share2,
  ShieldCheck,
  Tags,
  X,
} from 'lucide-react';
import {
  parsePortScanResponse,
  collectDetectedTechnologies,
  hasBannerData,
  bannerPreview,
  riskBadgeProps,
} from '../utils/portScan';
import { downloadFile, exportBrandedPdf, shareOrCopy } from '../utils/exportUtils';

const RISK_COLORS = {
  critical: { bg: 'rgba(255,77,77,0.12)', text: '#FF4D4D', border: 'rgba(255,77,77,0.25)' },
  high:     { bg: 'rgba(249,115,22,0.12)', text: '#F97316', border: 'rgba(249,115,22,0.25)' },
  medium:   { bg: 'rgba(249,115,22,0.12)',  text: '#F97316', border: 'rgba(249,115,22,0.25)' },
  low:      { bg: 'rgba(124,255,154,0.12)',  text: '#7CFF9A', border: 'rgba(124,255,154,0.25)' },
  open:     { bg: 'rgba(124,58,237,0.12)', text: '#a78bfa', border: 'rgba(124,58,237,0.3)' },
};

function RiskBadge({ label = 'medium', color = 'medium', title }) {
  const c = RISK_COLORS[color] || RISK_COLORS.medium;
  return (
    <span
      className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded-full"
      style={{ background: c.bg, color: c.text, border: `1px solid ${c.border}` }}
      title={title}
    >
      {label}
    </span>
  );
}

function BannerSection({ label, text }) {
  if (!text) return null;
  return (
    <div>
      <div className="banner-section-label">{label}</div>
      <pre className="banner-section-pre">{text}</pre>
    </div>
  );
}

function BannerModal({ row, target, onClose }) {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (!row) return null;

  return (
    <div
      className="banner-modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="banner-modal-title"
      onClick={onClose}
    >
      <div className="banner-modal" onClick={(e) => e.stopPropagation()}>
        <div className="banner-modal-header">
          <div>
            <h2
              id="banner-modal-title"
              className="text-sm font-semibold"
              style={{ color: '#e9d5ff' }}
            >
              Port {row.port} — {row.service}
            </h2>
            <p className="text-[10px] font-mono mt-0.5" style={{ color: '#8b7ec8' }}>
              {target}
              {row.version ? ` · ${row.version}` : ''}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="clear-input-btn"
            style={{ position: 'static', transform: 'none' }}
            aria-label="Close banner"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="banner-modal-body">
          <BannerSection label="Welcome message" text={row.welcome_message} />
          <BannerSection label="Server response" text={row.server_response} />
          <BannerSection label="Raw banner" text={row.raw_banner} />
          {row.technologies?.length > 0 && (
            <div>
              <div className="banner-section-label">Detected technologies</div>
              <div className="detected-tech-chips">
                {row.technologies.map((name) => (
                  <TechChip key={name} name={name} />
                ))}
              </div>
            </div>
          )}
          {!hasBannerData(row) && (
            <p className="text-xs" style={{ color: '#6b5fa0' }}>
              No banner data was captured for this port.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function ServiceTooltip({ row }) {
  const name = row.service_name || row.service || 'Unknown';
  const title = `Port ${row.port} (${name})`;
  return (
    <span className="port-service-tooltip-wrap">
      <span className="text-sm font-medium truncate block" style={{ color: '#c4b5fd' }}>
        {row.service || '—'}
      </span>
      <div className="port-service-tooltip" role="tooltip">
        <div className="port-service-tooltip-title">{title}</div>
        <div className="port-service-tooltip-label">What it does</div>
        <p className="port-service-tooltip-text">{row.service_description}</p>
        <div className="port-service-tooltip-label">Security concern</div>
        <p className="port-service-tooltip-text">{row.service_security_concern}</p>
      </div>
    </span>
  );
}

function TechChip({ name }) {
  return <span className="tech-chip">{name}</span>;
}

function scoreColor(score) {
  if (score >= 85) return '#7CFF9A';
  if (score >= 70) return '#F97316';
  if (score >= 50) return '#F97316';
  return '#FF4D4D';
}

function surfaceColor(level) {
  const normalized = (level || '').toUpperCase();
  if (normalized === 'LOW') return '#7CFF9A';
  if (normalized === 'MEDIUM') return '#F97316';
  if (normalized === 'HIGH') return '#F97316';
  if (normalized === 'CRITICAL') return '#FF4D4D';
  return '#a78bfa';
}

function combineAttackSurface(current, incoming) {
  if (!incoming) return current;
  const servicesByKey = new Map();
  [...(current?.publiclyExposedServices || []), ...(incoming.publiclyExposedServices || [])]
    .forEach((entry) => {
      servicesByKey.set(`${entry.port}-${entry.service}`, entry);
    });
  const factors = [...(current?.factors || []), ...(incoming.factors || [])];
  const score = Math.min(100, Math.max(Number(current?.score || 0), Number(incoming.score || 0)));
  const levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const currentLevel = (current?.level || 'LOW').toUpperCase();
  const incomingLevel = (incoming.level || 'LOW').toUpperCase();
  const level = levels[Math.max(levels.indexOf(currentLevel), levels.indexOf(incomingLevel), 0)];

  return {
    level,
    score,
    publiclyExposedServices: Array.from(servicesByKey.values()),
    factors: factors.slice(0, 12),
    summary: `${level} attack surface based on ${servicesByKey.size} exposed service(s).`,
  };
}

function reputationColor(reputation) {
  const value = (reputation || '').toLowerCase();
  if (value === 'malicious') return '#FF4D4D';
  if (value === 'suspicious') return '#F97316';
  if (value === 'clean') return '#7CFF9A';
  if (value === 'private/local') return '#a78bfa';
  return '#F97316';
}

function combineThreatIntelligence(current, incoming) {
  if (!incoming) return current;
  if (!current) return incoming;
  const rank = { Unknown: 0, Clean: 1, 'Private/Local': 1, Suspicious: 2, Malicious: 3 };
  const currentRank = rank[current.reputation] ?? 0;
  const incomingRank = rank[incoming.reputation] ?? 0;
  return incomingRank > currentRank ? incoming : current;
}

function ExposureSeverityFocusPanel({ rows, stats, riskCounts }) {
  const exposures = (rows || [])
    .filter((row) => row.exposure_severity?.finding)
    .sort((a, b) => Number(b.exposure_severity.score || 0) - Number(a.exposure_severity.score || 0));
  const primary = exposures[0];
  const summary = stats?.exposureSummary || {};
  const critical = summary.critical ?? riskCounts.critical ?? 0;
  const high = summary.high ?? riskCounts.high ?? 0;
  const medium = summary.medium ?? riskCounts.medium ?? 0;
  const low = summary.low ?? riskCounts.low ?? 0;
  const score = summary.highestScore || primary?.exposure_severity?.score || null;
  const severity = summary.highestSeverity || primary?.exposure_severity?.severity || null;
  const publicExposure = summary.publicExposure ?? Boolean((rows || []).length);
  const finding = summary.highestFinding
    || primary?.exposure_severity?.finding
    || null;

  return (
    <div className="min-h-[300px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <div className="mb-3 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]">
            <CircleDot className="h-4 w-4" />
            <span>Exposure Severity Engine</span>
          </div>
          <div className="text-[18px] font-semibold text-[#FF4D4D]">{score == null ? '—' : `${score}/100`}</div>
        </div>
        <RiskBadge label={severity || 'pending'} color={severity || 'medium'} />
      </div>
      <p className="min-h-[42px] text-[12px] leading-relaxed text-[#b7abc5]">{finding || '—'}</p>
      <div className="mt-5 flex items-center justify-between border-t border-[#554365]/70 pt-4 text-[12px] text-[#d8cce6]">
        <span>Public exposure</span>
        <span className={publicExposure ? 'text-[#7CFF9A]' : 'text-[#92859d]'}>{publicExposure ? 'Yes' : 'No'}</span>
      </div>
      <div className="mt-20 grid grid-cols-4 gap-4 text-center">
        {[
          ['critical', critical, '#FF4D4D'],
          ['high', high, '#F97316'],
          ['medium', medium, '#F97316'],
          ['low', low, '#7CFF9A'],
        ].map(([label, value, color]) => (
          <div key={label}>
            <div className="mb-2 text-[11px]" style={{ color }}>{label}</div>
            <div className="text-2xl font-light text-[#f4eef7]">{value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function RecommendedActionsFocusPanel({ rows }) {
  const recommendations = (rows || [])
    .filter((row) => row.recommendation)
    .slice(0, 2);

  return (
    <div className="min-h-[300px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
      <div className="mb-6 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]">
        <CircleDot className="h-4 w-4" />
        <span>Recommended Actions</span>
      </div>
      <div className="space-y-4">
        {recommendations.length === 0 && (
          <div className="rounded-lg border border-[#554365]/70 bg-[#1b0d2b]/80 p-5 text-[12px] text-[#b7abc5]">
            —
          </div>
        )}
        {recommendations.map((row) => {
          const priority = row.recommendation_priority;
          return (
            <div key={`focus-rec-${row.port}`} className="grid grid-cols-[44px_minmax(0,1fr)] gap-4 rounded-lg border border-[#743248]/80 bg-[#351222]/72 p-5">
              <div className="grid h-10 w-10 place-items-center rounded-lg bg-[#4a1730] text-[#FF4D4D]">
                <Bug className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <div className="text-[13px] font-semibold text-[#FF4D4D]">
                    Port {row.port} ({row.service || 'Unknown'})
                  </div>
                  {priority ? <RiskBadge label={priority} color={priority} /> : <span className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded-full border border-[#7c3aed]/30 bg-[#7c3aed]/10 text-[#a78bfa]">AI</span>}
                </div>
                <p className="text-[11px] leading-relaxed text-[#d8cce6]">
                  {row.recommendation_reason || '—'}
                </p>
                <p className="mt-2 text-[11px] leading-relaxed text-[#b7abc5]">
                  {row.recommendation}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function VisibilityFocusPanel({ rows, stats, riskCounts }) {
  const visibleRows = rows || [];
  const primary = visibleRows.find((row) => row.risk_level === 'critical' || row.risk_level === 'high') || visibleRows[0];
  const serviceName = primary?.service || '—';
  const versionName = primary?.version || primary?.fingerprint?.detected || '—';
  const intel = stats?.threatIntelligence || {};
  const misconfig = stats?.misconfigurationSummary || {};
  const intelReturned = Boolean(intel.ip || intel.summary || intel.sources?.length || intel.reputation);
  const criticalCves = visibleRows.reduce((sum, row) => sum + Number(row.cve_critical_count || 0), 0);
  const highCves = visibleRows.reduce((sum, row) => sum + Number(row.cve_high_count || 0), 0);
  const exploitRows = visibleRows.filter((row) => row.exploit_availability?.publicExploitAvailable != null);
  const publicExploits = exploitRows.length
    ? (visibleRows.some((row) => row.exploit_availability?.publicExploitAvailable) ? 'Yes' : 'No')
    : '—';
  const surfaceLevel = stats?.attackSurface?.level || (riskCounts.critical ? 'CRITICAL' : riskCounts.high ? 'HIGH' : visibleRows.length ? 'MEDIUM' : 'LOW');
  const missingHeaders = visibleRows.find((row) => row.misconfigurations?.length)?.misconfigurations?.[0];
  const cveRow = visibleRows.find((row) => row.max_cvss_score != null || row.max_cvss_cve);
  const targetIp = intel.ip || stats?.threatIntelligence?.ip || '—';

  return (
    <>
      <div className="min-h-[260px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7 xl:col-span-2">
        <div className="mb-8 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]">
          <CircleDot className="h-4 w-4" />
          <span>Attack Surface Visualisation</span>
        </div>
        <div className="grid grid-cols-[1fr_32px_1fr_32px_1fr] items-center gap-4 text-center">
          <div className="flex flex-col items-center gap-3">
            <Globe2 className="h-12 w-12 text-[#e9d5ff]" />
            <div className="text-sm font-semibold text-[#f4eef7]">{targetIp}</div>
            <div className="text-[10px] text-[#92859d]">Resolved IP</div>
          </div>
          <ArrowRight className="h-5 w-5 text-[#b79aff]" />
          <div className="flex flex-col items-center gap-3">
            <Server className="h-12 w-12 text-[#e9d5ff]" />
            <div className="text-sm font-semibold text-[#f4eef7]">{serviceName}</div>
            <div className="text-[10px] text-[#92859d]">{versionName}</div>
          </div>
          <ArrowRight className="h-5 w-5 text-[#b79aff]" />
          <div className="flex flex-col items-center gap-3">
            <ShieldCheck className="h-12 w-12 text-[#e9d5ff]" />
            <div className="text-sm font-semibold text-[#f4eef7]">{primary ? `Port ${primary.port}` : '—'}</div>
            <div className="text-[10px] text-[#92859d]">{surfaceLevel}</div>
          </div>
        </div>
        <div className="mt-8 rounded-lg border border-[#4f3b63] bg-[#2a1a3d] p-4">
          <div className="mb-2 flex items-center gap-3">
            <span className="grid h-6 w-6 place-items-center rounded-full bg-[#a78bfa] text-[#24183b]">i</span>
            <RiskBadge label={surfaceLevel.toLowerCase()} color={surfaceLevel.toLowerCase()} />
          </div>
          <p className="text-[11px] leading-relaxed text-[#92859d]">
            {primary?.risk_reason || stats?.attackSurface?.summary || '—'}
          </p>
        </div>
      </div>

      <div className="min-h-[260px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
        <div className="mb-6 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]">
          <CircleDot className="h-4 w-4" />
          <span>Vulnerability Signals</span>
        </div>
        {[
          ['Critical CVEs', criticalCves],
          ['High CVEs', highCves],
          ['Public Exploits', publicExploits],
        ].map(([label, value]) => (
          <div key={label} className="flex items-center justify-between border-b border-[#554365]/70 py-3 text-[12px] text-[#d8cce6] last:border-b-0">
            <span>{label}</span>
            <span className={value === 'Yes' || Number(value) > 0 ? 'text-[#FF4D4D]' : 'text-[#92859d]'}>{value}</span>
          </div>
        ))}
        <div className="mt-7 rounded-lg border border-[#4f3b63] bg-[#2a1a3d] p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[12px] font-semibold text-[#f4eef7]">{cveRow?.max_cvss_cve || '—'}</span>
            <RiskBadge label={cveRow?.max_cvss_severity || 'pending'} color={(cveRow?.max_cvss_severity || 'medium').toLowerCase()} />
          </div>
          <p className="text-[11px] text-[#92859d]">
            {cveRow?.max_cvss_score ? `CVSS ${cveRow.max_cvss_score}` : '—'}
          </p>
        </div>
      </div>

      <div className="min-h-[260px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]">
            <CircleDot className="h-4 w-4" />
            <span>Threat Intelligence</span>
          </div>
          <RiskBadge label={intelReturned ? `IP reputation: ${intel.reputation || '—'}` : 'pending'} color={(intel.reputation || '').toLowerCase() === 'clean' ? 'low' : 'medium'} />
        </div>
        <p className="mb-5 text-[11px] leading-relaxed text-[#92859d]">
          {intel.summary || '—'}
        </p>
        {[
          ['IP', intel.ip || '—'],
          ['Reported', `${intel.reportedTimes || 0} time(s)`],
          ['Abuse Score', intel.abuseConfidenceScore ?? '—'],
          ['Known Botnet', intelReturned ? (intel.knownBotnet ? 'Yes' : 'No') : '—'],
        ].map(([label, value]) => (
          <div key={label} className="flex items-center justify-between border-b border-[#554365]/70 py-2.5 text-[12px] text-[#d8cce6] last:border-b-0">
            <span>{label}</span>
            <span>{value}</span>
          </div>
        ))}
        <div className="mt-4 text-right text-[10px] text-[#b79aff]">
          Sources {intel.sources?.length ? intel.sources.join(', ') : '—'}
        </div>
      </div>

      <div className="min-h-[260px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]">
            <CircleDot className="h-4 w-4" />
            <span>Attack Surface Analysis</span>
          </div>
          <RiskBadge label={surfaceLevel.toLowerCase()} color={surfaceLevel.toLowerCase()} />
        </div>
        <div className="space-y-4 text-[12px] leading-relaxed text-[#b7abc5]">
          <p>{primary ? `${primary.service || '—'} on port ${primary.port}: ${primary.risk_level || '—'} risk.` : '—'}</p>
          <p>{stats?.attackSurface?.summary || `${visibleRows.length} open service${visibleRows.length === 1 ? '' : 's'} detected.`}</p>
          <p>{primary?.risk_reason || '—'}</p>
        </div>
      </div>

      <div className="min-h-[260px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div className="flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]">
            <CircleDot className="h-4 w-4" />
            <span>Misconfiguration Detection</span>
          </div>
          <span className="text-[12px] text-[#d8cce6]">{misconfig.total || 0} finding{(misconfig.total || 0) === 1 ? '' : 's'}</span>
        </div>
        <div className="mb-6 grid grid-cols-4 gap-3 text-center">
          {[
            ['critical', misconfig.critical || 0, '#FF4D4D'],
            ['high', misconfig.high || 0, '#F97316'],
            ['medium', misconfig.medium || 0, '#F97316'],
            ['low', misconfig.low || 0, '#7CFF9A'],
          ].map(([label, value, color]) => (
            <div key={label}>
              <div className="mb-1 text-[10px]" style={{ color }}>{label}</div>
              <div className="text-2xl font-light text-[#f4eef7]">{value}</div>
            </div>
          ))}
        </div>
        <div className="rounded-lg border border-[#4f3b63] bg-[#2a1a3d] p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[12px] font-semibold text-[#f4eef7]">
              {missingHeaders ? `Port ${primary?.port || ''} (${primary?.service || '—'})` : '—'}
            </span>
            <RiskBadge label={missingHeaders?.severity || 'pending'} color={missingHeaders?.severity || 'medium'} />
          </div>
          <p className="text-[11px] leading-relaxed text-[#92859d]">
            {missingHeaders?.recommendation || '—'}
          </p>
        </div>
      </div>
    </>
  );
}

function AdversaryFocusPanel({ rows, stats }) {
  const surface = stats?.attackSurface || {};
  const services = surface.publiclyExposedServices || [];
  const primary = rows?.find((row) => row.risk_level === 'critical' || row.risk_level === 'high') || rows?.[0];
  return (
    <div className="min-h-[300px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
      <div className="mb-6 flex items-center gap-3 text-[12px] font-medium uppercase text-[#b79aff]">
        <CircleDot className="h-4 w-4" />
        <span>Adversary & Exploit Modeling</span>
      </div>
      <div className="flex items-center justify-between border-b border-[#554365]/70 pb-4 text-[12px] text-[#d8cce6]">
        <span>Attack surface</span>
        <span style={{ color: surface.level ? surfaceColor(surface.level) : '#92859d' }}>{surface.level || '—'}</span>
      </div>
      <p className="mt-5 min-h-[42px] text-[12px] leading-relaxed text-[#b7abc5]">
        {surface.summary || '—'}
      </p>
      <div className="mt-6 space-y-3">
        {(services.length ? services.slice(0, 3) : primary ? [{ port: primary.port, service: primary.service, riskLevel: primary.risk_level }] : []).map((entry) => (
          <div key={`adversary-${entry.port}-${entry.service}`} className="rounded-lg border border-[#4f3b63] bg-[#24183b]/70 p-4 text-[12px] text-[#d8cce6]">
            Port {entry.port} {entry.service || 'Unknown'} is reachable.
          </div>
        ))}
        {!services.length && !primary && (
          <div className="rounded-lg border border-[#554365]/70 bg-[#1b0d2b]/80 p-5 text-[12px] text-[#b7abc5]">
            —
          </div>
        )}
      </div>
    </div>
  );
}

function cvssSeverity(score, fallback = 'UNKNOWN') {
  if (score == null || Number.isNaN(Number(score))) return fallback || 'UNKNOWN';
  const value = Number(score);
  if (value >= 9) return 'CRITICAL';
  if (value >= 7) return 'HIGH';
  if (value >= 4) return 'MEDIUM';
  if (value > 0) return 'LOW';
  return 'NONE';
}

function cvssLabel(score, severity) {
  if (score == null || Number.isNaN(Number(score))) return null;
  const normalized = cvssSeverity(score, severity).toLowerCase();
  const label = normalized.charAt(0).toUpperCase() + normalized.slice(1);
  return `CVSS: ${Number(score).toFixed(1)} ${label}`;
}

function CVEModal({ row, onClose }) {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (!row?.cve_result?.cves?.length) return null;

  const { cve_result } = row;

  return (
    <div
      className="banner-modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="cve-modal-title"
      onClick={onClose}
    >
      <div className="banner-modal" onClick={(e) => e.stopPropagation()}>
        <div className="banner-modal-header">
          <div>
            <h2
              id="cve-modal-title"
              className="text-sm font-semibold"
              style={{ color: '#e9d5ff' }}
            >
              CVE Details — {row.service} {row.version}
            </h2>
            <p className="text-[10px] font-mono mt-0.5" style={{ color: '#8b7ec8' }}>
              Port {row.port} · {cve_result.total_count} vulnerabilities found
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="clear-input-btn"
            style={{ position: 'static', transform: 'none' }}
            aria-label="Close CVE details"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="banner-modal-body">
          <div className="flex gap-2 mb-4">
            {cve_result.critical_count > 0 && (
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full" style={{ background: 'rgba(255,77,77,0.12)', color: '#FF4D4D', border: '1px solid rgba(255,77,77,0.25)' }}>
                {cve_result.critical_count} CRITICAL
              </span>
            )}
            {cve_result.high_count > 0 && (
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full" style={{ background: 'rgba(249,115,22,0.12)', color: '#F97316', border: '1px solid rgba(249,115,22,0.25)' }}>
                {cve_result.high_count} HIGH
              </span>
            )}
            {cve_result.medium_count > 0 && (
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full" style={{ background: 'rgba(249,115,22,0.12)', color: '#F97316', border: '1px solid rgba(249,115,22,0.25)' }}>
                {cve_result.medium_count} MEDIUM
              </span>
            )}
            {cve_result.low_count > 0 && (
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full" style={{ background: 'rgba(124,255,154,0.12)', color: '#7CFF9A', border: '1px solid rgba(124,255,154,0.25)' }}>
                {cve_result.low_count} LOW
              </span>
            )}
          </div>
          <div className="flex flex-col gap-3">
            {cve_result.cves.map((cve) => (
              <div key={cve.cve_id} className="p-3 rounded-lg" style={{ background: 'rgba(124,58,237,0.08)', border: '1px solid rgba(124,58,237,0.15)' }}>
                <div className="flex items-center justify-between mb-2">
                  <a
                    href={cve.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono font-semibold hover:underline"
                    style={{ color: '#c4b5fd' }}
                  >
                    {cve.cve_id}
                  </a>
                  <RiskBadge label={cve.severity} color={cve.severity.toLowerCase()} />
                </div>
                {cve.cvss_score != null && (
                  <div className="cve-cvss-line">
                    {cvssLabel(cve.cvss_score, cve.severity)}
                    {cve.cvss_vector && <span>{cve.cvss_vector}</span>}
                  </div>
                )}
                <p className="text-[11px] leading-relaxed" style={{ color: '#a78bfa' }}>
                  {cve.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function CVECell({ row, onViewCVE }) {
  if (!row.cve_count || row.cve_count === 0) {
    return <span className="text-[10px] font-mono" style={{ color: '#5b4d82' }}>—</span>;
  }

  const hasCritical = row.cve_critical_count > 0;
  const hasHigh = row.cve_high_count > 0;
  const maxCvss = row.max_cvss_score == null ? null : Number(row.max_cvss_score);
  
  return (
    <button
      type="button"
      onClick={() => onViewCVE(row)}
      className="cve-cell-btn"
      title={`${row.cve_count} CVEs detected`}
    >
      <span className="text-[10px] font-mono font-semibold" style={{ color: hasCritical ? '#FF4D4D' : hasHigh ? '#F97316' : '#F97316' }}>
        {row.cve_count}
      </span>
      <span className="text-[9px] font-mono" style={{ color: '#8b7ec8' }}>
        {maxCvss != null ? `CVSS ${maxCvss.toFixed(1)}` : `CVE${row.cve_count !== 1 ? 's' : ''}`}
      </span>
    </button>
  );
}

function PortTechnologies({ technologies }) {
  if (!technologies?.length) {
    return <span className="text-[10px] font-mono" style={{ color: '#5b4d82' }}>—</span>;
  }
  return (
    <div className="port-row-tech-chips">
      {technologies.map((name) => (
        <TechChip key={name} name={name} />
      ))}
    </div>
  );
}

function fingerprintColor(confidence) {
  if (confidence >= 85) return '#7CFF9A';
  if (confidence >= 70) return '#F97316';
  if (confidence >= 50) return '#F97316';
  return '#FF4D4D';
}

function VersionCell({ version, technologies, fingerprint }) {
  const hasVersion = Boolean(version);
  const confidence = Number(fingerprint?.confidence || 0);
  const detected = fingerprint?.detected || version;
  return (
    <div className="flex flex-col gap-1 min-w-0">
      <span
        className={`port-version-cell ${hasVersion ? 'has-version' : 'no-version'}`}
        title={hasVersion ? version : undefined}
      >
        {hasVersion ? version : '—'}
      </span>
      {detected && confidence > 0 && (
        <div className="fingerprint-confidence" title={fingerprint?.method || undefined}>
          <span>Detected: {detected}</span>
          <strong style={{ color: fingerprintColor(confidence) }}>
            Confidence: {Math.round(confidence)}%
          </strong>
        </div>
      )}
      <PortTechnologies technologies={technologies} />
    </div>
  );
}

function formatScanDuration(seconds) {
  const n = Number(seconds);
  if (!Number.isFinite(n)) return '0.0s';
  return `${n.toFixed(1)}s`;
}

function ScreenshotPreview({ row }) {
  if (!row.screenshot_url) {
    return <span className="text-[10px] font-mono" style={{ color: '#5b4d82' }}>—</span>;
  }
  return (
    <a
      href={row.screenshot_url}
      target="_blank"
      rel="noopener noreferrer"
      className="web-port-preview"
      title={`Open screenshot preview for port ${row.port}`}
    >
      <img
        src={row.screenshot_url}
        alt={`Preview of port ${row.port}`}
        loading="lazy"
        className="rounded border border-[#4f3b63] max-w-[80px] max-h-[50px] object-cover"
        onError={(e) => { e.currentTarget.style.display = 'none'; }}
      />
    </a>
  );
}

export default function PortScanner() {
  const getToken = useGetToken();
  const [target, setTarget] = useState('');
  const [portRange, setPortRange] = useState('common');
  const [customPortRange, setCustomPortRange] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [bannerRow, setBannerRow] = useState(null);
  const [cveRow, setCveRow] = useState(null);
  const [detectedTechnologies, setDetectedTechnologies] = useState([]);
  const [scanStats, setScanStats] = useState(null);
  const [activeFocusTab, setActiveFocusTab] = useState('risk');
  const streamAbortRef = useRef(null);
  const scanStartRef = useRef(0);

  useEffect(() => () => {
    streamAbortRef.current?.abort();
  }, []);

  const buildLiveScanStats = (rows, progressData = {}) => {
    const liveRows = Array.isArray(rows) ? rows : [];
    const riskCounts = ['critical', 'high', 'medium', 'low'].reduce((acc, level) => {
      acc[level] = liveRows.filter((row) => row.risk_level === level).length;
      return acc;
    }, {});
    const highestSeverity = riskCounts.critical ? 'critical' : riskCounts.high ? 'high' : riskCounts.medium ? 'medium' : 'low';
    const exposedServices = liveRows.map((row) => ({
      port: Number(row.port),
      service: row.service || 'Unknown',
      riskLevel: row.risk_level || 'medium',
    }));
    const startedAt = scanStartRef.current || performance.now();
    const checked = Number(progressData.checked ?? 0);
    const total = Number(progressData.total ?? checked);

    return {
      live: true,
      scanDurationSeconds: (performance.now() - startedAt) / 1000,
      packetsSent: checked,
      avgLatencyMs: progressData.latency_ms == null ? null : Number(progressData.latency_ms),
      securityScore: null,
      securityScoreFactors: [],
      attackSurface: {
        level: riskCounts.critical ? 'CRITICAL' : riskCounts.high ? 'HIGH' : liveRows.length ? 'MEDIUM' : 'LOW',
        score: Math.min(100, liveRows.length * 12 + riskCounts.high * 10 + riskCounts.critical * 18),
        publiclyExposedServices: exposedServices,
        factors: exposedServices.slice(0, 6).map((entry) => ({
          category: 'public_service',
          label: `Port ${entry.port} ${entry.service} is publicly reachable.`,
          weight: 8,
          severity: entry.riskLevel,
        })),
        summary: liveRows.length
          ? `${liveRows.length} open service${liveRows.length === 1 ? '' : 's'} detected while scanning ${checked}/${total || '?'} ports.`
          : `Scanning ${checked}/${total || '?'} ports for exposed services.`,
      },
      threatIntelligence: { sources: [] },
      misconfigurationSummary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, categories: [] },
      exposureSummary: {
        publicExposure: liveRows.length > 0,
        highestSeverity,
        highestScore: null,
        highestFinding: '',
        highestPort: liveRows[0]?.port ?? null,
        critical: riskCounts.critical,
        high: riskCounts.high,
        medium: riskCounts.medium,
        low: riskCounts.low,
      },
      attackPaths: { nodes: [], edges: [], paths: [], summary: '', highestSeverity },
      attackSimulations: [],
      recommendationsError: '',
    };
  };

  const getInitialPortTotal = () => {
    if (portRange === 'all') return 65535;
    if (portRange !== 'custom') return 0;
    const trimmed = customPortRange.trim();
    if (!trimmed) return 0;
    if (trimmed.includes('-')) {
      const [start, end] = trimmed.split('-').map((part) => parseInt(part.trim(), 10));
      return Number.isFinite(start) && Number.isFinite(end) && end >= start ? end - start + 1 : 0;
    }
    return trimmed.split(',').map((part) => parseInt(part.trim(), 10)).filter((port) => Number.isFinite(port)).length;
  };

  const mergeRowsByPort = (currentRows, incomingRows) => {
    const byPort = new Map((currentRows || []).map((row) => [Number(row.port), row]));
    (incomingRows || []).forEach((row) => {
      byPort.set(Number(row.port), row);
    });
    return Array.from(byPort.values()).sort((a, b) => Number(a.port) - Number(b.port));
  };

  const runPortScanStream = async (body, options = {}) => {
    const {
      finishOnDone = true,
      mergeFinal = false,
      progressOffset = 0,
      progressSpan = 99,
      abortPrevious = true,
      resetTimer = true,
    } = options;
    if (abortPrevious) {
      streamAbortRef.current?.abort();
    }
    const controller = new AbortController();
    streamAbortRef.current = controller;
    if (resetTimer) {
      scanStartRef.current = performance.now();
    }
    const result = await apiPostAndPoll('/api/tools/port_scan', body, getToken, {
      signal: controller.signal,
      onProgress: (pct, run) => {
        const scaled = progressOffset + ((Number(pct) / 100) * progressSpan);
        setProgress(Math.min(99, Math.round(scaled)));
        if (run?.data) {
          const partial = parsePortScanResponse({ data: run.data });
          setScanStats(partial.stats);
        }
      },
    });
    if (!result.response.ok) {
      if (result.response.status === 429) window.dispatchEvent(new CustomEvent('tier:limit_reached'));
      throw new Error(result.payload?.detail || result.payload?.error?.message || `Scan failed (${result.response.status})`);
    }
    const finalPayload = parsePortScanResponse({ data: result.data });
    const ports = finalPayload.ports || [];
    if (mergeFinal) {
      setResults((previous) => mergeRowsByPort(Array.isArray(previous) ? previous : [], ports));
      setDetectedTechnologies(collectDetectedTechnologies(ports, finalPayload.detectedTechnologies));
    } else {
      setResults(ports);
      setDetectedTechnologies(finalPayload.detectedTechnologies);
      setScanStats(finalPayload.stats);
    }
    if (finishOnDone) {
      setProgress(100);
      window.setTimeout(() => {
        setIsScanning(false);
        setProgress(0);
      }, 400);
    }
    if (streamAbortRef.current === controller) streamAbortRef.current = null;
    return finalPayload;
  };

  const handleScan = async () => {
    if (!target.trim() || isScanning) return;
    
    if (portRange === 'custom' && !customPortRange.trim()) {
      return;
    }
    
    setIsScanning(true);
    setResults([]);
    setDetectedTechnologies([]);
    setErrorMsg(null);
    setBannerRow(null);
    setCveRow(null);
    setProgress(0);
    scanStartRef.current = performance.now();
    setScanStats(buildLiveScanStats([], { checked: 0, total: getInitialPortTotal() }));

    let progressInterval = null;

    try {
      const targetClean = target.trim();
      let allOpenPorts = [];
      const allScanStart = performance.now();
      let packetsSent = 0;
      let weightedLatencyTotal = 0;
      let weightedLatencyPackets = 0;
      let securityScore = 100;
      let securityScoreFactors = [];
      let attackSurface = null;
      let threatIntelligence = null;

      if (portRange === 'all') {
        const BATCH_SIZE = 5000;
        const MAX_PORT = 65535;
        let currentStart = 1;

        while (currentStart <= MAX_PORT) {
          const currentEnd = Math.min(currentStart + BATCH_SIZE - 1, MAX_PORT);
          const body = {
            target: targetClean,
            start_port: currentStart,
            end_port: currentEnd,
            timeout: 0.8,
            max_concurrent: 1000
          };

          const batchStart = currentStart;
          const batchSize = currentEnd - currentStart + 1;
          const streamed = await runPortScanStream(body, {
            finishOnDone: false,
            mergeFinal: true,
            progressOffset: ((batchStart - 1) / MAX_PORT) * 100,
            progressSpan: (batchSize / MAX_PORT) * 100,
            abortPrevious: false,
            resetTimer: false,
          });
          const ports = streamed?.ports || [];
          const stats = streamed?.stats || buildLiveScanStats(ports, {
            checked: currentEnd,
            total: MAX_PORT,
          });
          packetsSent += stats.packetsSent;
          if (Number.isFinite(stats.avgLatencyMs) && stats.packetsSent > 0) {
            weightedLatencyTotal += stats.avgLatencyMs * stats.packetsSent;
            weightedLatencyPackets += stats.packetsSent;
          }
          if (Number.isFinite(stats.securityScore)) {
            securityScore = Math.min(securityScore, stats.securityScore);
          }
          securityScoreFactors.push(...(stats.securityScoreFactors || []));
          attackSurface = combineAttackSurface(attackSurface, stats.attackSurface);
          threatIntelligence = combineThreatIntelligence(threatIntelligence, stats.threatIntelligence);
          allOpenPorts = mergeRowsByPort(allOpenPorts, ports);
          setResults([...allOpenPorts]);
          setDetectedTechnologies(collectDetectedTechnologies(allOpenPorts));

          setProgress(Math.floor((currentEnd / MAX_PORT) * 100));
          currentStart += BATCH_SIZE;
        }

        setTimeout(() => {
          setScanStats({
            scanDurationSeconds: (performance.now() - allScanStart) / 1000,
            packetsSent,
            avgLatencyMs: weightedLatencyPackets > 0
              ? weightedLatencyTotal / weightedLatencyPackets
              : null,
            securityScore,
            securityScoreFactors: securityScoreFactors.slice(0, 12),
            attackSurface,
            threatIntelligence,
          });
          setIsScanning(false);
          setProgress(0);
        }, 400);

      } else {
        let body = { target: targetClean, timeout: 3.0 };
        
        if (portRange === 'custom') {
          if (customPortRange.includes('-')) {
            const parts = customPortRange.split('-');
            body.start_port = parseInt(parts[0], 10);
            body.end_port = parseInt(parts[1], 10);
          } else {
            body.ports = customPortRange.split(',').map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p));
          }
        }

        await runPortScanStream(body);
      }
    } catch (err) {
      console.error(err);
      if (progressInterval) clearInterval(progressInterval);
      setProgress(0);
      setIsScanning(false);
      setErrorMsg(err.message || 'An error occurred during scan.');
      // Keep results if any were accumulated
    }
  };

  const downloadText = (filename, content, type = 'text/plain') => downloadFile(filename, content, type);

  const renderMetricTile = (Icon, label, value, tone = '#f4eef7') => (
    <div className="min-h-[78px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-4">
      <div className="flex items-center gap-2 text-[10px] font-bold text-[#efe9f5]">
        <Icon className="h-3.5 w-3.5" />
        <span>{label}</span>
      </div>
      <div className="mt-4 text-[13px] font-semibold break-words" style={{ color: tone }}>{value}</div>
    </div>
  );

  const renderSectionTitle = (title) => (
    <div className="mb-7 flex items-center gap-3 text-[13px] font-medium uppercase text-[#b79aff]">
      <CircleDot className="h-5 w-5" />
      <span>{title}</span>
    </div>
  );

  const renderFocusContent = (rows, riskCounts) => {
    if (activeFocusTab === 'visibility') {
      return (
        <VisibilityFocusPanel rows={rows} stats={scanStats} riskCounts={riskCounts} />
      );
    }
    if (activeFocusTab === 'adversary') {
      const mitreRows = rows.filter((row) => row.mitre_attack?.length);
      const exploitRows = rows.filter((row) => row.exploit_availability?.publicExploitAvailable != null);
      return (
        <>
          <AdversaryFocusPanel rows={rows} stats={scanStats} />
          <div className="min-h-[300px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
            {renderSectionTitle('MITRE Signals')}
            <div className="space-y-3">
              {mitreRows.length === 0 && <p className="text-[12px] leading-relaxed text-[#b7abc5]">—</p>}
              {mitreRows.slice(0, 3).map((row) => (
                <div key={`mitre-focus-${row.port}`} className="rounded-lg border border-[#4f3b63] bg-[#24183b]/70 p-4 text-[12px] text-[#d8cce6]">
                  <div className="mb-2 font-semibold text-[#f4eef7]">Port {row.port} ({row.service || '—'})</div>
                  {row.mitre_attack.slice(0, 2).map((technique) => (
                    <div key={`${row.port}-${technique.technique_id}`} className="flex items-center justify-between gap-3 border-t border-[#382748] py-2 first:border-t-0">
                      <span>{technique.technique_id}</span>
                      <span className="text-right text-[#b7abc5]">{technique.technique_name}</span>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
          <div className="min-h-[300px] rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-7">
            {renderSectionTitle('Exploit Availability')}
            <div className="space-y-3 text-[12px] text-[#d8cce6]">
              {exploitRows.length === 0 && <p className="leading-relaxed text-[#b7abc5]">—</p>}
              {exploitRows.slice(0, 4).map((row) => (
                <div key={`exploit-focus-${row.port}`} className="rounded-lg border border-[#4f3b63] bg-[#24183b]/70 p-4">
                  <div className="mb-2 flex items-center justify-between gap-3">
                    <span>Port {row.port} ({row.service || '—'})</span>
                    <span className={row.exploit_availability.publicExploitAvailable ? 'text-[#FF4D4D]' : 'text-[#7CFF9A]'}>
                      {row.exploit_availability.publicExploitAvailable ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <div className="text-[#92859d]">ExploitDB: {row.exploit_availability.exploitdb || '—'}</div>
                  <div className="text-[#92859d]">Metasploit: {row.exploit_availability.metasploit || '—'}</div>
                </div>
              ))}
            </div>
          </div>
        </>
      );
    }
    return (
      <>
        <ExposureSeverityFocusPanel rows={rows} stats={scanStats} riskCounts={riskCounts} />
        <RecommendedActionsFocusPanel rows={rows} />
      </>
    );
  };

  const renderPortDashboard = () => {
    const rows = Array.isArray(results) ? results : [];
    const score = Number.isFinite(scanStats?.securityScore)
      ? Math.max(0, Math.min(100, Math.round(scanStats.securityScore)))
      : null;
    const cveTotal = rows.reduce((sum, row) => sum + Number(row.cve_count || 0), 0);
    const riskCounts = ['critical', 'high', 'medium', 'low'].reduce((acc, level) => {
      acc[level] = rows.filter((row) => row.risk_level === level).length;
      return acc;
    }, {});
    const dominantRisk = riskCounts.critical ? 'Critical' : riskCounts.high ? 'High' : riskCounts.medium ? 'Medium' : rows.length ? 'Low' : 'Pending';
    const attackLevel = scanStats?.attackSurface?.level || (riskCounts.critical ? 'Critical' : riskCounts.high ? 'High' : rows.length ? 'Medium' : 'Pending');
    const reputation = scanStats?.threatIntelligence?.reputation || '—';
    const techs = detectedTechnologies.length ? detectedTechnologies : collectDetectedTechnologies(rows);
    const techSummaries = techs.map((tech) => {
      const matchingRows = rows.filter((row) => row.technologies?.includes(tech));
      const bestConfidence = matchingRows.reduce((best, row) => {
        const confidence = Number(row.fingerprint?.confidence || 0);
        return Math.max(best, confidence);
      }, 0);
      return { name: tech, ports: matchingRows.map((row) => row.port), bestConfidence };
    });
    const scanDuration = scanStats ? formatScanDuration(scanStats.scanDurationSeconds) : isScanning ? 'Streaming' : '0.0s';
    const exposureTotal = Math.max(1, rows.length || 1);
    const exposureGradient = `conic-gradient(#FF4D4D 0deg ${(riskCounts.critical / exposureTotal) * 360}deg, #F97316 ${(riskCounts.critical / exposureTotal) * 360}deg ${((riskCounts.critical + riskCounts.high) / exposureTotal) * 360}deg, #d9f94f ${((riskCounts.critical + riskCounts.high) / exposureTotal) * 360}deg ${((riskCounts.critical + riskCounts.high + riskCounts.medium) / exposureTotal) * 360}deg, #7CFF9A ${((riskCounts.critical + riskCounts.high + riskCounts.medium) / exposureTotal) * 360}deg 360deg)`;
    const csv = [
      ['Port', 'State', 'Service', 'Version', 'CVEs', 'Risk'].join(','),
      ...rows.map((row) => [row.port, row.state, row.service, row.version, row.cve_count, row.risk_level].map((value) => `"${String(value ?? '').replaceAll('"', '""')}"`).join(',')),
    ].join('\n');

    return (
      <div className="flex-1 overflow-y-auto p-1 md:p-2">
        <div className="space-y-8">
          <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
            <div className="flex flex-wrap items-center gap-3">
              {isScanning ? <Activity className="h-7 w-7 animate-pulse text-[#b79aff]" /> : <CheckCircle2 className="h-7 w-7 text-[#7CFF9A]" />}
              <h2 className="text-[26px] font-medium text-[#f4eef7]">{isScanning ? 'Port Scan Running' : 'Port Scan Completed'}</h2>
            </div>
            <div className="mt-5 flex flex-wrap gap-3">
              <span className="inline-flex h-7 items-center gap-1.5 rounded-full border border-[#63516e]/80 bg-[#13091f]/74 px-3 text-[11px] text-[#d6cbe2]">
                <ScanLine className="h-3.5 w-3.5 text-[#f4eef7]" /> {Math.round(progress)}% Scan Progress
              </span>
              <span className="inline-flex h-7 items-center gap-1.5 rounded-full border border-[#63516e]/80 bg-[#13091f]/74 px-3 text-[11px] text-[#d6cbe2]">
                <Server className="h-3.5 w-3.5 text-[#f4eef7]" /> {rows.length} Open Ports Found
              </span>
              <span className="inline-flex h-7 items-center gap-1.5 rounded-full border border-[#63516e]/80 bg-[#13091f]/74 px-3 text-[11px] text-[#d6cbe2]">
                <ShieldCheck className="h-3.5 w-3.5 text-[#f4eef7]" /> {dominantRisk} Risk
              </span>
              <span className="inline-flex h-7 items-center gap-1.5 rounded-full border border-[#63516e]/80 bg-[#13091f]/74 px-3 text-[11px] text-[#d6cbe2]">
                <Activity className="h-3.5 w-3.5 text-[#f4eef7]" /> {scanDuration}
              </span>
            </div>
            <div className="mt-6 grid grid-cols-1 gap-1.5 md:grid-cols-2 xl:grid-cols-6">
              {renderMetricTile(Server, 'Open Ports', rows.length)}
              {renderMetricTile(Bug, 'CVEs', cveTotal)}
              {renderMetricTile(Radio, 'Risk Level', dominantRisk, dominantRisk === 'Critical' ? '#FF4D4D' : dominantRisk === 'High' ? '#F97316' : '#7CFF9A')}
              {renderMetricTile(ShieldCheck, 'Security Score', score == null ? '—' : `${score}/100`)}
              {renderMetricTile(Tags, 'Attack Surface', attackLevel, surfaceColor(attackLevel))}
              {renderMetricTile(Globe2, 'IP Reputation', reputation, reputationColor(reputation))}
            </div>
          </section>

          <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
              <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-8">
                {renderSectionTitle('Security Score')}
                <div className="flex flex-col items-center">
                  <div className="grid h-36 w-36 place-items-center rounded-full" style={{ background: score == null ? '#4a3857' : `conic-gradient(${scoreColor(score)} ${score * 3.6}deg, #4a3857 0deg)` }}>
                    <div className="grid h-24 w-24 place-items-center rounded-full bg-[#13091f] text-center">
                      <strong className="text-3xl text-[#f4eef7]">{score == null ? '—' : score}<span className="text-sm text-[#92859d]">{score == null ? '' : '/100'}</span></strong>
                    </div>
                  </div>
                  <p className="mt-5 text-center text-sm text-[#d8cce6]">{score == null ? '—' : score >= 85 ? 'High Security Posture' : score >= 65 ? 'Moderate Security Posture' : 'Elevated Exposure'}</p>
                </div>
              </div>

              <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-8">
                {renderSectionTitle('Exposure Breakdown')}
                <div className="grid grid-cols-[120px_minmax(0,1fr)] items-center gap-6">
                  <div className="h-28 w-28 rounded-full" style={{ background: exposureGradient }} />
                  <div className="space-y-3 text-sm">
                    {[
                      ['High', riskCounts.high, '#F97316'],
                      ['Critical', riskCounts.critical, '#FF4D4D'],
                      ['Medium', riskCounts.medium, '#d9f94f'],
                      ['Low', riskCounts.low, '#7CFF9A'],
                    ].map(([label, value, color]) => (
                      <div key={label} className="flex items-center justify-between gap-3 text-[#d8cce6]">
                        <span className="inline-flex items-center gap-2"><i className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />{label}</span>
                        <strong>{value}</strong>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="mt-5 space-y-3 border-t border-[#554365]/70 pt-4 text-xs text-[#b7abc5]">
                  <p><span className="text-[#F97316]">Critical Exposure</span><br />{rows.find((row) => row.risk_level === 'critical')?.service || 'No critical service'} publicly reachable.</p>
                  <p><span className="text-[#d9f94f]">Medium Exposure</span><br />{rows.find((row) => row.risk_level === 'medium')?.service || 'No medium-risk service'} publicly reachable.</p>
                </div>
              </div>

              <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-8">
                {renderSectionTitle('Detected Technologies')}
                <div className="space-y-6">
                  {(techSummaries.length ? techSummaries.slice(0, 4) : [{ name: '—', ports: [], bestConfidence: 0 }]).map((tech) => (
                    <div key={tech.name} className="grid grid-cols-[42px_minmax(0,1fr)] gap-4">
                      <div className="grid h-10 w-10 place-items-center rounded-lg bg-[#281743] text-[#b79aff]">
                        <Database className="h-5 w-5" />
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-semibold text-[#f4eef7]">{tech.name}</div>
                        <div className="text-[10px] text-[#92859d]">
                          {tech.ports.length ? `Observed on port${tech.ports.length === 1 ? '' : 's'} ${tech.ports.join(', ')}` : '—'}
                        </div>
                        {tech.bestConfidence > 0 && (
                          <>
                            <div className="text-[10px] text-[#92859d]">Fingerprint confidence: {Math.round(tech.bestConfidence)}%</div>
                            <div className="mt-2 h-1.5 rounded-full bg-[#43364b]"><div className="h-full rounded-full bg-[#7CFF9A]" style={{ width: `${Math.round(tech.bestConfidence)}%` }} /></div>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-7 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 p-8">
              {renderSectionTitle('Open Ports & Services')}
              <div className="overflow-x-auto">
                <table className="w-full min-w-[880px] border-collapse text-left">
                  <thead>
                    <tr className="border-b border-[#554365]/80 text-[11px] text-[#92859d]">
                      {['Port', 'State', 'Service', 'Preview', 'Version / Tech', 'Banner', 'CVEs', 'Risk'].map((head) => <th key={head} className="px-4 py-3 font-medium">{head}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.length === 0 && (
                      <tr><td colSpan="8" className="px-4 py-10 text-center text-sm text-[#92859d]">{isScanning ? 'Streaming port results into the dashboard...' : 'No open ports found.'}</td></tr>
                    )}
                    {rows.map((row) => {
                      const riskProps = riskBadgeProps(row);
                      return (
                        <tr key={row.port} className="border-b border-[#382748] text-[12px] text-[#d8cce6] last:border-b-0">
                          <td className="px-4 py-5 font-mono text-[#ddd6fe]">{row.port}</td>
                          <td className="px-4 py-5"><RiskBadge label={row.state || 'open'} color="open" /></td>
                          <td className="px-4 py-5"><ServiceTooltip row={row} /></td>
                          <td className="px-4 py-5"><ScreenshotPreview row={row} /></td>
                          <td className="px-4 py-5"><VersionCell version={row.version} technologies={row.technologies} fingerprint={row.fingerprint} /></td>
                          <td className="px-4 py-5">
                            <button type="button" className="banner-view-btn" disabled={!hasBannerData(row)} onClick={() => setBannerRow(row)}>
                              View Banner
                            </button>
                            {hasBannerData(row) && <div className="mt-2 max-w-[150px] truncate text-[10px] text-[#8b7ec8]">{bannerPreview(row)}</div>}
                          </td>
                          <td className="px-4 py-5"><CVECell row={row} onViewCVE={setCveRow} /></td>
                          <td className="px-4 py-5"><RiskBadge label={riskProps.label} color={riskProps.color} title={riskProps.title} /></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </section>

          <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
            <div className="grid grid-cols-3 overflow-hidden rounded-t-lg border border-[#4f3b63] bg-[#24183b] text-center text-sm text-[#b7abc5]">
              {[
                ['visibility', 'Security Visibility Layer Focus'],
                ['adversary', 'Adversary & Exploit Modeling Focus'],
                ['risk', 'Risk & Remediation Engine Focus'],
              ].map(([key, label], index) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setActiveFocusTab(key)}
                  aria-pressed={activeFocusTab === key}
                  className={`px-4 py-4 transition hover:bg-[#382748] ${activeFocusTab === key ? 'bg-[#654f90] text-[#f4eef7]' : index > 0 ? 'border-l border-[#4f3b63]' : ''}`}
                >
                  <Globe2 className="mr-2 inline h-4 w-4" />{label}
                </button>
              ))}
            </div>
            <div className="grid grid-cols-1 gap-6 rounded-b-lg border-x border-b border-[#382748] bg-[#13091f]/50 p-8 xl:grid-cols-3">
              {renderFocusContent(rows, riskCounts)}
            </div>
          </section>

          <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
            <div className="mb-2 text-[18px] font-medium uppercase text-[#b79aff]">Export & Share</div>
            <p className="text-sm text-[#d2c5dc]">Download or share your scan report.</p>
            <div className="mt-7 grid grid-cols-1 gap-4 md:grid-cols-4">
              <button type="button" onClick={() => exportBrandedPdf({ tool: 'Port Scanner', target })} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:border-[#9f7aea]"><FileText className="h-4 w-4" /> Export PDF</button>
              <button type="button" onClick={() => downloadText(`${target || 'port-scan'}-ports.json`, JSON.stringify({ target, results: rows, stats: scanStats }, null, 2), 'application/json')} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:border-[#9f7aea]"><FileText className="h-4 w-4" /> Export JSON</button>
              <button type="button" onClick={() => downloadText(`${target || 'port-scan'}-ports.csv`, csv, 'text/csv')} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:border-[#9f7aea]"><FileText className="h-4 w-4" /> Export CSV</button>
              <button type="button" onClick={() => shareOrCopy({ title: 'Port Scan Report', text: `${target}: ${rows.length} open port(s), ${dominantRisk} risk` })} className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:border-[#9f7aea]"><Share2 className="h-4 w-4" /> Share report</button>
            </div>
          </section>
        </div>
      </div>
    );
  };

  return (
    <div className="flex flex-col h-full port-scanner-page">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot">
          <ScanLine className="w-3 h-3" />
        </span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>
          Port Scanner
        </span>
      </div>

      <div className="scanner-control-shell">
        <div className="target-field relative">
          <input
            className="scan-input pr-10"
            type="text"
            placeholder="Target IP or domain (eg. 192.168.1.1)"
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
          />
          {target && (
            <button
              onClick={() => setTarget('')}
              className="clear-input-btn"
              aria-label="Clear target"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        <div className="select-field relative">
          <select
            className="scan-select"
            value={portRange}
            onChange={e => setPortRange(e.target.value)}
          >
            <option value="common">Common Ports</option>
            <option value="all">All Ports (1-65535)</option>
            <option value="custom">Custom Range</option>
          </select>
        </div>

        {portRange === 'custom' && (
          <div className="target-field relative">
            <input
              className="scan-input"
              type="text"
              placeholder="e.g., 80,443,8080 or 1-1000"
              value={customPortRange}
              onChange={e => setCustomPortRange(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleScan()}
            />
          </div>
        )}

        <button
          onClick={handleScan}
          disabled={isScanning || !target.trim()}
          className="run-btn"
        >
          <span>{isScanning ? 'Scanning' : 'Run Scan'}</span>
          {isScanning ? (
            <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          ) : (
            <ArrowRight className="w-5 h-5" />
          )}
        </button>
      </div>

      {isScanning && (
        <div
          className="h-[2px] rounded-full mb-3 overflow-hidden"
          style={{ background: 'rgba(124,58,237,0.15)' }}
        >
          <div
            className="h-full rounded-full transition-all duration-300"
            style={{
              width: `${progress}%`,
              background: 'linear-gradient(90deg, #7c3aed, #a855f7)',
            }}
          />
        </div>
      )}

      <div
        className="scanner-results-panel flex-1 overflow-hidden flex flex-col"
      >
        {results === null && !errorMsg && (
          <div className="flex flex-col items-center justify-center flex-1 gap-4">
            <img
              src="/assets/logo.svg"
              alt=""
              className="empty-logo h-20 w-auto"
              style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }}
            />
            <span
              className="text-xs font-medium uppercase"
              style={{ color: '#6d579b' }}
            >
              Your scan results will appear here
            </span>
          </div>
        )}
        
        {errorMsg && (
          <div className="flex flex-col items-center justify-center flex-1 gap-3 p-6 text-center">
            <div className="w-12 h-12 flex items-center justify-center rounded-full" style={{ background: 'rgba(255,77,77,0.1)' }}>
              <X className="w-6 h-6 text-[#FF4D4D]" />
            </div>
            <span className="text-sm font-medium text-[#FF4D4D]">Scan Error</span>
            <span className="text-xs" style={{ color: '#9ca3af' }}>{errorMsg}</span>
          </div>
        )}

        {results !== null && (
          renderPortDashboard()
        )}
      </div>

      {bannerRow && (
        <BannerModal
          row={bannerRow}
          target={target}
          onClose={() => setBannerRow(null)}
        />
      )}
      {cveRow && (
        <CVEModal
          row={cveRow}
          onClose={() => setCveRow(null)}
        />
      )}
    </div>
  );
}
