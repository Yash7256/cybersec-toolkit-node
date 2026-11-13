import { getPortDescription } from './portDescriptions';

/**
 * Normalize /api/tools/port_scan open_ports entries for the Port Scanner UI.
 */
export function mapOpenPort(p) {
  const version = (p.version ?? p.service_version ?? '').toString().trim();
  const rawBanner = (p.raw_banner ?? p.banner ?? '').toString().trim();
  const welcomeMessage = (p.welcome_message ?? '').toString().trim();
  const serverResponse = (p.server_response ?? '').toString().trim();
  const riskLevel = (p.risk_level ?? p.risk ?? 'medium').toString().toLowerCase();
  const riskReason = (p.risk_reason ?? '').toString().trim();
  const port = p.port_number ?? p.port;
  const service = p.service ?? p.name ?? '—';
  const desc = getPortDescription(
    port,
    service,
    p.service_description,
    p.service_security_concern,
  );
  const technologies = Array.isArray(p.technologies)
    ? p.technologies.map((t) => String(t).trim()).filter(Boolean)
    : [];
  const screenshot = (p.screenshot ?? '').toString().trim();
  const screenshotUrl = (p.screenshot_url ?? '').toString().trim()
    || (screenshot ? `/screenshots/${encodeURIComponent(screenshot)}` : '');
  const recommendation = (p.recommendation ?? '').toString().trim();
  const recommendationReason = (p.recommendation_reason ?? '').toString().trim();
  const recommendationPriority = (p.recommendation_priority ?? '').toString().trim().toLowerCase();
  const mitreAttack = Array.isArray(p.mitre_attack)
    ? p.mitre_attack
        .map((technique) => ({
          technique_id: (technique.technique_id ?? technique.id ?? '').toString().trim(),
          technique_name: (technique.technique_name ?? technique.name ?? '').toString().trim(),
          tactic: (technique.tactic ?? '').toString().trim(),
          url: (technique.url ?? '').toString().trim(),
          attack_vector: (technique.attack_vector ?? '').toString().trim(),
          threat_behavior: (technique.threat_behavior ?? technique.technique_name ?? '').toString().trim(),
        }))
        .filter((technique) => technique.technique_id && technique.technique_name)
    : [];
  const potentialThreat = (p.potential_threat ?? '').toString().trim();
  const rawExploit = p.exploit_availability ?? {};
  const exploitAvailability = {
    serviceVersion: (rawExploit.service_version ?? '').toString().trim(),
    publicExploitAvailable: rawExploit.public_exploit_available,
    exploitdbAvailable: rawExploit.exploitdb_available,
    metasploitAvailable: rawExploit.metasploit_available,
    metasploitModule: (rawExploit.metasploit_module ?? '').toString().trim(),
    exploitdb: (rawExploit.exploitdb ?? 'Unknown').toString(),
    metasploit: (rawExploit.metasploit ?? 'Unknown').toString(),
    evidence: Array.isArray(rawExploit.evidence)
      ? rawExploit.evidence.map((item) => String(item).trim()).filter(Boolean)
      : [],
  };
  const misconfigurations = Array.isArray(p.misconfigurations)
    ? p.misconfigurations
        .map((finding) => ({
          category: (finding.category ?? '').toString().trim(),
          title: (finding.title ?? 'Misconfiguration detected').toString().trim(),
          severity: (finding.severity ?? 'medium').toString().trim().toLowerCase(),
          evidence: (finding.evidence ?? '').toString().trim(),
          recommendation: (finding.recommendation ?? '').toString().trim(),
        }))
        .filter((finding) => finding.title)
    : [];
  const rawExposure = p.exposure_severity ?? {};
  const exposureSeverity = {
    score: Number(rawExposure.score ?? 0),
    severity: (rawExposure.severity ?? '').toString().trim().toLowerCase(),
    publicExposure: Boolean(rawExposure.public_exposure),
    finding: (rawExposure.finding ?? '').toString().trim(),
    recommendation: (rawExposure.recommendation ?? '').toString().trim(),
    factors: Array.isArray(rawExposure.factors)
      ? rawExposure.factors.map((factor) => String(factor).trim()).filter(Boolean)
      : [],
  };
  const rawCveResult = p.cve_result ?? null;
  const cveResult = rawCveResult
    ? {
        service_name: (rawCveResult.service_name ?? '').toString(),
        version: (rawCveResult.version ?? '').toString(),
        cves: Array.isArray(rawCveResult.cves)
          ? rawCveResult.cves.map((cve) => ({
              cve_id: (cve.cve_id ?? '').toString(),
              description: (cve.description ?? '').toString(),
              severity: (cve.severity ?? 'UNKNOWN').toString(),
              cvss_score: cve.cvss_score == null ? null : Number(cve.cvss_score),
              cvss_vector: (cve.cvss_vector ?? '').toString(),
              published_date: (cve.published_date ?? '').toString(),
              url: (cve.url ?? '').toString(),
            })).filter((cve) => cve.cve_id)
          : [],
        total_count: Number(rawCveResult.total_count ?? 0),
        critical_count: Number(rawCveResult.critical_count ?? 0),
        high_count: Number(rawCveResult.high_count ?? 0),
        medium_count: Number(rawCveResult.medium_count ?? 0),
        low_count: Number(rawCveResult.low_count ?? 0),
      }
    : null;
  const rawFingerprint = p.fingerprint ?? {};
  const fingerprint = {
    detected: (rawFingerprint.detected ?? version ?? service ?? '').toString().trim(),
    confidence: Number(rawFingerprint.confidence ?? 0),
    method: (rawFingerprint.method ?? '').toString().trim(),
    evidence: Array.isArray(rawFingerprint.evidence)
      ? rawFingerprint.evidence.map((item) => String(item).trim()).filter(Boolean)
      : [],
  };

  return {
    port,
    state: p.status ?? p.state ?? 'open',
    service,
    version,
    raw_banner: rawBanner,
    welcome_message: welcomeMessage,
    server_response: serverResponse,
    risk_level: ['critical', 'low', 'medium', 'high'].includes(riskLevel) ? riskLevel : 'medium',
    risk_reason: riskReason,
    service_name: desc.name,
    service_description: desc.purpose,
    service_security_concern: desc.concern,
    technologies,
    screenshot,
    screenshot_url: screenshotUrl,
    recommendation,
    recommendation_reason: recommendationReason,
    recommendation_priority: ['critical', 'high', 'medium', 'low'].includes(recommendationPriority)
      ? recommendationPriority
      : '',
    mitre_attack: mitreAttack,
    potential_threat: potentialThreat,
    exploit_availability: exploitAvailability,
    misconfigurations,
    exposure_severity: exposureSeverity,
    cve_result: cveResult,
    cve_count: Number(p.cve_count ?? cveResult?.total_count ?? 0),
    cve_critical_count: Number(p.cve_critical_count ?? cveResult?.critical_count ?? 0),
    cve_high_count: Number(p.cve_high_count ?? cveResult?.high_count ?? 0),
    cve_medium_count: Number(p.cve_medium_count ?? cveResult?.medium_count ?? 0),
    cve_low_count: Number(p.cve_low_count ?? cveResult?.low_count ?? 0),
    max_cvss_score: p.max_cvss_score == null ? null : Number(p.max_cvss_score),
    max_cvss_severity: (p.max_cvss_severity ?? '').toString(),
    max_cvss_cve: (p.max_cvss_cve ?? '').toString(),
    fingerprint,
  };
}

export function collectDetectedTechnologies(rows, scanLevel = []) {
  const merged = [];
  const seen = new Set();
  const add = (name) => {
    const n = String(name).trim();
    if (n && !seen.has(n)) {
      seen.add(n);
      merged.push(n);
    }
  };
  if (Array.isArray(scanLevel)) scanLevel.forEach(add);
  (rows || []).forEach((row) => {
    (row.technologies || []).forEach(add);
  });
  return merged;
}

export function riskBadgeProps(row) {
  const level = row.risk_level || 'medium';
  return {
    label: level,
    color: level,
    title: row.risk_reason || undefined,
  };
}

export function parsePortScanResponse(responseData) {
  const data = responseData?.data ?? {};
  const ports = data.open_ports;
  const securityScore = Number(data.security_score ?? 100);
  const securityScoreFactors = Array.isArray(data.security_score_factors)
    ? data.security_score_factors
        .map((factor) => ({
          category: (factor.category ?? '').toString(),
          label: (factor.label ?? '').toString(),
          penalty: Number(factor.penalty ?? 0),
          severity: (factor.severity ?? 'medium').toString().toLowerCase(),
        }))
        .filter((factor) => factor.label)
    : [];
  const rawSurface = data.attack_surface ?? {};
  const attackSurface = {
    level: (rawSurface.level ?? 'LOW').toString(),
    score: Number(rawSurface.score ?? 0),
    publiclyExposedServices: Array.isArray(rawSurface.publicly_exposed_services)
      ? rawSurface.publicly_exposed_services
          .map((entry) => ({
            port: Number(entry.port ?? 0),
            service: (entry.service ?? 'Unknown').toString(),
            riskLevel: (entry.risk_level ?? 'medium').toString().toLowerCase(),
          }))
          .filter((entry) => entry.port > 0)
      : [],
    factors: Array.isArray(rawSurface.factors)
      ? rawSurface.factors
          .map((factor) => ({
            category: (factor.category ?? '').toString(),
            label: (factor.label ?? '').toString(),
            weight: Number(factor.weight ?? 0),
            severity: (factor.severity ?? 'medium').toString().toLowerCase(),
          }))
          .filter((factor) => factor.label)
      : [],
    summary: (rawSurface.summary ?? '').toString(),
  };
  const rawThreatIntel = data.threat_intelligence ?? {};
  const threatIntelligence = {
    ip: (rawThreatIntel.ip ?? '').toString(),
    reputation: (rawThreatIntel.reputation ?? 'Unknown').toString(),
    summary: (rawThreatIntel.summary ?? '').toString(),
    reportedTimes: Number(rawThreatIntel.reported_times ?? 0),
    abuseConfidenceScore: rawThreatIntel.abuse_confidence_score == null
      ? null
      : Number(rawThreatIntel.abuse_confidence_score),
    abuseipdb: rawThreatIntel.abuseipdb ?? {},
    spamhaus: rawThreatIntel.spamhaus ?? {},
    knownBotnet: Boolean(rawThreatIntel.known_botnet),
    sources: Array.isArray(rawThreatIntel.sources)
      ? rawThreatIntel.sources.map((source) => String(source)).filter(Boolean)
      : [],
    error: (rawThreatIntel.error ?? '').toString(),
  };
  const rawMisconfig = data.misconfiguration_summary ?? {};
  const misconfigurationSummary = {
    total: Number(rawMisconfig.total ?? 0),
    critical: Number(rawMisconfig.critical ?? 0),
    high: Number(rawMisconfig.high ?? 0),
    medium: Number(rawMisconfig.medium ?? 0),
    low: Number(rawMisconfig.low ?? 0),
    categories: Array.isArray(rawMisconfig.categories)
      ? rawMisconfig.categories.map((category) => String(category)).filter(Boolean)
      : [],
  };
  const rawExposureSummary = data.exposure_summary ?? {};
  const exposureSummary = {
    publicExposure: Boolean(rawExposureSummary.public_exposure),
    highestSeverity: (rawExposureSummary.highest_severity ?? 'low').toString().toLowerCase(),
    highestScore: Number(rawExposureSummary.highest_score ?? 0),
    highestFinding: (rawExposureSummary.highest_finding ?? '').toString(),
    highestPort: rawExposureSummary.highest_port == null
      ? null
      : Number(rawExposureSummary.highest_port),
    critical: Number(rawExposureSummary.critical ?? 0),
    high: Number(rawExposureSummary.high ?? 0),
    medium: Number(rawExposureSummary.medium ?? 0),
    low: Number(rawExposureSummary.low ?? 0),
  };
  const rawAttackPaths = data.attack_paths ?? {};
  const attackPaths = {
    nodes: Array.isArray(rawAttackPaths.nodes)
      ? rawAttackPaths.nodes.map((node) => ({
          id: (node.id ?? '').toString(),
          label: (node.label ?? '').toString(),
          type: (node.type ?? 'service').toString(),
          severity: (node.severity ?? 'medium').toString().toLowerCase(),
          port: node.port == null ? null : Number(node.port),
          detail: (node.detail ?? '').toString(),
        })).filter((node) => node.id && node.label)
      : [],
    edges: Array.isArray(rawAttackPaths.edges)
      ? rawAttackPaths.edges.map((edge) => ({
          source: (edge.source ?? '').toString(),
          target: (edge.target ?? '').toString(),
          label: (edge.label ?? '').toString(),
          severity: (edge.severity ?? 'medium').toString().toLowerCase(),
        })).filter((edge) => edge.source && edge.target)
      : [],
    paths: Array.isArray(rawAttackPaths.paths)
      ? rawAttackPaths.paths.map((path) => ({
          id: (path.id ?? '').toString(),
          title: (path.title ?? 'Attack Path').toString(),
          severity: (path.severity ?? 'medium').toString().toLowerCase(),
          steps: Array.isArray(path.steps) ? path.steps.map((step) => String(step)).filter(Boolean) : [],
          summary: (path.summary ?? '').toString(),
        })).filter((path) => path.steps.length > 0)
      : [],
    summary: (rawAttackPaths.summary ?? '').toString(),
    highestSeverity: (rawAttackPaths.highest_severity ?? 'low').toString().toLowerCase(),
  };
  const attackSimulations = Array.isArray(data.attack_simulations)
    ? data.attack_simulations.map((item) => ({
        id: (item.id ?? '').toString(),
        title: (item.title ?? 'Attack Simulation').toString(),
        severity: (item.severity ?? 'medium').toString().toLowerCase(),
        steps: Array.isArray(item.steps) ? item.steps.map((step) => String(step)).filter(Boolean) : [],
        chain: (item.chain ?? '').toString(),
        likelihood: (item.likelihood ?? 'Medium').toString(),
        confidence: (item.confidence ?? 'Inferred').toString(),
        recommendation: (item.recommendation ?? '').toString(),
        evidence: Array.isArray(item.evidence)
          ? item.evidence.map((entry) => String(entry)).filter(Boolean)
          : [],
      })).filter((item) => item.steps.length || item.chain)
    : [];
  const stats = {
    scanDurationSeconds: Number(data.scan_duration_seconds ?? 0),
    packetsSent: Number(data.packets_sent ?? data.total_scanned ?? 0),
    avgLatencyMs: data.avg_latency_ms == null ? null : Number(data.avg_latency_ms),
    securityScore: Number.isFinite(securityScore) ? securityScore : 100,
    securityScoreFactors,
    attackSurface,
    threatIntelligence,
    misconfigurationSummary,
    exposureSummary,
    attackPaths,
    attackSimulations,
    recommendationsError: (data.recommendations_error ?? '').toString().trim(),
  };
  if (!Array.isArray(ports)) return { ports: [], detectedTechnologies: [], stats };
  const mapped = ports.map(mapOpenPort);
  const scanTechs = data.detected_technologies;
  return {
    ports: mapped,
    detectedTechnologies: collectDetectedTechnologies(
      mapped,
      Array.isArray(scanTechs) ? scanTechs : [],
    ),
    stats,
  };
}

export function hasBannerData(row) {
  return Boolean(row.raw_banner || row.welcome_message || row.server_response);
}

export function bannerPreview(row, maxLen = 48) {
  const text = row.welcome_message || row.raw_banner || row.server_response || '';
  if (!text) return '';
  const oneLine = text.replace(/\s+/g, ' ').trim();
  return oneLine.length <= maxLen ? oneLine : `${oneLine.slice(0, maxLen)}…`;
}
