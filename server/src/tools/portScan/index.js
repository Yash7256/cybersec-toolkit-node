import { env as defaultEnv } from '../../config/env.js'
import { schema, inputShape } from './schema.js'
import { scanPorts } from '../../scanner/engine.js'
import { COMMON_PORTS } from '../../scanner/data/portRegistry.js'
import { HTTPS_PORTS } from '../../scanner/constants.js'
import { addServiceFingerprints } from '../../scanner/fingerprint.js'
import { createCveDetector, attachCvesToPort } from '../../scanner/cve/detect.js'
import { detectMisconfigurations } from '../../scanner/probes/index.js'
import { checkThreatIntelligence, emptyThreatIntelForScan } from '../../scanner/intel/threatIntel.js'
import { addExploitAvailability } from '../../scanner/analysis/exploits.js'
import { calculateExposureSeverity } from '../../scanner/analysis/exposure.js'
import { buildAttackPathVisualization } from '../../scanner/analysis/attackPaths.js'
import { buildAttackSimulationRecommendations } from '../../scanner/analysis/simulations.js'
import { addMitreAttackMapping } from '../../scanner/analysis/mitre.js'
import { calculateSecurityScore } from '../../scanner/analysis/securityScore.js'
import { calculateAttackSurface } from '../../scanner/analysis/attackSurface.js'
import { definition as sslDefinition } from '../ssl/index.js'

const DEFAULT_PORTS = Object.keys(COMMON_PORTS).map(Number).sort((a, b) => a - b)

function emptyPortScanResult(input = {}) {
  return {
    target: input.target ?? null,
    total_scanned: 0,
    open_ports_count: 0,
    open_ports: [],
    scan_duration_seconds: 0,
    packets_sent: 0,
    avg_latency_ms: null,
    detected_technologies: [],
    security_score: 100,
    security_score_factors: [],
    attack_surface: {},
    threat_intelligence: {},
    misconfiguration_summary: {},
    exposure_summary: {},
    attack_paths: {},
    attack_simulations: [],
    recommendations_error: null,
    error: null,
    scanned_ip: null,
    closed_count: 0,
    filtered_count: 0,
    max_concurrent_effective: null,
    cve_error: null,
    intel_error: null,
  }
}

async function mapLimit(items, limit, fn) {
  let index = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) {
      const current = items[index]
      index += 1
      await fn(current)
    }
  })
  await Promise.all(workers)
}

function uniqueTechnologies(openPorts) {
  const seen = new Set()
  for (const port of openPorts) {
    for (const tech of port.technologies ?? []) {
      if (tech) seen.add(String(tech))
    }
  }
  return [...seen].sort()
}

export function createPortScanDefinition({
  env = defaultEnv,
  scanner = scanPorts,
  sslAudit = sslDefinition.execute.bind(sslDefinition),
  createDetector = createCveDetector,
  misconfigDetector = detectMisconfigurations,
  intelCheck = checkThreatIntelligence,
  now = Date.now,
} = {}) {
  return {
    name: 'port_scan',
    toolEnum: 'PORT_SCAN',
    schema,
    inputShape,
    touchesTarget: true,
    mode: 'async',
    timeoutMs: env.SCAN_TIMEOUT_MS,
    dedupeTtlSec: 0,
    normalize(input) {
      const target = input.target.trim()
      const cleaned = /^https?:\/\//i.test(target) ? new URL(target).hostname : target
      return { ...input, target: cleaned }
    },
    async execute(input, ctx = {}) {
      const runEnv = ctx.env ?? env
      const signal = ctx.signal
      const reportProgress = ctx.reportProgress ?? (() => {})
      const started = now()
      const address = ctx.target?.addresses?.[0]
      if (!address) {
        return { ...emptyPortScanResult(input), error: 'Target is not allowed' }
      }

      const hostname = ctx.target?.targetKey ?? input.target
      const ports = input.ports?.length ? input.ports : DEFAULT_PORTS
      const maxConcurrent = Math.max(
        1,
        Math.min(input.max_concurrent ?? runEnv.SCAN_DEFAULT_CONCURRENCY, runEnv.SCAN_MAX_CONCURRENCY)
      )
      const timeoutMs = Math.round(input.timeout * 1000)

      const scan = await scanner({
        address: address.address,
        family: address.family,
        hostname,
        ports,
        timeoutMs,
        concurrency: maxConcurrent,
        ratePerSec: runEnv.SCAN_RATE_CONN_PER_SEC,
        signal,
        onProgress: (fraction) => reportProgress(Math.round(fraction * 55)),
      })

      const openPorts = addServiceFingerprints(scan.open)
      const sslCache = new Map()
      const httpsPorts = openPorts.filter((port) => HTTPS_PORTS.has(port.port_number))

      reportProgress(58)
      await mapLimit(httpsPorts, 3, async (port) => {
        try {
          const result = await sslAudit(
            { host: hostname, port: port.port_number },
            {
              target: { addresses: [address] },
              signal,
              env: runEnv,
            }
          )
          sslCache.set(port.port_number, result)
        } catch (err) {
          sslCache.set(port.port_number, err instanceof Error ? err : new Error('TLS audit failed'))
        }
      })

      reportProgress(65)

      const detector = createDetector({ env: runEnv })
      const versionStrings = [...new Set(openPorts.map((port) => port.version).filter(Boolean))]
      const [cveByVersion, misconfigurationSummary, threatIntelligence] = await Promise.all([
        versionStrings.length ? detector.detectCvesBatch(versionStrings, { signal }) : Promise.resolve({}),
        input.include_misconfigurations
          ? misconfigDetector({
              address: address.address,
              family: address.family,
              hostname,
              openPorts,
              timeoutMs,
              sslCache,
              signal,
            })
          : Promise.resolve({ total: 0, critical: 0, high: 0, medium: 0, low: 0, categories: [] }),
        input.include_threat_intel
          ? intelCheck({ ip: address.address, env: runEnv })
          : Promise.resolve(emptyThreatIntelForScan(address.address, 'Threat intelligence disabled.')),
      ])

      reportProgress(90)

      for (const port of openPorts) {
        if (port.version && cveByVersion[port.version]) {
          attachCvesToPort(port, cveByVersion[port.version])
        } else {
          attachCvesToPort(port, null)
        }
      }

      const cveError = versionStrings.length ? detector.error ?? null : null
      const intelError = threatIntelligence?.error ?? null

      addExploitAvailability(openPorts)
      const exposureSummary = calculateExposureSeverity(address.address, openPorts, threatIntelligence)
      addMitreAttackMapping(openPorts)
      const security = calculateSecurityScore({ openPorts, sslCache })
      const attackSurface = calculateAttackSurface(openPorts)
      const attackPaths = buildAttackPathVisualization(openPorts, exposureSummary)
      const attackSimulations = buildAttackSimulationRecommendations(openPorts, exposureSummary)

      reportProgress(100)

      const result = emptyPortScanResult(input)
      return {
        ...result,
        target: input.target,
        scanned_ip: address.address,
        total_scanned: scan.total_scanned,
        open_ports_count: openPorts.length,
        open_ports: openPorts,
        scan_duration_seconds: Math.round(((now() - started) / 1000) * 100) / 100,
        packets_sent: scan.packets_sent,
        avg_latency_ms: scan.avg_latency_ms,
        closed_count: scan.closed_count,
        filtered_count: scan.filtered_count,
        max_concurrent_effective: maxConcurrent,
        detected_technologies: uniqueTechnologies(openPorts),
        security_score: security.score,
        security_score_factors: security.factors,
        attack_surface: attackSurface,
        threat_intelligence: threatIntelligence,
        misconfiguration_summary: misconfigurationSummary,
        exposure_summary: exposureSummary,
        attack_paths: attackPaths,
        attack_simulations: attackSimulations,
        recommendations_error: null,
        cve_error: cveError,
        intel_error: intelError,
        error: scan.aborted ? 'Scan cancelled' : null,
      }
    },
    emptyResult: emptyPortScanResult,
    summarize: (data) => ({
      openPorts: data.open_ports_count ?? 0,
      scanned: data.total_scanned ?? 0,
      securityScore: data.security_score ?? null,
      highestSeverity: data.exposure_summary?.highest_severity ?? null,
      cveCount: (data.open_ports ?? []).reduce((sum, port) => sum + (port.cve_count ?? 0), 0),
    }),
  }
}

export const definition = createPortScanDefinition()
