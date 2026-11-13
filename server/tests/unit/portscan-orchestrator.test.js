import { describe, it, expect, vi } from 'vitest'
import { createPortScanDefinition } from '../../src/tools/portScan/index.js'
import { schema } from '../../src/tools/portScan/schema.js'
import { PORT_SCAN_RESULT_KEYS } from '../../src/tools/portScan/contract.js'

const env = {
  SCAN_MAX_CONCURRENCY: 50,
  SCAN_DEFAULT_CONCURRENCY: 10,
  SCAN_RATE_CONN_PER_SEC: 100,
  SCAN_TIMEOUT_MS: 10000,
  NVD_MIN_CVSS_SCORE: 5,
  NVD_MAX_RESULTS_PER_SERVICE: 10,
  NVD_CACHE_TTL_HOURS: 24,
}

function openPort(number, service, version, extra = {}) {
  return {
    port_number: number,
    service,
    status: 'open',
    version,
    raw_banner: version,
    welcome_message: null,
    server_response: null,
    risk_level: 'medium',
    risk_reason: null,
    service_description: null,
    service_security_concern: null,
    technologies: [],
    screenshot: null,
    screenshot_url: null,
    recommendation: null,
    recommendation_reason: null,
    recommendation_priority: null,
    mitre_attack: [],
    potential_threat: null,
    exploit_availability: {},
    misconfigurations: [],
    exposure_severity: {},
    cve_result: null,
    cve_count: 0,
    cve_critical_count: 0,
    cve_high_count: 0,
    cve_medium_count: 0,
    cve_low_count: 0,
    max_cvss_score: null,
    max_cvss_severity: null,
    max_cvss_cve: null,
    fingerprint: {},
    ...extra,
  }
}

describe('port scan orchestrator', () => {
  it('assembles the result contract and shares the TLS cache across analyses', async () => {
    const progress = []
    const sslAudit = vi.fn(async () => ({
      error: null,
      tls_version: 'TLSv1.2',
      is_self_signed: true,
      supports_tls12: true,
      certificate: { is_expired: true, days_remaining: -3 },
    }))
    const detector = {
      detectCvesBatch: vi.fn(async () => ({
        'OpenSSH 9.6p1': {
          service_name: 'openssh',
          version: 'OpenSSH 9.6p1',
          cves: [
            {
              cve_id: 'CVE-2024-6387',
              description: 'regreSSHion',
              severity: 'CRITICAL',
              cvss_score: 9.8,
              cvss_vector: null,
              published_date: null,
              url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',
            },
          ],
          total_count: 1,
          critical_count: 1,
          high_count: 0,
          medium_count: 0,
          low_count: 0,
        },
      })),
      error: null,
    }
    const definition = createPortScanDefinition({
      env,
      scanner: async () => ({
        open: [openPort(22, 'SSH', 'OpenSSH 9.6p1'), openPort(443, 'HTTPS', null)],
        total_scanned: 2,
        open_ports_count: 2,
        closed_count: 0,
        filtered_count: 0,
        packets_sent: 2,
        avg_latency_ms: 4.2,
        scan_duration_seconds: 0.2,
        aborted: false,
      }),
      sslAudit,
      createDetector: () => detector,
      misconfigDetector: async () => ({ total: 1, high: 1, critical: 0, medium: 0, low: 0, categories: ['weak_ssl'] }),
      intelCheck: async () => ({ reputation: 'Malicious', error: null }),
    })

    const input = schema.parse({ target: 'scanme.example', ports: [22, 443] })
    const result = await definition.execute(input, {
      target: { targetKey: 'scanme.example', addresses: [{ address: '93.184.216.34', family: 4 }] },
      env,
      reportProgress: (pct) => progress.push(pct),
    })

    expect(Object.keys(result).sort()).toEqual([...PORT_SCAN_RESULT_KEYS].sort())
    expect(sslAudit).toHaveBeenCalledTimes(1)
    expect(result.scanned_ip).toBe('93.184.216.34')
    expect(result.open_ports_count).toBe(2)
    const ssh = result.open_ports.find((port) => port.port_number === 22)
    expect(ssh.cve_critical_count).toBe(1)
    expect(ssh.max_cvss_score).toBe(9.8)
    expect(ssh.exploit_availability.public_exploit_available).toBe(true)
    expect(ssh.mitre_attack.length).toBeGreaterThan(0)
    expect(ssh.fingerprint.confidence).toBeGreaterThan(0)
    expect(result.security_score).toBeLessThan(100)
    expect(result.threat_intelligence.reputation).toBe('Malicious')
    expect(result.exposure_summary.public_exposure).toBe(true)
    expect(result.attack_paths.nodes.length).toBeGreaterThan(0)
    expect(result.attack_simulations.length).toBeGreaterThan(0)
    expect(result.misconfiguration_summary.high).toBe(1)
    expect(progress.at(-1)).toBe(100)
    expect(definition.summarize(result)).toMatchObject({
      openPorts: 2,
      scanned: 2,
      cveCount: 1,
    })
  })

  it('honors include flags and degrades enrichment errors', async () => {
    const misconfig = vi.fn()
    const intel = vi.fn()
    const definition = createPortScanDefinition({
      env,
      scanner: async () => ({
        open: [openPort(80, 'HTTP', null)],
        total_scanned: 1,
        open_ports_count: 1,
        closed_count: 0,
        filtered_count: 0,
        packets_sent: 1,
        avg_latency_ms: null,
        scan_duration_seconds: 0.1,
        aborted: false,
      }),
      createDetector: () => ({
        detectCvesBatch: async () => ({}),
        error: 'Lookup service unavailable',
      }),
      misconfigDetector: misconfig,
      intelCheck: intel,
    })
    const input = schema.parse({
      target: 'scanme.example',
      ports: [80],
      include_misconfigurations: false,
      include_threat_intel: false,
    })
    const result = await definition.execute(input, {
      target: { targetKey: 'scanme.example', addresses: [{ address: '93.184.216.34', family: 4 }] },
      env,
      reportProgress: () => {},
    })
    expect(misconfig).not.toHaveBeenCalled()
    expect(intel).not.toHaveBeenCalled()
    expect(result.misconfiguration_summary.total).toBe(0)
    expect(result.threat_intelligence.reputation).toBe('Not checked')
    expect(result.cve_error).toBeNull()
  })
})
