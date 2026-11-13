import { describe, it, expect } from 'vitest'
import { addExploitAvailability } from '../../src/scanner/analysis/exploits.js'
import { calculateExposureSeverity } from '../../src/scanner/analysis/exposure.js'
import { calculateSecurityScore } from '../../src/scanner/analysis/securityScore.js'
import { calculateAttackSurface, attackSurfaceLevel } from '../../src/scanner/analysis/attackSurface.js'
import { buildAttackPathVisualization } from '../../src/scanner/analysis/attackPaths.js'
import { buildAttackSimulationRecommendations } from '../../src/scanner/analysis/simulations.js'
import { addMitreAttackMapping } from '../../src/scanner/analysis/mitre.js'

function port(portNumber, service, extra = {}) {
  return {
    port_number: portNumber,
    service,
    version: null,
    risk_level: 'medium',
    risk_reason: null,
    technologies: [],
    misconfigurations: [],
    exploit_availability: {},
    cve_result: null,
    cve_count: 0,
    cve_critical_count: 0,
    cve_high_count: 0,
    ...extra,
  }
}

describe('exploit availability', () => {
  it('matches curated Apache and near-miss versions', () => {
    const hit = port(80, 'HTTP', { version: 'Apache/2.4.49' })
    const miss = port(80, 'HTTP', { version: 'Apache/2.4.51' })
    addExploitAvailability([hit, miss])
    expect(hit.exploit_availability.public_exploit_available).toBe(true)
    expect(hit.exploit_availability.evidence).toEqual(expect.arrayContaining(['CVE-2021-41773']))
    expect(miss.exploit_availability.public_exploit_available).toBe(false)
  })
})

describe('exposure severity', () => {
  it('escalates public remote-access services', () => {
    const rdp = port(3389, 'RDP', { risk_level: 'medium' })
    const summary = calculateExposureSeverity('8.8.8.8', [rdp])
    expect(summary.public_exposure).toBe(true)
    expect(['high', 'critical']).toContain(rdp.exposure_severity.severity)
    expect(rdp.exposure_severity.factors).toEqual(expect.arrayContaining(['Remote access service']))
    expect(rdp.risk_level).not.toBe('medium')
  })

  it('keeps private targets lower and returns the empty shape', () => {
    const ssh = port(22, 'SSH')
    const summary = calculateExposureSeverity('10.0.0.5', [ssh])
    expect(summary.public_exposure).toBe(false)
    expect(ssh.exposure_severity.severity).toBe('medium')

    const empty = calculateExposureSeverity('10.0.0.5', [])
    expect(empty).toMatchObject({ highest_severity: 'low', highest_score: 0, critical: 0, high: 0, medium: 0, low: 0 })
  })

  it('raises severity for malicious threat intelligence', () => {
    const web = port(80, 'HTTP')
    const clean = calculateExposureSeverity('8.8.8.8', [web])
    const maliciousPort = port(80, 'HTTP')
    const malicious = calculateExposureSeverity('8.8.8.8', [maliciousPort], { reputation: 'Malicious' })
    expect(maliciousPort.exposure_severity.score).toBeGreaterThanOrEqual(web.exposure_severity.score)
    expect(maliciousPort.exposure_severity.factors).toContain('Malicious IP reputation')
    expect(malicious.highest_score).toBeGreaterThanOrEqual(clean.highest_score)
  })
})

describe('security score', () => {
  it('scores an empty scan at 100 and applies penalties', () => {
    expect(calculateSecurityScore({ openPorts: [] })).toEqual({ score: 100, factors: [] })

    const result = calculateSecurityScore({
      openPorts: [port(22, 'SSH', { risk_level: 'high', cve_count: 1, cve_high_count: 1 })],
    })
    expect(result.score).toBeLessThan(100)
    expect(result.factors.map((item) => item.category)).toEqual(
      expect.arrayContaining(['risky_ports', 'outdated_versions'])
    )
  })

  it('penalizes expired and self-signed TLS results from the cache only', () => {
    const cache = new Map([
      [443, { certificate: { is_expired: true }, is_self_signed: true, supports_tls12: true }],
    ])
    const result = calculateSecurityScore({ openPorts: [port(443, 'HTTPS')], sslCache: cache })
    expect(result.factors.map((item) => item.label)).toEqual(
      expect.arrayContaining([
        'Expired TLS certificate on port 443.',
        'Self-signed TLS certificate on port 443.',
      ])
    )
  })
})

describe('attack surface and paths', () => {
  it('maps score bands and builds factors', () => {
    expect(attackSurfaceLevel(70)).toBe('CRITICAL')
    expect(attackSurfaceLevel(45)).toBe('HIGH')
    expect(attackSurfaceLevel(20)).toBe('MEDIUM')
    expect(attackSurfaceLevel(19)).toBe('LOW')

    const surface = calculateAttackSurface([port(3389, 'RDP', { risk_level: 'critical' })])
    expect(surface.level).toBe('MEDIUM')
    expect(surface.factors.length).toBeGreaterThan(0)
    expect(surface.publicly_exposed_services[0]).toMatchObject({ port: 3389, service: 'RDP' })
  })

  it('returns the empty graph and a populated graph with simulated chains', () => {
    const empty = buildAttackPathVisualization([], { public_exposure: true })
    expect(empty.nodes).toEqual([])
    expect(empty.edges).toEqual([])
    expect(empty.summary).toContain('No attack path')

    const ports = [port(22, 'SSH'), port(80, 'HTTP'), port(3306, 'MySQL', { risk_level: 'high' })]
    const exposure = calculateExposureSeverity('8.8.8.8', ports)
    addMitreAttackMapping(ports)
    const graph = buildAttackPathVisualization(ports, exposure)
    expect(graph.nodes.length).toBeGreaterThan(0)
    expect(graph.edges.length).toBeGreaterThan(0)

    const simulations = buildAttackSimulationRecommendations(ports, exposure)
    expect(simulations.length).toBeGreaterThan(0)
    expect(simulations[0]).toHaveProperty('chain')
  })
})
