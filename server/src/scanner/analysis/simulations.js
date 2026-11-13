import { DATABASE_PORTS, HTTP_PORTS } from '../constants.js'
import { bestPortByScore } from './attackPaths.js'

export function simulation(chainId, title, severity, steps, likelihood, recommendation, evidence, confidence = 'Inferred') {
  return {
    id: chainId,
    title,
    severity,
    steps,
    chain: steps.join(' → '),
    likelihood,
    recommendation,
    evidence: evidence.filter(Boolean).slice(0, 6),
    confidence,
  }
}

export function buildAttackSimulationRecommendations(openPorts, exposureSummary = null) {
  const simulations = []
  const publicExposure = Boolean(exposureSummary?.public_exposure)

  for (const port of openPorts) {
    const service = port.service || `TCP/${port.port_number}`
    const evidence = [
      `Port ${port.port_number} open`,
      port.exposure_severity?.finding,
      port.risk_reason,
    ]

    if (port.port_number === 22) {
      simulations.push(
        simulation(
          'ssh-credential-access',
          'SSH Credential Attack Simulation',
          publicExposure ? 'critical' : 'high',
          ['Open SSH', 'Credential Attack Risk', 'Potential Server Access'],
          publicExposure ? 'Elevated' : 'Moderate',
          'Run an authorized password-policy audit, disable password login where possible, enforce MFA, and restrict SSH to VPN or trusted IPs.',
          [...evidence, 'Remote login service observed', 'Credential attack risk inferred from exposed SSH']
        )
      )
    } else if (port.port_number === 3389) {
      simulations.push(
        simulation(
          'rdp-credential-access',
          'RDP Remote Access Simulation',
          'critical',
          ['Open RDP', 'Credential Attack Risk', 'Potential Interactive Access'],
          publicExposure ? 'Elevated' : 'Moderate',
          'Place RDP behind VPN or zero-trust access, require MFA, lock out brute-force attempts, and monitor successful remote logons.',
          [...evidence, 'Remote desktop service observed']
        )
      )
    } else if (port.port_number === 23) {
      simulations.push(
        simulation(
          'telnet-cleartext-access',
          'Telnet Credential Exposure Simulation',
          'critical',
          ['Open Telnet', 'Cleartext Credential Exposure', 'Potential Server Access'],
          'Elevated',
          'Disable Telnet and replace it with SSH over a restricted management network.',
          [...evidence, 'Cleartext authentication risk is inherent to Telnet']
        )
      )
    } else if (HTTP_PORTS.has(port.port_number)) {
      const webSteps = [`Open ${service}`, 'Web Reconnaissance']
      if (port.misconfigurations?.length) webSteps.push('Observed Misconfiguration Review')
      else if (port.cve_count) webSteps.push('Known Vulnerability Validation')
      else webSteps.push('Administrative Route Discovery')
      webSteps.push('Potential Application Access')

      simulations.push(
        simulation(
          `web-${port.port_number}-application-access`,
          'Web Application Attack Simulation',
          port.cve_critical_count
            ? 'critical'
            : port.misconfigurations?.length || port.cve_count
              ? 'high'
              : 'medium',
          webSteps,
          publicExposure && (port.misconfigurations?.length || port.cve_count) ? 'Elevated' : 'Moderate',
          'Validate authentication, patch the web stack, remove exposed admin routes, and fix reported web misconfigurations.',
          [
            ...evidence,
            port.misconfigurations?.length ? `${port.misconfigurations.length} misconfiguration(s)` : null,
            port.cve_count ? `${port.cve_count} CVE signal(s)` : null,
          ]
        )
      )
    } else if (DATABASE_PORTS.has(port.port_number)) {
      simulations.push(
        simulation(
          `db-${port.port_number}-data-access`,
          'Database Exposure Simulation',
          publicExposure ? 'critical' : 'high',
          [`Open ${service}`, 'Credential Reuse Risk', 'Potential Data Access'],
          publicExposure ? 'Elevated' : 'Moderate',
          'Bind the database to private interfaces, restrict source networks, rotate exposed credentials, and alert on direct database logins.',
          [...evidence, 'Database service observed']
        )
      )
    } else if (port.port_number === 445) {
      simulations.push(
        simulation(
          'smb-lateral-movement',
          'SMB Lateral Movement Simulation',
          publicExposure ? 'critical' : 'high',
          ['Open SMB', 'Share Enumeration Risk', 'Potential Lateral Movement'],
          publicExposure ? 'Elevated' : 'Moderate',
          'Block SMB from untrusted networks, audit shares, disable guest access, and require SMB signing.',
          [...evidence, 'SMB service observed']
        )
      )
    }
  }

  const vulnerable = bestPortByScore(
    openPorts.filter(
      (p) => p.exploit_availability?.public_exploit_available === true || p.cve_critical_count
    )
  )
  if (vulnerable) {
    simulations.push(
      simulation(
        `exploit-${vulnerable.port_number}-server-access`,
        'Curated Exploit-Signal Simulation',
        'critical',
        [`Open ${vulnerable.service}`, 'Curated Public-Exploit Signal', 'Potential Server Access'],
        'Elevated',
        'Prioritize patching this service, confirm compensating controls, and run only authorized exploit validation in a controlled test window.',
        [
          `Port ${vulnerable.port_number} open`,
          vulnerable.max_cvss_cve,
          vulnerable.exploit_availability?.public_exploit_available === true
            ? 'Curated public-exploit signal'
            : null,
        ]
      )
    )
  }

  const rank = { critical: 4, high: 3, medium: 2, low: 1 }
  const deduped = {}
  for (const item of simulations) deduped[item.id] = item

  return Object.values(deduped)
    .sort((a, b) => {
      const bySeverity = (rank[b.severity] ?? 2) - (rank[a.severity] ?? 2)
      if (bySeverity !== 0) return bySeverity
      return Number(b.likelihood === 'Elevated') - Number(a.likelihood === 'Elevated')
    })
    .slice(0, 8)
}
