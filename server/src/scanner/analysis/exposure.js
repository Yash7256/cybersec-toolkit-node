import {
  ADMIN_SERVICE_PORTS,
  DATABASE_PORTS,
  EXPOSURE_SEVERITY_RANK,
  HTTP_PORTS,
  REMOTE_ACCESS_PORTS,
} from '../constants.js'
import { isPublicIp } from '../ip.js'

export function exposureLevel(score) {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 35) return 'medium'
  return 'low'
}

export function promoteRiskLevel(current, incoming) {
  const currentRank = EXPOSURE_SEVERITY_RANK[String(current || 'medium').toLowerCase()] ?? 2
  const incomingRank = EXPOSURE_SEVERITY_RANK[String(incoming || 'medium').toLowerCase()] ?? 2
  return incomingRank > currentRank ? incoming : current
}

export function exposureFinding(port, publicExposure, severity) {
  const prefix = `${severity.replace(/^./, (c) => c.toUpperCase())} Exposure`
  if (publicExposure && port.port_number === 3389) {
    return `${prefix}: RDP is publicly reachable; this scan did not verify a VPN or access-gateway boundary.`
  }
  if (publicExposure && port.port_number === 22) {
    return `${prefix}: SSH is publicly reachable and commonly targeted for credential attacks.`
  }
  if (publicExposure && port.port_number === 23) {
    return `${prefix}: Telnet is publicly reachable and uses cleartext authentication.`
  }
  if (publicExposure && port.port_number === 445) {
    return `${prefix}: SMB is publicly reachable, which increases share-enumeration and lateral-movement risk.`
  }
  if (publicExposure && DATABASE_PORTS.has(port.port_number)) {
    return `${prefix}: ${port.service} database service is publicly reachable.`
  }
  if (publicExposure && HTTP_PORTS.has(port.port_number)) {
    return `${prefix}: Web service is publicly reachable and adds application attack surface.`
  }
  if (publicExposure) {
    return `${prefix}: ${port.service} on TCP/${port.port_number} is reachable from the internet.`
  }
  return `${prefix}: ${port.service} on TCP/${port.port_number} is reachable on the scanned network.`
}

export function exposureRecommendation(port, publicExposure) {
  if (publicExposure && port.port_number === 3389) {
    return 'Place RDP behind a VPN or zero-trust access gateway, restrict source IPs, and require MFA.'
  }
  if (publicExposure && port.port_number === 22) {
    return 'Restrict SSH to trusted IPs or VPN, disable password login, and enforce key-based authentication with MFA where possible.'
  }
  if (publicExposure && port.port_number === 23) {
    return 'Disable Telnet and use SSH over a restricted management network.'
  }
  if (publicExposure && port.port_number === 445) {
    return 'Block SMB from the internet and allow it only inside trusted private networks.'
  }
  if (publicExposure && DATABASE_PORTS.has(port.port_number)) {
    return 'Bind the database to private interfaces, require authentication, and allow access only from application hosts or VPN ranges.'
  }
  if (publicExposure && HTTP_PORTS.has(port.port_number)) {
    return 'Keep the web stack patched, enforce TLS/security headers, and place administrative paths behind authentication.'
  }
  return 'Restrict access to trusted networks and close the service if it is not required.'
}

export function calculateExposureSeverity(ip, openPorts, threatIntelligence = null) {
  const publicExposure = isPublicIp(ip)
  const reputation = threatIntelligence?.reputation ?? 'Unknown'
  const summaryCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  let highest = {
    severity: 'low',
    score: 0,
    finding: 'No open-port exposure findings were generated.',
    port: null,
  }

  for (const port of openPorts) {
    let score = 10
    const factors = []
    if (publicExposure) {
      score += 20
      factors.push('Publicly reachable IP')
    } else {
      factors.push('Reachable on scanned network')
    }

    if (REMOTE_ACCESS_PORTS.has(port.port_number)) {
      score += 30
      factors.push('Remote access service')
    }
    if (ADMIN_SERVICE_PORTS.has(port.port_number)) {
      score += 18
      factors.push('Administrative service')
    }
    if (DATABASE_PORTS.has(port.port_number)) {
      score += 24
      factors.push('Database service')
    }
    if (HTTP_PORTS.has(port.port_number)) {
      score += 10
      factors.push('Web application surface')
    }

    if (port.port_number === 3389 && publicExposure) {
      score += 35
      factors.push('RDP public reachability; VPN boundary not verified')
    } else if (port.port_number === 23) {
      score += 30
      factors.push('Cleartext Telnet service')
    } else if (port.port_number === 445 && publicExposure) {
      score += 30
      factors.push('Internet-exposed SMB')
    }

    if (port.cve_critical_count) {
      score += Math.min(25, port.cve_critical_count * 12)
      factors.push('Critical CVE signals')
    } else if (port.cve_high_count) {
      score += Math.min(18, port.cve_high_count * 8)
      factors.push('High CVE signals')
    } else if (port.cve_count) {
      score += 6
      factors.push('Known CVE signals')
    }

    if (port.exploit_availability?.public_exploit_available === true) {
      score += 20
      factors.push('Curated public-exploit signal')
    }

    const misconfigSeverities = new Set(
      (port.misconfigurations ?? []).map((item) => String(item.severity || 'medium').toLowerCase())
    )
    if (misconfigSeverities.has('critical')) {
      score += 25
      factors.push('Critical misconfiguration')
    } else if (misconfigSeverities.has('high')) {
      score += 15
      factors.push('High misconfiguration')
    } else if (misconfigSeverities.has('medium')) {
      score += 8
      factors.push('Medium misconfiguration')
    }

    if (reputation === 'Malicious') {
      score += 18
      factors.push('Malicious IP reputation')
    } else if (reputation === 'Suspicious') {
      score += 10
      factors.push('Suspicious IP reputation')
    }

    score = Math.min(100, score)
    const severity = exposureLevel(score)
    const finding = exposureFinding(port, publicExposure, severity)
    port.exposure_severity = {
      score,
      severity,
      public_exposure: publicExposure,
      finding,
      factors: factors.slice(0, 8),
      recommendation: exposureRecommendation(port, publicExposure),
    }

    const promoted = promoteRiskLevel(port.risk_level, severity)
    if (promoted !== port.risk_level) {
      port.risk_level = promoted
      port.risk_reason = finding
    }

    summaryCounts[severity] += 1
    if (score > highest.score) {
      highest = { severity, score, finding, port: port.port_number }
    }
  }

  return {
    public_exposure: publicExposure,
    highest_severity: highest.severity,
    highest_score: highest.score,
    highest_finding: highest.finding,
    highest_port: highest.port,
    critical: summaryCounts.critical,
    high: summaryCounts.high,
    medium: summaryCounts.medium,
    low: summaryCounts.low,
  }
}
