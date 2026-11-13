import { COMMON_PORTS, PORT_REGISTRY } from './data/portRegistry.js'

const SERVICE_RISK_KEYWORDS = [
  ['telnet', 'high', 'Telnet service detected'],
  ['rdp', 'high', 'Remote Desktop service'],
  ['vnc', 'high', 'VNC remote desktop'],
  ['redis', 'high', 'Redis in-memory datastore'],
  ['mongodb', 'high', 'MongoDB database'],
  ['smb', 'high', 'SMB file sharing'],
  ['microsoft-ds', 'high', 'SMB / Microsoft-DS'],
  ['ftp', 'medium', 'FTP file transfer'],
  ['smtp', 'medium', 'SMTP mail service'],
  ['mysql', 'medium', 'MySQL database'],
  ['postgresql', 'medium', 'PostgreSQL database'],
  ['http-proxy', 'medium', 'HTTP proxy or alternate web port'],
  ['https-alt', 'medium', 'Alternate HTTPS service'],
]

const SERVICE_FALLBACKS = [
  ['ssh', 'SSH', 'Secure remote login protocol for shell access and tunneling.', 'Can be brute-forced if exposed publicly or weak keys/passwords are used.'],
  ['ftp', 'FTP', 'File Transfer Protocol for uploading and downloading files.', 'Credentials and data travel in cleartext; anonymous uploads may be enabled.'],
  ['telnet', 'Telnet', 'Legacy remote terminal access to network devices and servers.', 'All traffic including passwords is sent unencrypted — high interception risk.'],
  ['http', 'HTTP', 'Unencrypted web traffic for websites and APIs.', 'Traffic can be intercepted or modified; outdated web apps increase exploit risk.'],
  ['https', 'HTTPS', 'Encrypted web traffic using TLS for websites and APIs.', 'Certificate or TLS misconfiguration can still weaken confidentiality.'],
  ['mysql', 'MySQL', 'Popular relational database server for application data storage.', 'Exposed databases are scanned for weak credentials and SQL injection chains.'],
  ['redis', 'Redis', 'In-memory key-value store used for caching and messaging.', 'Frequently left without authentication, allowing remote command execution.'],
  ['mongodb', 'MongoDB', 'Document-oriented NoSQL database for modern applications.', 'Historically many deployments allowed unauthenticated access from the internet.'],
  ['rdp', 'RDP', 'Remote Desktop Protocol for graphical Windows administration.', 'Common brute-force and exploit target when reachable from the internet.'],
  ['vnc', 'VNC', 'Virtual Network Computing for remote desktop viewing and control.', 'Often protected only by a password; many instances lack encryption.'],
  ['smtp', 'SMTP', 'Simple Mail Transfer Protocol for sending email between servers.', 'Open relays and user enumeration can enable spam or phishing abuse.'],
  ['dns', 'DNS', 'Domain Name System for resolving hostnames to IP addresses.', 'Zone transfers and recursion misconfigurations may leak internal network data.'],
]

export { COMMON_PORTS, PORT_REGISTRY }

export function getServiceForPort(port) {
  return PORT_REGISTRY[port]?.service ?? 'Unknown'
}

export function classifyPortRisk(port, service = null) {
  const info = PORT_REGISTRY[port]
  if (info) return [info.risk_level, info.risk_reason]

  const serviceKey = String(service ?? '').toLowerCase()
  for (const [needle, level, reason] of SERVICE_RISK_KEYWORDS) {
    if (serviceKey.includes(needle)) return [level, reason]
  }

  if (port >= 1 && port <= 1023) {
    return ['medium', `Well-known port ${port} exposed — verify service hardening`]
  }

  return ['medium', `Port ${port} open — review exposed service and firewall rules`]
}

export function getPortDescription(port, service = null) {
  const info = PORT_REGISTRY[port]
  if (info) {
    return {
      name: info.service,
      purpose: info.purpose,
      security_concern: info.security_concern,
    }
  }

  const serviceKey = String(service ?? '').toLowerCase()
  for (const [needle, name, purpose, concern] of SERVICE_FALLBACKS) {
    if (serviceKey.includes(needle)) {
      return { name, purpose, security_concern: concern }
    }
  }

  const label = service || 'Unknown'
  return {
    name: label,
    purpose: `Network service listening on port ${port} (${label}).`,
    security_concern: 'Review whether this port must be internet-facing and keep the service patched.',
  }
}
