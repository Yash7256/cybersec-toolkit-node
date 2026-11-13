/**
 * Port service descriptions for hover tooltips in the Port Scanner.
 */

const PORT_DESCRIPTIONS = {
  21: {
    name: 'FTP',
    purpose: 'File Transfer Protocol for uploading and downloading files.',
    concern: 'Credentials and data travel in cleartext; anonymous uploads may be enabled.',
  },
  22: {
    name: 'SSH',
    purpose: 'Secure remote login protocol for shell access and tunneling.',
    concern: 'Can be brute-forced if exposed publicly or weak keys/passwords are used.',
  },
  23: {
    name: 'Telnet',
    purpose: 'Legacy remote terminal access to network devices and servers.',
    concern: 'All traffic including passwords is sent unencrypted — high interception risk.',
  },
  25: {
    name: 'SMTP',
    purpose: 'Simple Mail Transfer Protocol for sending email between servers.',
    concern: 'Open relays and user enumeration can enable spam or phishing abuse.',
  },
  53: {
    name: 'DNS',
    purpose: 'Domain Name System for resolving hostnames to IP addresses.',
    concern: 'Zone transfers and recursion misconfigurations may leak internal network data.',
  },
  80: {
    name: 'HTTP',
    purpose: 'Unencrypted web traffic for websites and APIs.',
    concern: 'Traffic can be intercepted or modified; outdated web apps increase exploit risk.',
  },
  110: {
    name: 'POP3',
    purpose: 'Post Office Protocol for downloading email from a mail server.',
    concern: 'Usernames and passwords are often transmitted without encryption.',
  },
  143: {
    name: 'IMAP',
    purpose: 'Internet Message Access Protocol for remote mailbox management.',
    concern: 'Cleartext login exposes mail credentials on untrusted networks.',
  },
  443: {
    name: 'HTTPS',
    purpose: 'Encrypted web traffic using TLS for websites and APIs.',
    concern: 'Certificate or TLS misconfiguration can still weaken confidentiality.',
  },
  445: {
    name: 'SMB',
    purpose: 'Server Message Block for Windows file and printer sharing.',
    concern: 'Frequent target for ransomware and lateral movement (e.g. EternalBlue).',
  },
  993: {
    name: 'IMAPS',
    purpose: 'IMAP over TLS for encrypted remote mailbox access.',
    concern: 'Weak TLS settings or expired certificates reduce protection.',
  },
  995: {
    name: 'POP3S',
    purpose: 'POP3 over TLS for encrypted mail download.',
    concern: 'Misconfigured TLS or credential stuffing still pose login risk.',
  },
  3306: {
    name: 'MySQL',
    purpose: 'Popular relational database server for application data storage.',
    concern: 'Exposed databases are scanned for weak credentials and SQL injection chains.',
  },
  3389: {
    name: 'RDP',
    purpose: 'Remote Desktop Protocol for graphical Windows administration.',
    concern: 'Common brute-force and exploit target when reachable from the internet.',
  },
  5432: {
    name: 'PostgreSQL',
    purpose: 'Advanced open-source relational database server.',
    concern: 'Public exposure invites credential attacks and privilege escalation attempts.',
  },
  5900: {
    name: 'VNC',
    purpose: 'Virtual Network Computing for remote desktop viewing and control.',
    concern: 'Often protected only by a password; many instances lack encryption.',
  },
  6379: {
    name: 'Redis',
    purpose: 'In-memory key-value store used for caching and messaging.',
    concern: 'Frequently left without authentication, allowing remote command execution.',
  },
  8080: {
    name: 'HTTP-Proxy',
    purpose: 'Alternate HTTP port for proxies, dev servers, or admin panels.',
    concern: 'May expose management interfaces or unpatched application backends.',
  },
  8443: {
    name: 'HTTPS-Alt',
    purpose: 'Alternate HTTPS port for web apps, proxies, or admin UIs.',
    concern: 'Non-standard TLS services are easy to misconfigure or forget to patch.',
  },
  27017: {
    name: 'MongoDB',
    purpose: 'Document-oriented NoSQL database for modern applications.',
    concern: 'Historically many deployments allowed unauthenticated access from the internet.',
  },
};

const SERVICE_FALLBACKS = [
  ['ssh', 22],
  ['ftp', 21],
  ['telnet', 23],
  ['https', 443],
  ['http', 80],
  ['mysql', 3306],
  ['redis', 6379],
  ['mongodb', 27017],
  ['rdp', 3389],
  ['vnc', 5900],
  ['smtp', 25],
  ['dns', 53],
  ['postgres', 5432],
];

export function getPortDescription(
  port,
  service = '',
  purposeFromApi = '',
  concernFromApi = '',
) {
  if (purposeFromApi?.trim() && concernFromApi?.trim()) {
    const local = PORT_DESCRIPTIONS[port];
    return {
      port,
      name: local?.name || service || 'Unknown',
      purpose: purposeFromApi.trim(),
      concern: concernFromApi.trim(),
    };
  }
  if (PORT_DESCRIPTIONS[port]) {
    return { port, ...PORT_DESCRIPTIONS[port] };
  }
  const key = service.toLowerCase();
  for (const [needle, refPort] of SERVICE_FALLBACKS) {
    if (key.includes(needle) && PORT_DESCRIPTIONS[refPort]) {
      return { port, ...PORT_DESCRIPTIONS[refPort] };
    }
  }
  const label = service || 'Unknown';
  return {
    port,
    name: label,
    purpose: `Network service listening on port ${port} (${label}).`,
    concern: 'Review whether this port must be internet-facing and keep the service patched.',
  };
}
