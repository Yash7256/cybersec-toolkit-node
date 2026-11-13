export const SSH_PORTS = new Set([22])
export const HTTP_PORTS = new Set([80, 443, 8000, 8080, 8443, 8888, 3000, 5000])
export const HTTPS_PORTS = new Set([443, 8443])
export const SCREENSHOT_PORTS = new Set([80, 443, 8080])
export const FTP_PORTS = new Set([21])
export const PROXY_PORTS = new Set([8080, 3128, 8000, 8888])
export const WELCOME_PORTS = new Set([21, 22, 23, 25, 110, 143, 3306, 6379, 27017])
export const BANNER_PORTS = new Set([...WELCOME_PORTS, ...HTTP_PORTS])
export const WEAK_TLS_CIPHER_MARKERS = new Set(['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5'])

export const WEB_SECURITY_HEADERS = {
  'content-security-policy': 'Content-Security-Policy',
  'x-frame-options': 'X-Frame-Options',
  'x-content-type-options': 'X-Content-Type-Options',
}

export const HTTPS_SECURITY_HEADERS = {
  ...WEB_SECURITY_HEADERS,
  'strict-transport-security': 'Strict-Transport-Security',
}

export const EXPOSED_SERVICE_PORTS = new Set([21, 23, 445, 3306, 3389, 5432, 5900, 6379, 27017])
export const ADMIN_SERVICE_PORTS = new Set([22, 23, 445, 3389, 5900, 6379])
export const DATABASE_PORTS = new Set([3306, 5432, 6379, 27017])
export const REMOTE_ACCESS_PORTS = new Set([22, 23, 3389, 5900])
export const EXPOSURE_SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 }

export const MAX_BANNER_BYTES = 4096
export const MAX_BANNER_LINES = 100

export function shouldProbeTls(port) {
  return HTTPS_PORTS.has(port)
}

export function isHttpProbePort(port) {
  return HTTP_PORTS.has(port)
}

export function probeTimeoutFor(port, timeoutMs) {
  return BANNER_PORTS.has(port) ? Math.max(timeoutMs, 3000) : timeoutMs
}
