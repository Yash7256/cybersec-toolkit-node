export const SECURITY_HEADERS = [
  ['content-security-policy', 'high', 'Controls executable content', 'Define a restrictive policy'],
  ['strict-transport-security', 'high', 'Enforces HTTPS', 'Use max-age with includeSubDomains'],
  ['x-content-type-options', 'medium', 'Prevents MIME sniffing', 'Set nosniff'],
  ['x-frame-options', 'medium', 'Prevents clickjacking', 'Set DENY or SAMEORIGIN'],
  ['referrer-policy', 'low', 'Controls referrer leakage', 'Set strict-origin-when-cross-origin'],
  ['permissions-policy', 'low', 'Restricts browser features', 'Declare required features'],
]
