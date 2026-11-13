export function analyzeCookies(setCookie, scheme = 'https') {
  const values = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : []
  return values.map((raw) => {
    const text = String(raw); const lower = text.toLowerCase()
    const secure = /(?:^|;)\s*secure(?:;|$)/i.test(text)
    const httpOnly = /(?:^|;)\s*httponly(?:;|$)/i.test(text)
    const sameSite = text.match(/samesite\s*=\s*([^;]+)/i)?.[1]?.toLowerCase() ?? null
    const issues = []
    if (scheme === 'https' && !secure) issues.push('missing_secure')
    if (!httpOnly) issues.push('missing_httponly')
    if (sameSite === 'none' && !secure) issues.push('samesite_none_without_secure')
    return { name: text.split('=', 1)[0], secure, httpOnly, sameSite, issues, risk: issues.length ? 'medium' : 'low', raw: lower }
  })
}
