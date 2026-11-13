import { FINGERPRINTS, LANGUAGE_PATTERNS, LOGIN_KEYWORDS } from './constants.js'

export function fingerprintPages(pages) {
  const fingerprint = {
    cms: null,
    framework: null,
    server: null,
    languages: [],
    libraries: [],
    login_paths: [],
  }

  const combined = pages.slice(0, 5).map((page) => page.body_snippet ?? '').join(' ')
  const headersCombined = pages
    .slice(0, 3)
    .flatMap((page) => Object.entries(page.response_headers ?? {}).map(([key, value]) => `${key}: ${value}`))
    .join(' ')
  const blob = `${combined} ${headersCombined}`.toLowerCase()

  const server = pages[0]?.response_headers?.server
  fingerprint.server = server ? String(server) : null

  for (const [pattern, name, category] of FINGERPRINTS) {
    if (!new RegExp(pattern, 'i').test(blob)) continue
    if (category === 'cms' && !fingerprint.cms) fingerprint.cms = name
    else if (category === 'framework' && !fingerprint.framework) fingerprint.framework = name
    else if (category === 'library' && !fingerprint.libraries.includes(name)) fingerprint.libraries.push(name)
  }

  for (const [language, patterns] of LANGUAGE_PATTERNS) {
    if (patterns.some((pattern) => new RegExp(pattern, 'i').test(blob))) {
      if (!fingerprint.languages.includes(language)) fingerprint.languages.push(language)
    }
  }

  for (const page of pages) {
    const url = String(page.url ?? '').toLowerCase()
    if (LOGIN_KEYWORDS.some((keyword) => url.includes(keyword)) && !fingerprint.login_paths.includes(page.url)) {
      fingerprint.login_paths.push(page.url)
    }
  }

  return fingerprint
}
