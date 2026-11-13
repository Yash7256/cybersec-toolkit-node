import { z } from 'zod'
import { safeHttp } from '../../net/safeHttp.js'
import { normalizeTarget, fetchHeaders } from './request.js'
import {
  analyzeSecurityHeaders,
  analyzeHsts,
  analyzeCsp,
  analyzeClickjacking,
} from './analysis/headers.js'
import { analyzeCookies } from './analysis/cookies.js'
import {
  analyzeDisclosure,
  analyzeCors,
  analyzeCompression,
  analyzeCache,
  allowedMethods,
  detectTechnologies,
} from './analysis/misc.js'
import { scoreResult } from './analysis/scoring.js'

export const RESULT_KEYS = [
  'url',
  'status_code',
  'headers',
  'redirects',
  'security_score',
  'risk_level',
  'technologies',
  'error',
  'tls_verification_skipped',
]

export const schema = z.object({
  target: z.string().trim().min(1).max(2048),
  path: z.string().default('/'),
})

export function createHttpHeadersDefinition({ client = safeHttp } = {}) {
  return {
    name: 'http_headers',
    toolEnum: 'HTTP_HEADERS',
    schema,
    touchesTarget: true,
    dedupeTtlSec: 120,
    normalize: normalizeTarget,
    async execute(input, ctx) {
      const result = await fetchHeaders({ input, ctx, client })
      const securityHeaders = analyzeSecurityHeaders(result.headers)
      const hsts = analyzeHsts(result.headers['strict-transport-security'])
      const csp = analyzeCsp(result.headers['content-security-policy'])
      const clickjacking = analyzeClickjacking(
        result.headers,
        result.headers['content-security-policy']
      )
      const cookies = analyzeCookies(
        result.headers['set-cookie'],
        new URL(input.url).protocol.slice(0, -1)
      )
      const disclosure = analyzeDisclosure(result.headers)
      const score = scoreResult({
        securityHeaders,
        hsts,
        csp,
        clickjacking,
        cookies,
        disclosure,
      })

      return {
        url: result.finalUrl,
        status_code: result.status,
        headers: result.headers,
        redirects: result.redirects,
        security_score: score.securityScore,
        risk_level: score.riskLevel,
        technologies: detectTechnologies(result.headers),
        security_headers: securityHeaders,
        hsts,
        csp,
        clickjacking,
        cookies,
        compression: analyzeCompression(result.headers),
        cache: analyzeCache(result.headers),
        cors: analyzeCors(result.headers),
        allowed_methods: allowedMethods(result.headers),
        disclosure,
        tls_verification_skipped: true,
        error: null,
      }
    },
    emptyResult: (input) => ({
      url: input.url ?? input.target,
      status_code: null,
      headers: {},
      redirects: [],
      security_score: 0,
      risk_level: 'unknown',
      technologies: [],
      error: null,
      tls_verification_skipped: true,
    }),
    summarize: (data) => ({
      statusCode: data.status_code,
      securityScore: data.security_score,
      riskLevel: data.risk_level,
      error: data.error,
    }),
  }
}

export const definition = createHttpHeadersDefinition()
