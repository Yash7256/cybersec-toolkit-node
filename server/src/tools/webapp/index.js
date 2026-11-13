import { env as defaultEnv } from '../../config/env.js'
import { schema, inputShape, AUTH_GATE_MESSAGE } from './schema.js'
import { crawlSite } from './crawl.js'
import { createWebClient } from './client.js'
import { fingerprintPages } from './fingerprint.js'
import {
  checkHeaders, checkHttpMethods, checkCors, checkExposedFiles, checkAdminPanels,
  checkDirectoryListing, checkOpenRedirect, checkRobots, checkTls,
} from './passive.js'
import { checkDnsEmailSecurity } from './dnsEmail.js'
import { checkCsrf, checkSqli, checkXss, checkSsti, checkPathTraversal } from './active.js'
import { buildResult, dedupeAndSort } from './result.js'
import { getDomain } from 'tldts'
import AppError from '../../utils/AppError.js'
import * as targetAuthRepo from '../../db/repos/targetAuthRepo.js'
import { getProducerConnection } from '../../queue/connections.js'

export const RESULT_KEYS = Object.freeze([
  'target', 'base_url', 'pages_crawled', 'vulnerabilities', 'total_vulns',
  'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count',
  'scan_duration', 'fingerprint', 'screenshot', 'ai_summary', 'error',
])

function makeBaseUrl(target) {
  return /^https?:\/\//i.test(target) ? target.replace(/\/+$/, '') : `https://${target}`
}

export function createWebappDefinition({ env = defaultEnv, crawl = crawlSite, clientFactory = createWebClient } = {}) {
  return {
    name: 'webapp_scan',
    toolEnum: 'WEBAPP_SCAN',
    schema,
    inputShape,
    touchesTarget: true,
    mode: 'async',
    timeoutMs: env.WEBAPP_SCAN_TOTAL_TIMEOUT_SEC ? env.WEBAPP_SCAN_TOTAL_TIMEOUT_SEC * 1000 : (env.WEBAPP_SCAN_TIMEOUT_MS ?? 120000),
    dedupeTtlSec: 0,
    normalize(input) {
      const requestedTarget = input.target
      const host = /^https?:\/\//i.test(requestedTarget) ? new URL(requestedTarget).hostname : requestedTarget
      return { ...input, target: host, requestedTarget }
    },
    async beforeSubmit(input, { req, target, env: runEnv }) {
      if (!input.active) return
      const domain = getDomain(target.targetKey) ?? target.targetKey
      const active = await targetAuthRepo.getActive(req.user.id, domain)
      if (!active && input.confirm_authorized !== true) {
        throw new AppError(422, 'AUTH_GATE_REQUIRED', AUTH_GATE_MESSAGE)
      }
      if (!active) {
        const attested = await targetAuthRepo.attest(req.user.id, domain, {
          env: runEnv, ip: req.ip, userAgent: req.get('user-agent'),
        })
        if (attested.cooldown) throw new AppError(429, 'AUTH_ATTESTATION_COOLDOWN', 'Authorization was recently attested; try again later.')
      }
      const redis = getProducerConnection()
      const key = `${runEnv.QUEUE_PREFIX}:webapp-scan:${req.user.id}:${new Date().toISOString().slice(0, 10)}`
      const count = await redis.incr(key)
      if (count === 1) await redis.expire(key, 172800)
      if (count > runEnv.WEBAPP_SCAN_USER_LIMIT_PER_DAY) {
        await redis.decr(key)
        throw new AppError(429, 'WEBAPP_DAILY_LIMIT', 'Web-app scan daily limit reached.')
      }
    },
    emptyResult(input = {}) {
      return buildResult({ target: input.requestedTarget ?? input.target, baseUrl: makeBaseUrl(input.requestedTarget ?? input.target), vulnerabilities: [] })
    },
    async execute(input, ctx = {}) {
      const started = Date.now()
      const runEnv = ctx.env ?? env
      const root = makeBaseUrl(input.requestedTarget ?? input.target)
      const client = clientFactory({ env: runEnv, signal: ctx.signal })
      const pages = await crawl(root, {
        client,
        maxPages: Math.min(input.max_pages, runEnv.WEBAPP_SCAN_MAX_PAGES ?? 100),
        signal: ctx.signal,
        onProgress: (count) => ctx.reportProgress?.(Math.min(35, Math.round((count / input.max_pages) * 35))),
      })
      const first = pages[0]?.url ?? root
      const fingerprint = fingerprintPages(pages)
      const passiveTasks = [
        () => checkHeaders(first, { client }),
        () => checkHttpMethods(first, { client }),
        () => checkCors(first, { client }),
        () => checkExposedFiles(root, { client, env: runEnv, signal: ctx.signal }),
        () => checkAdminPanels(root, { client, env: runEnv, signal: ctx.signal }),
        () => checkDirectoryListing(pages),
        () => checkRobots(root, { client }),
        () => checkDnsEmailSecurity(root, { env: runEnv }),
        () => checkTls(first, { env: runEnv, target: ctx.target, signal: ctx.signal }),
      ]
      const passive = (await Promise.all(passiveTasks.map((task) => task().catch(() => [])))).flat()
      ctx.reportProgress?.(70)
      let active = []
      if (input.active) {
        const forms = pages.flatMap((page) => page.forms ?? [])
        const activeTasks = [
          () => checkCsrf(first, forms),
          () => checkOpenRedirect(root, { client }),
          () => checkSqli(first, forms, { client }),
          () => checkXss(first, forms, { client }),
          () => checkSsti(first, forms, { client }),
          () => checkPathTraversal(root, { client }),
        ]
        active = (await Promise.all(activeTasks.map((task) => task().catch(() => [])))).flat()
      }
      ctx.reportProgress?.(100)
      return buildResult({
        target: input.requestedTarget ?? input.target,
        baseUrl: root,
        pages,
        fingerprint,
        vulnerabilities: dedupeAndSort([...passive, ...active]),
        scanDuration: (Date.now() - started) / 1000,
      })
    },
    summarize: (data) => ({ pages: data.pages_crawled ?? 0, vulnerabilities: data.total_vulns ?? 0, critical: data.critical_count ?? 0 }),
  }
}

export const definition = createWebappDefinition()
export { schema }
