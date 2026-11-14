import { Router } from 'express'
import { createToolHandler } from '../tools/_shared/toolRoute.js'
import tools from '../tools/index.js'
import { z } from 'zod'
import { createAttachUser } from '../middleware/attachUser.js'
import * as runRepo from '../db/repos/runRepo.js'
import AppError from '../utils/AppError.js'

const CATALOGUE = {
  dns: { label: 'DNS Lookup', description: 'Resolve DNS records over public DoH resolvers.' },
  ssl: { label: 'SSL Audit', description: 'Inspect a TLS certificate and supported protocol versions.' },
  http_headers: { label: 'HTTP Headers', description: 'Audit response security headers and disclosure.' },
  whois: { label: 'WHOIS / RDAP', description: 'Look up domain registration and expiry details.' },
  geoip: { label: 'GeoIP', description: 'Geolocate a host or IP address.' },
  ping: { label: 'Ping', description: 'Measure reachability and latency over ICMP or TCP.' },
  port_scan: { label: 'Port Scan', description: 'Scan TCP ports, fingerprint services, and assess exposure.' },
  subdomain: { label: 'Subdomain Discovery', description: 'Discover and safely probe public subdomains.' },
  traceroute: { label: 'Traceroute', description: 'Trace the network path to a validated target.' },
  webapp_scan: { label: 'Web App Scanner', description: 'Run passive or authorized active web security checks.' },
}

export default function toolsRouter({ auth, clerkClient, env, limiters } = {}) {
  const router = Router()
  for (const [name, definition] of Object.entries(tools)) {
    router.post(`/${name}`, createToolHandler({ definition, auth, clerkClient, env, limiters }))
  }
  router.get('/whois', createToolHandler({ definition: tools.whois, auth, clerkClient, env, limiters }))
  const geoipMe = {
    ...tools.geoip,
    name: 'geoip_me',
    schema: z.object({}),
    normalize: () => ({}),
    prepare: (input, { req }) => { input.target = String(req.ip ?? '').replace(/^::ffff:/i, '') },
  }
  const attach = createAttachUser({ clerkClient })
  const GEO_TOOLS = ['GEOIP', 'GEOIP_BULK', 'GEOIP_CIDR', 'ASN']
  router.get('/geoip/history', auth.requireAuth, attach, async (req, res, next) => {
    try {
      const limit = req.query.limit == null ? 20 : Number(req.query.limit)
      if (!Number.isInteger(limit) || limit < 1 || limit > 50) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid limit')
      const requested = req.query.tool ? String(req.query.tool).toUpperCase() : null
      if (requested && !GEO_TOOLS.includes(requested)) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid tool')
      const toolsToQuery = requested ? [requested] : GEO_TOOLS
      const batches = await Promise.all(toolsToQuery.map((tool) => runRepo.listForUser({ userId: req.user.id, tool, limit })))
      const runs = batches.flat().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, limit)
      res.set('Cache-Control', 'no-store').json({ runs })
    } catch (err) { next(err) }
  })
  router.delete('/geoip/history', auth.requireAuth, attach, async (req, res, next) => {
    try {
      const deleted = await runRepo.deleteTerminalForUser(req.user.id, GEO_TOOLS)
      res.set('Cache-Control', 'no-store').json({ deleted })
    } catch (err) { next(err) }
  })
  router.get('/geoip/me', createToolHandler({ definition: geoipMe, auth, clerkClient, env, limiters }))
  router.get('/geoip', createToolHandler({ definition: tools.geoip, auth, clerkClient, env, limiters }))
  router.get('/geo', createToolHandler({ definition: tools.geoip, auth, clerkClient, env, limiters }))
  const deprecated = (definition) => ({ ...definition, schema: definition.schema, beforeSubmit: async (input, context) => { context?.res?.set?.('Deprecation', 'true'); return definition.beforeSubmit?.(input, context) } })
  const legacyAsn = { ...tools.geoip, schema: z.object({ asn: z.string().trim().min(1) }), normalize: (input) => ({ target: input.asn }) }
  const legacyBulk = { ...tools.geoip, schema: z.object({ targets: z.array(z.string().trim().min(1)).min(1).max(500) }), normalize: (input) => ({ target: input.targets.join('\n') }) }
  const legacyCidr = { ...tools.geoip, schema: z.object({ target: z.string().trim().min(1) }), normalize: (input) => input }
  const legacyHandler = (definition) => createToolHandler({ definition, auth, clerkClient, env, limiters })
  router.get('/asn', (req, res, next) => { res.set('Deprecation', 'true'); return legacyHandler(legacyAsn)(req, res, next) })
  router.post('/asn', (req, res, next) => { res.set('Deprecation', 'true'); return legacyHandler(legacyAsn)(req, res, next) })
  router.post('/geoip_bulk', (req, res, next) => { res.set('Deprecation', 'true'); return legacyHandler(legacyBulk)(req, res, next) })
  router.get('/geoip/cidr', (req, res, next) => { res.set('Deprecation', 'true'); return legacyHandler(legacyCidr)(req, res, next) })
  router.post('/geoip_cidr', (req, res, next) => { res.set('Deprecation', 'true'); return legacyHandler(legacyCidr)(req, res, next) })
  router.get('/', (_req, res) =>
    res.set('Cache-Control', 'no-store').json(
      Object.values(tools).map((tool) => ({
        name: tool.name,
        label: CATALOGUE[tool.name]?.label ?? tool.name,
        description: CATALOGUE[tool.name]?.description ?? '',
        touchesTarget: tool.touchesTarget,
        async: tool.mode === 'async',
        input: Object.entries(tool.inputShape ?? tool.schema?.shape ?? {}).map(([name, schema]) => ({
          name,
          type: schema?._def?.typeName?.replace('Zod', '').toLowerCase() ?? 'unknown',
          required: !schema?.isOptional?.(),
        })),
        dailyLimit: env?.FREE_DAILY_LIMIT ?? null,
        ...(tool.name === 'webapp_scan' ? { requiresAuthorization: true } : {}),
      }))
    )
  )
  return router
}
