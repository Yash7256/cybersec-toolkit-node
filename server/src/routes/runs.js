import { Router } from 'express'
import { createAttachUser } from '../middleware/attachUser.js'
import * as runRepo from '../db/repos/runRepo.js'
import AppError from '../utils/AppError.js'
import * as runLifecycle from '../db/repos/runRepo.js'
import { removeRunJob } from '../queue/queues.js'
import { publishRunEvent } from '../queue/events.js'
import * as findingsRepo from '../db/repos/findingsRepo.js'
import * as shareRepo from '../db/repos/shareRepo.js'
import { renderReportMarkdown } from '../services/report.js'

export default function runsRouter({ auth, clerkClient, env } = {}) {
  const router = Router()
  const attach = createAttachUser({ clerkClient })
  router.use(auth.requireAuth, attach)
  router.get('/', async (req, res, next) => { try { let cursor; if (req.query.cursor) { try { const decoded = JSON.parse(Buffer.from(String(req.query.cursor), 'base64url').toString('utf8')); if (!decoded?.id || !decoded?.createdAt) throw new Error('bad cursor'); cursor = { id: decoded.id, createdAt: decoded.createdAt } } catch { throw new AppError(400, 'VALIDATION_ERROR', 'Invalid cursor') } } const limit = Number(req.query.limit) || 50; if (!Number.isInteger(limit) || limit < 1 || limit > 50) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid limit'); const statuses = new Set(['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT']); if (req.query.status && !statuses.has(req.query.status)) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid status'); const rows = await runRepo.listForUser({ userId: req.user.id, tool: req.query.tool, status: req.query.status, limit, cursor }); const nextCursor = rows.length === limit ? Buffer.from(JSON.stringify({ createdAt: rows.at(-1).createdAt, id: rows.at(-1).id })).toString('base64url') : null; res.set('Cache-Control', 'no-store').json({ runs: rows, nextCursor }) } catch (err) { next(err) } })
  router.post('/:id/share', async (req, res, next) => {
    try {
      const run = await runRepo.findOwnedMeta(req.params.id, req.user.id)
      if (!run) throw new AppError(404, 'NOT_FOUND', 'Run not found')
      if (run.status !== 'COMPLETED') throw new AppError(409, 'RUN_NOT_COMPLETED', 'Only completed runs can be shared')
      const ttlDays = req.body?.ttlDays == null ? (env?.SHARE_DEFAULT_TTL_DAYS ?? 7) : Number(req.body.ttlDays)
      if (!Number.isInteger(ttlDays) || ttlDays < 1 || ttlDays > 30) throw new AppError(400, 'VALIDATION_ERROR', 'ttlDays must be between 1 and 30')
      const active = await shareRepo.countActiveForRun(run.id, req.user.id)
      if (active >= 10) throw new AppError(429, 'SHARE_LIMIT_REACHED', 'This run already has the maximum number of active share links')
      const redactAbuseContact = req.body?.redactAbuseContact !== false
      const { share, token } = await shareRepo.create({ runId: run.id, userId: req.user.id, ttlDays, redactAbuseContact })
      res.status(201).set('Cache-Control', 'no-store').json({
        id: share.id,
        token,
        path: `/share/${token}`,
        expiresAt: share.expiresAt,
        redactAbuseContact: share.redactAbuseContact,
      })
    } catch (err) { next(err) }
  })
  router.get('/:id/shares', async (req, res, next) => {
    try {
      const run = await runRepo.findOwnedMeta(req.params.id, req.user.id)
      if (!run) throw new AppError(404, 'NOT_FOUND', 'Run not found')
      const shares = await shareRepo.listForRun(run.id, req.user.id)
      res.set('Cache-Control', 'no-store').json({ shares })
    } catch (err) { next(err) }
  })
  router.delete('/:id/share/:shareId', async (req, res, next) => {
    try {
      const run = await runRepo.findOwnedMeta(req.params.id, req.user.id)
      if (!run) throw new AppError(404, 'NOT_FOUND', 'Run not found')
      const revoked = await shareRepo.revoke(req.params.shareId, run.id, req.user.id)
      if (!revoked) throw new AppError(404, 'NOT_FOUND', 'Share link not found')
      res.status(204).end()
    } catch (err) { next(err) }
  })
  router.get('/:id/findings', async (req, res, next) => {
    try {
      const run = await runRepo.findOwnedMeta(req.params.id, req.user.id)
      if (!run) throw new AppError(404, 'NOT_FOUND', 'Run not found')
      const limit = req.query.limit == null ? 50 : Number(req.query.limit)
      if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
        throw new AppError(400, 'VALIDATION_ERROR', 'Invalid limit')
      }
      let cursor = null
      if (req.query.cursor != null) {
        cursor = Number(req.query.cursor)
        if (!Number.isInteger(cursor) || cursor < 1 || cursor > 65535) {
          throw new AppError(400, 'VALIDATION_ERROR', 'Invalid cursor')
        }
      }
      const rows = await findingsRepo.listForRun({ runId: run.id, cursor, limit })
      const findings = rows.map(findingsRepo.toFinding)
      const nextCursor = rows.length === limit ? rows.at(-1).port : null
      res.set('Cache-Control', 'no-store').json({ findings, nextCursor })
    } catch (err) {
      next(err)
    }
  })
  router.get('/compare', async (req, res, next) => {
    try {
      const ids = String(req.query.ids ?? '').split(',').map((id) => id.trim()).filter(Boolean)
      if (ids.length < 2 || ids.length > 5) throw new AppError(400, 'VALIDATION_ERROR', 'ids must contain between 2 and 5 run IDs')
      if (new Set(ids).size !== ids.length) throw new AppError(400, 'VALIDATION_ERROR', 'ids must be unique')
      const runs = await Promise.all(ids.map((id) => runRepo.findByIdForUser(id, req.user.id)))
      if (runs.some((run) => !run)) throw new AppError(404, 'NOT_FOUND', 'Run not found')
      res.set('Cache-Control', 'no-store').json({
        runs: runs.map((run) => ({
          id: run.id,
          tool: run.tool,
          target: run.target,
          status: run.status,
          createdAt: run.createdAt,
          finishedAt: run.finishedAt,
          summary: run.summary,
          data: run.status === 'COMPLETED' ? run.result?.data ?? null : null,
        })),
      })
    } catch (err) { next(err) }
  })
  router.get('/:id/report', async (req, res, next) => {
    try {
      const run = await runRepo.findByIdForUser(req.params.id, req.user.id)
      if (!run) throw new AppError(404, 'NOT_FOUND', 'Run not found')
      if (run.status !== 'COMPLETED') throw new AppError(409, 'RUN_NOT_COMPLETED', 'Only completed runs can be reported')
      const data = run.result?.data ?? null
      const format = String(req.query.format ?? 'md').toLowerCase()
      if (format === 'json') {
        res.set('Cache-Control', 'no-store')
          .set('Content-Disposition', `attachment; filename="run-${run.id}.json"`)
          .json({ tool: run.tool, target: run.target, status: run.status, createdAt: run.createdAt, finishedAt: run.finishedAt, summary: run.summary, data })
        return
      }
      if (format !== 'md' && format !== 'markdown') throw new AppError(400, 'VALIDATION_ERROR', 'format must be md or json')
      const markdown = renderReportMarkdown({ run, data })
      res.status(200)
        .set('Cache-Control', 'no-store')
        .set('Content-Disposition', `attachment; filename="run-${run.id}.md"`)
        .type('text/markdown')
        .send(markdown)
    } catch (err) { next(err) }
  })
  router.get('/:id', async (req, res, next) => { try { const run = await runRepo.findByIdForUser(req.params.id, req.user.id); if (!run) throw new AppError(404, 'NOT_FOUND', 'Run not found'); const active = run.status === 'QUEUED' || run.status === 'RUNNING'; const queuePosition = run.status === 'QUEUED' ? await runRepo.countQueuedBefore(run.queuedAt) : undefined; res.set('Cache-Control', 'no-store').json({ ...run, progressPct: run.progressPct, pollAfterMs: active ? 1500 : undefined, queuePosition, data: run.status === 'COMPLETED' ? run.result?.data : undefined, error: ['FAILED', 'TIMED_OUT'].includes(run.status) ? { code: run.errorCode, message: run.errorMessage } : undefined }) } catch (err) { next(err) } })
  router.post('/:id/cancel', async (req, res, next) => { try { const run = await runRepo.findByIdForUser(req.params.id, req.user.id); if (!run) throw new AppError(404, 'NOT_FOUND', 'Run not found'); if (run.status === 'QUEUED') { const cancelled = await runLifecycle.cancelQueued(run.id, req.user.id); if (cancelled) { await removeRunJob({ runId: run.id, attempt: cancelled.attempt }); await runLifecycle.refundOnce(run.id) } res.json({ status: 'CANCELLED' }); return } if (run.status === 'RUNNING') { await runLifecycle.requestCancel(run.id, req.user.id); await publishRunEvent(run.id, { type: 'cancel' }); res.status(202).json({ status: 'RUNNING', cancelRequested: true }); return } throw new AppError(409, 'RUN_NOT_CANCELLABLE', 'Run is not cancellable') } catch (err) { next(err) } })
  router.delete('/:id', async (req, res, next) => { try { const deleted = await runRepo.deleteForUser(req.params.id, req.user.id); if (!deleted) throw new AppError(404, 'NOT_FOUND', 'Run not found'); res.status(204).end() } catch (err) { next(err) } })
  return router
}
