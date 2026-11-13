import { Router } from 'express'
import { createAttachUser } from '../middleware/attachUser.js'
import * as runRepo from '../db/repos/runRepo.js'
import AppError from '../utils/AppError.js'
import * as runLifecycle from '../db/repos/runRepo.js'
import { removeRunJob } from '../queue/queues.js'
import { publishRunEvent } from '../queue/events.js'
import * as findingsRepo from '../db/repos/findingsRepo.js'

export default function runsRouter({ auth, clerkClient } = {}) {
  const router = Router()
  const attach = createAttachUser({ clerkClient })
  router.use(auth.requireAuth, attach)
  router.get('/', async (req, res, next) => { try { let cursor; if (req.query.cursor) { try { const decoded = JSON.parse(Buffer.from(String(req.query.cursor), 'base64url').toString('utf8')); if (!decoded?.id || !decoded?.createdAt) throw new Error('bad cursor'); cursor = { id: decoded.id, createdAt: decoded.createdAt } } catch { throw new AppError(400, 'VALIDATION_ERROR', 'Invalid cursor') } } const limit = Number(req.query.limit) || 50; if (!Number.isInteger(limit) || limit < 1 || limit > 50) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid limit'); const statuses = new Set(['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT']); if (req.query.status && !statuses.has(req.query.status)) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid status'); const rows = await runRepo.listForUser({ userId: req.user.id, tool: req.query.tool, status: req.query.status, limit, cursor }); const nextCursor = rows.length === limit ? Buffer.from(JSON.stringify({ createdAt: rows.at(-1).createdAt, id: rows.at(-1).id })).toString('base64url') : null; res.set('Cache-Control', 'no-store').json({ runs: rows, nextCursor }) } catch (err) { next(err) } })
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
  router.get('/:id', async (req, res, next) => { try { const run = await runRepo.findByIdForUser(req.params.id, req.user.id); if (!run) throw new AppError(404, 'NOT_FOUND', 'Run not found'); const active = run.status === 'QUEUED' || run.status === 'RUNNING'; const queuePosition = run.status === 'QUEUED' ? await runRepo.countQueuedBefore(run.queuedAt) : undefined; res.set('Cache-Control', 'no-store').json({ ...run, progressPct: run.progressPct, pollAfterMs: active ? 1500 : undefined, queuePosition, data: run.status === 'COMPLETED' ? run.result?.data : undefined, error: ['FAILED', 'TIMED_OUT'].includes(run.status) ? { code: run.errorCode, message: run.errorMessage } : undefined }) } catch (err) { next(err) } })
  router.post('/:id/cancel', async (req, res, next) => { try { const run = await runRepo.findByIdForUser(req.params.id, req.user.id); if (!run) throw new AppError(404, 'NOT_FOUND', 'Run not found'); if (run.status === 'QUEUED') { const cancelled = await runLifecycle.cancelQueued(run.id, req.user.id); if (cancelled) { await removeRunJob({ runId: run.id, attempt: cancelled.attempt }); await runLifecycle.refundOnce(run.id) } res.json({ status: 'CANCELLED' }); return } if (run.status === 'RUNNING') { await runLifecycle.requestCancel(run.id, req.user.id); await publishRunEvent(run.id, { type: 'cancel' }); res.status(202).json({ status: 'RUNNING', cancelRequested: true }); return } throw new AppError(409, 'RUN_NOT_CANCELLABLE', 'Run is not cancellable') } catch (err) { next(err) } })
  router.delete('/:id', async (req, res, next) => { try { const deleted = await runRepo.deleteForUser(req.params.id, req.user.id); if (!deleted) throw new AppError(404, 'NOT_FOUND', 'Run not found'); res.status(204).end() } catch (err) { next(err) } })
  return router
}
