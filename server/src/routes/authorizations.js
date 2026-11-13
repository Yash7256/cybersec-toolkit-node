import { Router } from 'express'
import { createAttachUser } from '../middleware/attachUser.js'
import asyncHandler from '../utils/asyncHandler.js'
import AppError from '../utils/AppError.js'
import * as targetAuthRepo from '../db/repos/targetAuthRepo.js'

export default function authorizationsRouter({ auth, clerkClient } = {}) {
  const router = Router()
  router.use(auth.requireAuth, createAttachUser({ clerkClient }))
  router.get('/', asyncHandler(async (req, res) => {
    res.set('Cache-Control', 'no-store').json({ authorizations: await targetAuthRepo.list(req.user.id) })
  }))
  router.post('/', asyncHandler(async (req, res) => {
    const domain = String(req.body?.domain ?? '').trim()
    if (!domain || /\s|[/:?#@]/.test(domain)) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid domain')
    const result = await targetAuthRepo.attest(req.user.id, domain, { ip: req.ip, userAgent: req.get('user-agent') })
    if (result.cooldown) throw new AppError(429, 'AUTH_ATTESTATION_COOLDOWN', 'Authorization was recently attested; try again later.')
    res.status(201).json({ authorization: result.record })
  }))
  router.delete('/:domain', asyncHandler(async (req, res) => {
    const revoked = await targetAuthRepo.revoke(req.user.id, req.params.domain, { ip: req.ip, userAgent: req.get('user-agent') })
    if (!revoked) throw new AppError(404, 'NOT_FOUND', 'Authorization not found')
    res.status(204).end()
  }))
  return router
}
