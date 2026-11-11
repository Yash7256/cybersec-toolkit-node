import { clerkClient as defaultClerkClient } from '@clerk/express'
import AppError from '../utils/AppError.js'
import asyncHandler from '../utils/asyncHandler.js'
import * as userRepo from '../db/repos/userRepo.js'
import { primaryEmail, tierFromMetadata } from '../services/clerkSync.js'

// Factory so tests can inject a fake Clerk Backend client (no network).
export function createAttachUser({ clerkClient = defaultClerkClient } = {}) {
  return asyncHandler(async (req, _res, next) => {
    const clerkUserId = req.auth?.clerkUserId
    let user = await userRepo.findByClerkId(clerkUserId)

    if (!user) {
      let clerkUser
      try {
        clerkUser = await clerkClient.users.getUser(clerkUserId)
      } catch {
        throw new AppError(
          502,
          'UPSTREAM_AUTH_ERROR',
          'Failed to load user from authentication provider'
        )
      }
      user = await userRepo.upsertFromClerk({
        clerkUserId,
        email: primaryEmail(clerkUser),
        tier: tierFromMetadata(clerkUser.public_metadata ?? clerkUser.publicMetadata),
      })
    }

    if (!user.isActive || user.deletedAt) {
      throw new AppError(403, 'ACCOUNT_DISABLED', 'Account disabled')
    }

    req.user = {
      id: user.id,
      clerkUserId: user.clerkUserId,
      tier: user.tier,
      role: user.role,
    }
    next()
  })
}
