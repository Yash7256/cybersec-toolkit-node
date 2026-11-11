import request from 'supertest'
import { prisma } from '../../src/db/client.js'
import * as userRepo from '../../src/db/repos/userRepo.js'
import AppError from '../../src/utils/AppError.js'
import { createApp } from '../../src/app.js'

// Fake auth injected into createApp in tests. No fake-auth path exists in src.
export function makeTestAuth() {
  const middleware = (req, _res, next) => {
    const clerkUserId = req.get('x-test-clerk-id')
    if (clerkUserId) {
      req.auth = { clerkUserId, sessionId: req.get('x-test-session') ?? null }
    }
    next()
  }

  const requireAuth = (req, _res, next) => {
    if (!req.auth?.clerkUserId) {
      next(AppError.unauthorized('Authentication required'))
      return
    }
    next()
  }

  return { middleware, requireAuth }
}

// Stub for the Clerk Backend API client: lookup by id, throw when unknown.
export function makeClerkStub(users = {}) {
  return {
    users: {
      async getUser(id) {
        if (!Object.prototype.hasOwnProperty.call(users, id)) {
          throw new Error('Clerk user not found')
        }
        return users[id]
      },
    },
  }
}

// Snake_case payload shaped like the Clerk Backend API / webhook user object.
export function clerkUserPayload({ id, email, tier = 'free' }) {
  return {
    id,
    email_addresses: [{ id: `${id}_email`, email_address: email }],
    primary_email_address_id: `${id}_email`,
    public_metadata: { tier },
  }
}

export function makeTestApp({ auth = makeTestAuth(), clerkClient = makeClerkStub(), ...rest } = {}) {
  return createApp({ auth, clerkClient, ...rest })
}

// Seed a local user and return a supertest wrapper that always sends its header.
export async function asUser(app, { clerkId, tier = 'FREE', role = 'USER', email } = {}) {
  const user = await userRepo.upsertFromClerk({
    clerkUserId: clerkId,
    email: email ?? `${clerkId}@example.test`,
    tier,
  })
  if (role !== 'USER') {
    await prisma.user.update({ where: { id: user.id }, data: { role } })
  }

  const agent = request(app)
  const withHeader = (method, path) =>
    agent[method](path).set('x-test-clerk-id', clerkId)

  return {
    user,
    get: (path) => withHeader('get', path),
    post: (path) => withHeader('post', path),
    put: (path) => withHeader('put', path),
    patch: (path) => withHeader('patch', path),
    delete: (path) => withHeader('delete', path),
    raw: agent,
  }
}
