import { getRedisClient } from '../../redis/client.js'

export async function cacheGet(name, id) {
  try { const value = await getRedisClient().get(`cst:${name}:${id}`); return value ? JSON.parse(value) : null } catch { return null }
}
export async function cacheSet(name, id, value, ttl) {
  try { await getRedisClient().set(`cst:${name}:${id}`, JSON.stringify(value), 'EX', ttl) } catch {}
}
