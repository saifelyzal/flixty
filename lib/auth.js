import crypto from 'crypto'
import { promisify } from 'util'

const scrypt = promisify(crypto.scrypt)

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex')
  const key  = await scrypt(password, salt, 64)
  return `${salt}:${key.toString('hex')}`
}

export async function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':')
  const key = await scrypt(password, salt, 64)
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), key)
}

// Express middleware — rejects unauthenticated requests with 401
export function requireAuth(req, res, next) {
  if (req.session?.userId) return next()
  res.status(401).json({ error: 'Login required', code: 'UNAUTHENTICATED' })
}
