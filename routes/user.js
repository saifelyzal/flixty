import { Router } from 'express'
import { hashPassword, verifyPassword } from '../lib/auth.js'
import { findUserByEmail, findUserById, createUser } from '../lib/store.js'

const router = Router()

// POST /api/user/register  { name, email, password }
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body
  if (!name || !email || !password)
    return res.status(400).json({ error: 'name, email and password are required' })
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' })
  if (findUserByEmail(email))
    return res.status(409).json({ error: 'An account with that email already exists' })

  const passwordHash = await hashPassword(password)
  const user = createUser({ name: name.trim(), email: email.trim().toLowerCase(), passwordHash })
  req.session.userId = user.id
  res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email } })
})

// POST /api/user/login  { email, password }
router.post('/login', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password)
    return res.status(400).json({ error: 'email and password are required' })

  const user = findUserByEmail(email)
  if (!user) return res.status(401).json({ error: 'Invalid email or password' })

  const ok = await verifyPassword(password, user.passwordHash)
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' })

  req.session.userId = user.id
  res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email } })
})

// POST /api/user/logout
router.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }))
})

// GET /api/user/me
router.get('/me', (req, res) => {
  if (!req.session?.userId) return res.status(401).json({ error: 'Not logged in', code: 'UNAUTHENTICATED' })
  const user = findUserById(req.session.userId)
  if (!user) return res.status(401).json({ error: 'Session invalid', code: 'UNAUTHENTICATED' })
  res.json({ id: user.id, name: user.name, email: user.email })
})

export default router
