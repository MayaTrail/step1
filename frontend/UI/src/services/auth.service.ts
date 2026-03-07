/**
 * Auth Service — handles JWT login, signup, and token management.
 *
 * Backend endpoints (Django SimpleJWT):
 *   POST /api/auth/login    → { access, refresh }
 *   POST /api/auth/register → { username, email }
 *   POST /api/auth/refresh  → { access }
 *   GET  /api/auth/me       → user profile
 *
 * Falls back to mock auth when the backend is unreachable (dev without backend).
 */

import api from './api'
import type { AuthResponse, LoginRequest, SignupRequest, TokenPayload, User } from '@/types'

export interface UserProfile {
  id: number
  username: string
  email: string
  first_name: string
  last_name: string
  date_joined: string
}

const TOKEN_KEY = 'mayatrail_token'
const REFRESH_KEY = 'mayatrail_refresh'

// ─── Demo users (mock fallback) ─────────────────────────────────
const DEMO_USERS: Record<string, { password: string; name: string }> = {
  'admin@mayatrail.tech': { password: 'mayatrail', name: 'Admin User' },
  admin: { password: 'admin', name: 'Administrator' },
  demo: { password: 'demo', name: 'Demo User' },
}

// ─── JWT helpers ────────────────────────────────────────────────
function createMockToken(user: User): string {
  const payload: TokenPayload = {
    sub: user.username,
    name: user.name,
    initials: user.initials,
    method: user.method,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400,
  }
  return btoa(JSON.stringify(payload))
}

function decodeMockToken(token: string): TokenPayload | null {
  try {
    const payload: TokenPayload = JSON.parse(atob(token))
    if (payload.exp * 1000 < Date.now()) return null
    return payload
  } catch {
    return null
  }
}

/** Decode a real JWT (SimpleJWT) payload section */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const payload = parts[1]!
    return JSON.parse(atob(payload))
  } catch {
    return null
  }
}

function initials(name: string): string {
  return name
    .split(' ')
    .map((w) => w[0])
    .join('')
    .toUpperCase()
    .slice(0, 2)
}

// ─── Backend auth calls ─────────────────────────────────────────
async function backendLogin(req: LoginRequest): Promise<AuthResponse> {
  // SimpleJWT expects { username, password }
  const { data } = await api.post<{ access: string; refresh: string }>('/auth/login/', {
    username: req.username,
    password: req.password,
  })

  localStorage.setItem(TOKEN_KEY, data.access)
  localStorage.setItem(REFRESH_KEY, data.refresh)

  // Fetch user profile
  const user = await fetchMe(data.access)
  return { token: data.access, user }
}

async function backendSignup(req: SignupRequest): Promise<AuthResponse> {
  // Split name into first_name / last_name
  const parts = req.name.trim().split(/\s+/)
  const firstName = parts[0] ?? ''
  const lastName = parts.slice(1).join(' ')

  // Register
  await api.post('/auth/register/', {
    username: req.email,
    email: req.email,
    password: req.password,
    first_name: firstName,
    last_name: lastName,
    invite_code: req.inviteCode,
  })
  // Auto-login after registration
  return backendLogin({ username: req.email, password: req.password })
}

async function fetchMe(accessToken?: string): Promise<User> {
  const headers: Record<string, string> = {}
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`
  }
  const { data } = await api.get<{
    id: number
    username: string
    email: string
    first_name: string
    last_name: string
  }>('/auth/me/', { headers })

  const name = [data.first_name, data.last_name].filter(Boolean).join(' ') || data.username
  return {
    username: data.username,
    name,
    initials: initials(name),
    method: 'credentials',
  }
}

// ─── Mock fallback auth ─────────────────────────────────────────
function mockLogin(req: LoginRequest): AuthResponse {
  const entry = DEMO_USERS[req.username]
  if (!entry || entry.password !== req.password) {
    throw new Error('Invalid credentials')
  }
  const user: User = {
    username: req.username,
    name: entry.name,
    initials: initials(entry.name),
    method: 'credentials',
  }
  const token = createMockToken(user)
  localStorage.setItem(TOKEN_KEY, token)
  return { token, user }
}

function mockSignup(req: SignupRequest): AuthResponse {
  const user: User = {
    username: req.email,
    name: req.name,
    initials: initials(req.name),
    method: 'credentials',
  }
  const token = createMockToken(user)
  localStorage.setItem(TOKEN_KEY, token)
  return { token, user }
}

// ─── Public API ─────────────────────────────────────────────────

/**
 * Extract a human-readable error message from an Axios error response.
 * Handles DRF's various error response shapes (object of field arrays,
 * flat detail string, non_field_errors array).
 */
function extractApiError(err: any): string {
  const data = err.response?.data
  if (!data) return err.message ?? 'Request failed'

  // DRF "detail" string, e.g. { detail: "Not found." }
  if (typeof data.detail === 'string') return data.detail

  // DRF field-level errors, e.g. { invite_code: ["Invalid invite code."] }
  if (typeof data === 'object') {
    const messages: string[] = []
    for (const value of Object.values(data)) {
      if (Array.isArray(value)) {
        messages.push(...value.map(String))
      } else if (typeof value === 'string') {
        messages.push(value)
      }
    }
    if (messages.length) return messages.join(' ')
  }

  return 'Request failed'
}

/**
 * Login — tries real backend first, falls back to mock only when
 * the backend is unreachable (no HTTP response at all).
 */
export async function login(req: LoginRequest): Promise<AuthResponse> {
  try {
    return await backendLogin(req)
  } catch (err: any) {
    // Backend responded with an error (4xx/5xx) — propagate it
    if (err.response) {
      throw new Error(extractApiError(err))
    }
    // Backend unreachable — fall back to mock for dev convenience
    return mockLogin(req)
  }
}

/**
 * Signup — tries real backend first, falls back to mock only when
 * the backend is unreachable (no HTTP response at all).
 */
export async function signup(req: SignupRequest): Promise<AuthResponse> {
  try {
    return await backendSignup(req)
  } catch (err: any) {
    // Backend responded with an error (4xx/5xx) — propagate it
    if (err.response) {
      throw new Error(extractApiError(err))
    }
    return mockSignup(req)
  }
}

/** Google SSO placeholder — swap for real OAuth redirect */
export async function googleSSO(): Promise<AuthResponse> {
  const user: User = {
    username: 'google@mayatrail.tech',
    name: 'Google User',
    initials: 'GU',
    method: 'google_sso',
  }
  const token = createMockToken(user)
  localStorage.setItem(TOKEN_KEY, token)
  return { token, user }
}

export function logout(): void {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(REFRESH_KEY)
}

/**
 * Refresh the access token using the stored refresh token.
 * Returns the new access token or null on failure.
 */
export async function refreshAccessToken(): Promise<string | null> {
  const refresh = localStorage.getItem(REFRESH_KEY)
  if (!refresh) return null

  try {
    const { data } = await api.post<{ access: string }>('/auth/refresh/', { refresh })
    localStorage.setItem(TOKEN_KEY, data.access)
    return data.access
  } catch {
    logout()
    return null
  }
}

export function getStoredUser(): User | null {
  const token = localStorage.getItem(TOKEN_KEY)
  if (!token) return null

  // Try decoding as real JWT first
  const jwtPayload = decodeJwtPayload(token)
  if (jwtPayload && typeof jwtPayload.user_id === 'number') {
    // Real SimpleJWT — extract what we can from the token payload
    const username = (jwtPayload.username as string) ?? `user-${jwtPayload.user_id}`
    return {
      username,
      name: username,
      initials: initials(username),
      method: 'credentials',
    }
  }

  // Try decoding as mock token
  const payload = decodeMockToken(token)
  if (!payload) {
    localStorage.removeItem(TOKEN_KEY)
    return null
  }
  return {
    username: payload.sub,
    name: payload.name,
    initials: payload.initials,
    method: payload.method as User['method'],
  }
}

export function isAuthenticated(): boolean {
  return getStoredUser() !== null
}

/**
 * Fetch the full user profile from the backend.
 * Requires a valid JWT in localStorage.
 */
export async function fetchProfile(): Promise<UserProfile> {
  const { data } = await api.get<UserProfile>('/auth/me/')
  return data
}
