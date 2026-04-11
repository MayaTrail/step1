/**
 * Auth Service — handles JWT login, signup with OTP verification,
 * token management, connector verification, and demo activation.
 *
 * Backend endpoints:
 *   POST /api/auth/login                → { access, refresh }
 *   POST /api/auth/register/            → { message, email }  (sends OTP)
 *   POST /api/auth/register/verify-otp/ → { message }         (activates user)
 *   POST /api/auth/register/resend-otp/ → { message }         (resends OTP)
 *   POST /api/auth/refresh/             → { access }
 *   GET  /api/auth/me/                  → user profile
 *   POST /api/auth/google/              → { access, refresh, user } (Google SSO)
 *   POST /api/connectors/aws/verify/    → STS role verification
 *   POST /api/connectors/demo/          → switch to demo mode
 *
 * Falls back to mock auth when the backend is unreachable.
 */

import api from './api'
import type {
  AuthResponse,
  ConnectorRequest,
  ConnectorResponse,
  ForgotPasswordRequest,
  ForgotPasswordResponse,
  LoginRequest,
  RegisterResponse,
  ResendOTPRequest,
  ResendOTPResponse,
  ResetPasswordRequest,
  ResetPasswordResponse,
  SignupRequest,
  TokenPayload,
  User,
  VerifyOTPRequest,
  VerifyOTPResponse,
} from '@/types'

export interface UserProfile {
  id: number
  username: string
  email: string
  first_name: string
  last_name: string
  date_joined: string
  is_verified: boolean
  is_demo: boolean
  aws_role_arn: string
  demo_activated_at: string | null
  demo_used: boolean
  demo_expires_at: string | null
}

const TOKEN_KEY = 'mayatrail_token'
const REFRESH_KEY = 'mayatrail_refresh'

const DEMO_USERS: Record<string, { password: string; name: string }> = {
  'admin@mayatrail.tech': { password: 'mayatrail', name: 'Admin User' },
  admin: { password: 'admin', name: 'Administrator' },
  demo: { password: 'demo', name: 'Demo User' },
}

// JWT helpers
function createMockToken(user: User): string {
  const payload: TokenPayload = {
    sub: user.username,
    name: user.name,
    initials: user.initials,
    method: user.method,
    isVerified: user.isVerified,
    isDemo: user.isDemo,
    demoUsed: user.demoUsed,
    demoExpiresAt: user.demoExpiresAt,
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

// Backend auth calls
async function backendLogin(req: LoginRequest): Promise<AuthResponse> {
  const { data } = await api.post<{ access: string; refresh: string }>('/auth/login/', {
    username: req.username,
    password: req.password,
  })

  localStorage.setItem(TOKEN_KEY, data.access)
  localStorage.setItem(REFRESH_KEY, data.refresh)

  const user = await fetchMe(data.access)
  return { token: data.access, user }
}

async function backendSignup(req: SignupRequest): Promise<RegisterResponse> {
  const parts = req.name.trim().split(/\s+/)
  const firstName = parts[0] ?? ''
  const lastName = parts.slice(1).join(' ')

  const { data } = await api.post<RegisterResponse>('/auth/register/', {
    username: req.email,
    email: req.email,
    password: req.password,
    first_name: firstName,
    last_name: lastName,
    invite_code: req.inviteCode,
  })

  return data
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
    is_verified: boolean
    is_demo: boolean
    demo_used: boolean
    demo_expires_at: string | null
    auth_method: string
  }>('/auth/me/', { headers })

  const name = [data.first_name, data.last_name].filter(Boolean).join(' ') || data.username
  const method: User['method'] = data.auth_method === 'google_sso' ? 'google_sso' : 'credentials'
  return {
    username: data.username,
    name,
    initials: initials(name),
    method,
    isVerified: data.is_verified ?? false,
    isDemo: data.is_demo ?? false,
    demoUsed: data.demo_used ?? false,
    demoExpiresAt: data.demo_expires_at ?? null,
  }
}

// Mock fallback auth
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
    isVerified: false,
    isDemo: false,
    demoUsed: false,
    demoExpiresAt: null,
  }
  const token = createMockToken(user)
  localStorage.setItem(TOKEN_KEY, token)
  return { token, user }
}

function mockSignup(req: SignupRequest): RegisterResponse {
  return {
    message: 'Verification code sent to your email.',
    email: req.email,
  }
}

// Error extraction
function extractApiError(err: any): string {
  const data = err.response?.data
  if (!data) return err.message ?? 'Request failed'

  if (typeof data.detail === 'string') return data.detail

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

// Public API

export async function login(req: LoginRequest): Promise<AuthResponse> {
  try {
    return await backendLogin(req)
  } catch (err: any) {
    if (err.response) {
      throw new Error(extractApiError(err))
    }
    return mockLogin(req)
  }
}

/**
 * Step 1 of registration: submit user details and receive an OTP via email.
 * Does NOT log the user in — they must verify OTP first.
 */
export async function signup(req: SignupRequest): Promise<RegisterResponse> {
  try {
    return await backendSignup(req)
  } catch (err: any) {
    if (err.response) {
      throw new Error(extractApiError(err))
    }
    return mockSignup(req)
  }
}

/**
 * Step 2 of registration: verify the OTP to activate the account.
 */
export async function verifyOTP(req: VerifyOTPRequest): Promise<VerifyOTPResponse> {
  try {
    const { data } = await api.post<VerifyOTPResponse>('/auth/register/verify-otp/', req)
    return data
  } catch (err: any) {
    if (err.response) {
      throw new Error(extractApiError(err))
    }
    // Mock fallback — accept any 6-digit code
    return { message: 'Email verified successfully. You can now sign in.' }
  }
}

/**
 * Re-send OTP to the given email address.
 */
export async function resendOTP(req: ResendOTPRequest): Promise<ResendOTPResponse> {
  try {
    const { data } = await api.post<ResendOTPResponse>('/auth/register/resend-otp/', req)
    return data
  } catch (err: any) {
    if (err.response) {
      throw new Error(extractApiError(err))
    }
    return { message: 'A new verification code has been sent.' }
  }
}

/**
 * Authenticate via Google Identity Services.
 *
 * Sends the Google ID token to the backend, which verifies it and returns
 * a MayaTrail JWT pair.  Stores the tokens and returns the resolved user.
 * No invite code is required — Google's identity verification acts as the
 * equivalent gate.
 *
 * @param idToken - The credential string from the GIS CredentialResponse.
 */
export async function googleSSO(idToken: string): Promise<AuthResponse> {
  const { data } = await api.post<{ access: string; refresh: string; user: User }>('/auth/google/', {
    id_token: idToken,
  })

  localStorage.setItem(TOKEN_KEY, data.access)
  localStorage.setItem(REFRESH_KEY, data.refresh)

  // Hydrate user from /auth/me/ so the returned shape is always consistent
  // with the rest of the app regardless of what the Google response returns.
  const user = await fetchMe(data.access)
  return { token: data.access, user }
}

export async function logout(): Promise<void> {
  const access = localStorage.getItem(TOKEN_KEY)
  const refresh = localStorage.getItem(REFRESH_KEY)

  // Always clear local tokens first — even if the backend call fails
  // (network error, token already expired, etc.), the user should
  // still be logged out on the client side.
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(REFRESH_KEY)

  // Blacklist the refresh token server-side so it cannot be reused.
  // We pass the access token explicitly since localStorage is already
  // cleared and the request interceptor won't find it.
  if (refresh && access) {
    try {
      await api.post('/auth/logout/', { refresh }, {
        headers: { Authorization: `Bearer ${access}` },
      })
    } catch {
      // Best-effort — token may already be expired or blacklisted.
    }
  }
}

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

  const jwtPayload = decodeJwtPayload(token)
  if (jwtPayload && typeof jwtPayload.user_id === 'number') {
    const username = (jwtPayload.username as string) ?? `user-${jwtPayload.user_id}`
    return {
      username,
      name: username,
      initials: initials(username),
      method: 'credentials',
      isVerified: (jwtPayload.is_verified as boolean) ?? false,
      isDemo: (jwtPayload.is_demo as boolean) ?? false,
      demoUsed: (jwtPayload.demo_used as boolean) ?? false,
      demoExpiresAt: (jwtPayload.demo_expires_at as string) ?? null,
    }
  }

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
    isVerified: payload.isVerified ?? false,
    isDemo: payload.isDemo ?? false,
    demoUsed: payload.demoUsed ?? false,
    demoExpiresAt: payload.demoExpiresAt ?? null,
  }
}

export function isAuthenticated(): boolean {
  return getStoredUser() !== null
}

export async function fetchProfile(): Promise<UserProfile> {
  const { data } = await api.get<UserProfile>('/auth/me/')
  return data
}

// Connector / Demo API

export async function verifyConnector(req: ConnectorRequest): Promise<ConnectorResponse> {
  try {
    const { data } = await api.post<ConnectorResponse>('/connectors/aws/verify/', req)
    return data
  } catch (err: any) {
    if (err.response?.data) {
      return err.response.data as ConnectorResponse
    }
    return { status: 'verified', account_id: '123456789012' }
  }
}

export async function activateDemo(): Promise<{ is_demo: boolean }> {
  try {
    const { data } = await api.post<{ status: string; is_demo: boolean }>('/connectors/demo/')
    return { is_demo: data.is_demo }
  } catch (err: any) {
    if (err.response) {
      throw new Error(extractApiError(err))
    }
    return { is_demo: true }
  }
}

export async function refreshUser(): Promise<User> {
  return fetchMe()
}

// Password reset

export async function forgotPassword(req: ForgotPasswordRequest): Promise<ForgotPasswordResponse> {
  try {
    const { data } = await api.post<ForgotPasswordResponse>('/auth/forgot-password/', req)
    return data
  } catch (err: any) {
    throw new Error(extractApiError(err))
  }
}

export async function resetPassword(req: ResetPasswordRequest): Promise<ResetPasswordResponse> {
  try {
    const { data } = await api.post<ResetPasswordResponse>('/auth/reset-password/', req)
    return data
  } catch (err: any) {
    throw new Error(extractApiError(err))
  }
}
