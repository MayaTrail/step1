export interface User {
  username: string
  name: string
  initials: string
  method: 'credentials' | 'google_sso'
  isVerified: boolean
  isDemo: boolean
  demoUsed: boolean
  demoExpiresAt: string | null
}

export interface LoginRequest {
  username: string
  password: string
}

export interface SignupRequest {
  name: string
  email: string
  password: string
  inviteCode: string
}

export interface AuthResponse {
  token: string
  user: User
}

export interface RegisterResponse {
  message: string
  email: string
}

export interface VerifyOTPRequest {
  email: string
  otp: string
}

export interface VerifyOTPResponse {
  message: string
}

export interface ResendOTPRequest {
  email: string
}

export interface ResendOTPResponse {
  message: string
}

export interface TokenPayload {
  sub: string
  name: string
  initials: string
  method: string
  isVerified: boolean
  isDemo: boolean
  demoUsed: boolean
  demoExpiresAt: string | null
  iat: number
  exp: number
}

export interface ConnectorRequest {
  role_arn: string
}

export interface ConnectorResponse {
  status: 'verified' | 'error'
  account_id?: string
  is_demo?: boolean
  message?: string
}
