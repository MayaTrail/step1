export interface User {
  username: string
  name: string
  initials: string
  method: 'credentials' | 'google_sso'
  isVerified: boolean
  /**
   * Whether a read-only Scout audit role is connected. Separate from
   * isVerified, which is the emulation role: an org may connect either one
   * without the other, and the Attack Graph page gates on this.
   */
  hasAuditRole: boolean
}

export interface LoginRequest {
  username: string
  password: string
}

export interface SignupRequest {
  name: string
  username: string
  email: string
  password: string
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
  iat: number
  exp: number
}

export interface ConnectorRequest {
  role_arn: string
}

export interface ConnectorResponse {
  status: 'verified' | 'error'
  account_id?: string
  message?: string
}

export interface ForgotPasswordRequest {
  email: string
}

export interface ForgotPasswordResponse {
  message: string
}

export interface ResetPasswordRequest {
  email: string
  otp: string
  new_password: string
}

export interface ResetPasswordResponse {
  message: string
}
