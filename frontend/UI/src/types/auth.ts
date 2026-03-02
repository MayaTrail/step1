export interface User {
  username: string
  name: string
  initials: string
  method: 'credentials' | 'google_sso'
}

export interface LoginRequest {
  username: string
  password: string
}

export interface SignupRequest {
  name: string
  email: string
  password: string
}

export interface AuthResponse {
  token: string
  user: User
}

export interface TokenPayload {
  sub: string
  name: string
  initials: string
  method: string
  iat: number
  exp: number
}
