import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import type { User, LoginRequest, SignupRequest } from '@/types'
import * as authService from '@/services/auth.service'

interface AuthContextValue {
  user: User | null
  loading: boolean
  error: string | null
  login: (req: LoginRequest) => Promise<void>
  signup: (req: SignupRequest) => Promise<void>
  googleSSO: () => Promise<void>
  logout: () => void
  clearError: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => authService.getStoredUser())
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const login = useCallback(async (req: LoginRequest) => {
    setLoading(true)
    setError(null)
    try {
      const res = await authService.login(req)
      setUser(res.user)
    } catch (err: any) {
      setError(err.message ?? 'Login failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const signup = useCallback(async (req: SignupRequest) => {
    setLoading(true)
    setError(null)
    try {
      const res = await authService.signup(req)
      setUser(res.user)
    } catch (err: any) {
      setError(err.message ?? 'Signup failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const googleSSO = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await authService.googleSSO()
      setUser(res.user)
    } catch (err: any) {
      setError(err.message ?? 'Google SSO failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const logout = useCallback(() => {
    authService.logout()
    setUser(null)
  }, [])

  const clearError = useCallback(() => setError(null), [])

  return (
    <AuthContext.Provider value={{ user, loading, error, login, signup, googleSSO, logout, clearError }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within <AuthProvider>')
  return ctx
}
