import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from 'react'
import type {
  User, LoginRequest, SignupRequest, ConnectorRequest,
  RegisterResponse, VerifyOTPRequest, VerifyOTPResponse,
  ResendOTPRequest, ResendOTPResponse,
} from '@/types'
import * as authService from '@/services/auth.service'

interface AuthContextValue {
  user: User | null
  loading: boolean
  // True while the app hydrates user state from the server on mount.
  // ProtectedRoute and ConnectorPage hold rendering until this resolves
  // to prevent premature redirects based on stale JWT claims.
  initializing: boolean
  error: string | null
  login: (req: LoginRequest) => Promise<User>
  googleSSO: (idToken: string) => Promise<User>
  signup: (req: SignupRequest) => Promise<RegisterResponse>
  verifyOTP: (req: VerifyOTPRequest) => Promise<VerifyOTPResponse>
  resendOTP: (req: ResendOTPRequest) => Promise<ResendOTPResponse>
  logout: () => void
  clearError: () => void
  verifyConnector: (req: ConnectorRequest) => Promise<void>
  activateDemo: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => authService.getStoredUser())
  const [loading, setLoading] = useState(false)
  const [initializing, setInitializing] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    /**
     * On mount, hydrate user state from the server via /auth/me/.
     *
     * The JWT stored in localStorage is used solely as a bearer token.
     * User profile fields (isVerified, isDemo, etc.) may have changed
     * server-side after the token was issued (e.g. demo activation,
     * connector verification), so we always fetch fresh state from the
     * /auth/me/ endpoint rather than trusting the JWT claims.
     *
     * If the access token is expired, the 401 interceptor in api.ts
     * will silently refresh it before retrying. If that also fails,
     * the interceptor redirects to /login.
     */
    const token = localStorage.getItem('mayatrail_token')

    if (!token) {
      setInitializing(false)
      return
    }

    authService
      .refreshUser()
      .then((freshUser) => {
        setUser(freshUser)
      })
      .catch(() => {
        // If /auth/me/ fails and the 401 interceptor could not refresh
        // the token, the interceptor will hard-redirect to /login via
        // window.location.href. Clear local state as a safety net in
        // case the redirect has not fired yet.
        setUser(null)
      })
      .finally(() => {
        setInitializing(false)
      })
  }, [])

  const login = useCallback(async (req: LoginRequest): Promise<User> => {
    setLoading(true)
    setError(null)
    try {
      const res = await authService.login(req)
      setUser(res.user)
      return res.user
    } catch (err: any) {
      setError(err.message ?? 'Login failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const googleSSO = useCallback(async (idToken: string): Promise<User> => {
    setLoading(true)
    setError(null)
    try {
      const res = await authService.googleSSO(idToken)
      setUser(res.user)
      return res.user
    } catch (err: any) {
      setError(err.message ?? 'Google sign-in failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const signup = useCallback(async (req: SignupRequest): Promise<RegisterResponse> => {
    setLoading(true)
    setError(null)
    try {
      return await authService.signup(req)
    } catch (err: any) {
      setError(err.message ?? 'Signup failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const verifyOTP = useCallback(async (req: VerifyOTPRequest): Promise<VerifyOTPResponse> => {
    setLoading(true)
    setError(null)
    try {
      return await authService.verifyOTP(req)
    } catch (err: any) {
      setError(err.message ?? 'OTP verification failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const resendOTP = useCallback(async (req: ResendOTPRequest): Promise<ResendOTPResponse> => {
    setLoading(true)
    setError(null)
    try {
      return await authService.resendOTP(req)
    } catch (err: any) {
      setError(err.message ?? 'Failed to resend code')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const verifyConnector = useCallback(async (req: ConnectorRequest) => {
    setLoading(true)
    setError(null)
    try {
      const res = await authService.verifyConnector(req)
      if (res.status === 'error') {
        setError(res.message ?? 'Verification failed')
        throw new Error(res.message ?? 'Verification failed')
      }
      const refreshed = await authService.refreshUser()
      setUser(refreshed)
    } catch (err: any) {
      if (!error) setError(err.message ?? 'Connector verification failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [error])

  const activateDemo = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      await authService.activateDemo()
      const refreshed = await authService.refreshUser()
      setUser(refreshed)
    } catch (err: any) {
      setError(err.message ?? 'Demo activation failed')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])

  const logout = useCallback(async () => {
    setUser(null)
    await authService.logout()
  }, [])

  const clearError = useCallback(() => setError(null), [])

  return (
    <AuthContext.Provider value={{
      user, loading, initializing, error,
      login, googleSSO, signup, verifyOTP, resendOTP, logout, clearError,
      verifyConnector, activateDemo,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within <AuthProvider>')
  return ctx
}
