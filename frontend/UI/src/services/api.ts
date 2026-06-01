import axios, { type AxiosRequestConfig } from 'axios'

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'

const TOKEN_KEY = 'mayatrail_token'
const REFRESH_KEY = 'mayatrail_refresh'

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 15_000,
  headers: { 'Content-Type': 'application/json' },
})

// State for coordinating concurrent token refresh attempts.
// If multiple requests get a 401 simultaneously, only one refresh call
// is made; the rest are queued and retried once the new token arrives.
let isRefreshing = false
type PendingEntry = { resolve: (token: string) => void; reject: (err: unknown) => void }
let pendingQueue: PendingEntry[] = []

function drainQueue(token: string | null, err: unknown): void {
  pendingQueue.forEach(({ resolve, reject }) => {
    if (token !== null) resolve(token)
    else reject(err)
  })
  pendingQueue = []
}

function clearTokens(): void {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(REFRESH_KEY)
}

// Public endpoints that must never receive a stale Bearer token.
// SimpleJWT's authentication backend will attempt to validate any
// Authorization header it sees, even on AllowAny views.  If a leftover
// expired token is sent, the request fails with "Token is invalid or
// expired" before the view logic ever runs.
const PUBLIC_PATHS = [
  '/auth/login/',
  '/auth/register/',
  '/auth/google/',
  '/auth/refresh/',
  '/auth/forgot-password/',
  '/auth/reset-password/',
]

// Attach the stored JWT to every outgoing request — except public ones.
api.interceptors.request.use((config) => {
  const url = config.url ?? ''
  const isPublic = PUBLIC_PATHS.some((p) => url.startsWith(p))

  if (!isPublic) {
    const token = localStorage.getItem(TOKEN_KEY)
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
  }
  return config
})

// Global response error handler.
api.interceptors.response.use(
  (res) => res,
  async (err) => {
    const original = err.config as AxiosRequestConfig & { _retry?: boolean }
    const url: string = original?.url ?? ''
    const isAuthEndpoint = url.startsWith('/auth/')

    // Demo expiry — redirect to connector upgrade flow.
    if (
      err.response?.status === 403 &&
      err.response?.data?.code === 'DEMO_EXPIRED'
    ) {
      window.location.href = '/connector?upgrade=1'
      return Promise.reject(err)
    }

    // 401 on non-auth endpoints — attempt a silent token refresh before
    // giving up and redirecting to the login page.
    if (err.response?.status === 401 && !isAuthEndpoint && !original?._retry) {

      // Another refresh is already in flight — queue this request and
      // resolve it once the shared refresh completes.
      if (isRefreshing) {
        return new Promise<string>((resolve, reject) => {
          pendingQueue.push({ resolve, reject })
        }).then((token) => {
          if (original.headers) {
            original.headers['Authorization'] = `Bearer ${token}`
          }
          return api(original)
        })
      }

      original._retry = true
      isRefreshing = true

      const refreshToken = localStorage.getItem(REFRESH_KEY)
      if (!refreshToken) {
        isRefreshing = false
        clearTokens()
        window.location.href = '/login'
        return Promise.reject(err)
      }

      try {
        // Use a standalone axios call to avoid re-entering this interceptor.
        const { data } = await axios.post<{ access: string }>(
          `${BASE_URL}/auth/refresh/`,
          { refresh: refreshToken },
          { headers: { 'Content-Type': 'application/json' } },
        )

        const newToken = data.access
        localStorage.setItem(TOKEN_KEY, newToken)

        drainQueue(newToken, null)

        if (original.headers) {
          original.headers['Authorization'] = `Bearer ${newToken}`
        }
        return api(original)
      } catch (refreshErr) {
        // Refresh token is also expired or invalid — clear everything and
        // send the user back to login.
        drainQueue(null, refreshErr)
        clearTokens()
        window.location.href = '/login'
        return Promise.reject(refreshErr)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(err)
  },
)

export default api
