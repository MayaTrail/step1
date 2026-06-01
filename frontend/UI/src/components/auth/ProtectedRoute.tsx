import { Navigate, Outlet } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { useDemoCountdown } from '@/hooks/useDemoCountdown'

export function ProtectedRoute() {
  const { user, initializing } = useAuth()

  // Live countdown — fires every second while demo is active.
  // When the timer hits zero the `isExpired` flag flips and the
  // redirect below fires immediately, even if the user is idle.
  const { isExpired: demoExpired } = useDemoCountdown(
    user?.isDemo ? user.demoExpiresAt : null,
  )

  // Hold rendering while the auth context hydrates user state from the
  // server via /auth/me/. Without this guard, ProtectedRoute would act
  // on stale JWT claims and redirect verified or demo users to /connector
  // before the fresh server response has arrived.
  if (initializing) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-surface-deep">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-accent-blue border-t-transparent" />
      </div>
    )
  }

  if (!user) return <Navigate to="/login" replace />
  if (!user.isVerified && !user.isDemo) return <Navigate to="/connector" replace />

  // Demo users whose session has expired — redirect to connector upgrade.
  // This fires in real-time via useDemoCountdown (no navigation needed).
  if (user.isDemo && demoExpired) {
    return <Navigate to="/connector?upgrade=1" replace />
  }

  return <Outlet />
}
