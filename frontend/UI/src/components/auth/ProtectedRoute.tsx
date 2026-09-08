import { Navigate, Outlet } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'

export function ProtectedRoute() {
  const { user, initializing } = useAuth()

  // Hold rendering while the auth context hydrates user state from the
  // server via /auth/me/. Without this guard, ProtectedRoute would act
  // on stale JWT claims before the fresh server response has arrived.
  if (initializing) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-surface-deep">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-accent-blue border-t-transparent" />
      </div>
    )
  }

  if (!user) return <Navigate to="/login" replace />

  // An unconnected user ("Explorer") is deliberately NOT bounced to /connector.
  // They browse the whole product read-only to decide whether connecting is
  // worth it; the backend refuses every mutating request regardless, so the gate
  // lives on the action rather than on the page. See
  // product-design-requirements/connector-access-design/.

  return <Outlet />
}
