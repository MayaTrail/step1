import { Routes, Route } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { ThemeProvider } from './context/ThemeContext'
import { PlatformProvider } from './context/PlatformContext'
import { ProtectedRoute } from './components/auth/ProtectedRoute'
import { AppLayout } from './components/layout/AppLayout'
import { LoginPage } from './components/auth/LoginPage'
import { DashboardPage } from './components/dashboard/DashboardPage'
import { ProfilePage } from './components/profile/ProfilePage'
import { StacksPage } from './components/stacks/StacksPage'
import { EmulationsListPage } from './components/emulations/EmulationsListPage'
import { EmulationDetailPage } from './components/emulations/EmulationDetailPage'
import { PlaybookPage } from './components/playbooks/PlaybookPage'
import { DetectionsPage } from './components/detections/DetectionsPage'
import { GuardrailsPage } from './components/guardrails/GuardrailsPage'

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <PlatformProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route element={<ProtectedRoute />}>
              <Route element={<AppLayout />}>
                <Route index element={<DashboardPage />} />
                <Route path="me" element={<ProfilePage />} />
                <Route path="stacks" element={<StacksPage />} />
                <Route path=":platformId/emulations" element={<EmulationsListPage />} />
                <Route path=":platformId/emulations/:emulationId" element={<EmulationDetailPage />} />
                <Route path=":platformId/playbooks/:playbookId" element={<PlaybookPage />} />
                <Route path=":platformId/detections" element={<DetectionsPage />} />
                <Route path=":platformId/guardrails" element={<GuardrailsPage />} />
              </Route>
            </Route>
          </Routes>
        </PlatformProvider>
      </AuthProvider>
    </ThemeProvider>
  )
}
