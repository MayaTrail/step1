import { Routes, Route } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { ThemeProvider } from './context/ThemeContext'
import { PlatformProvider } from './context/PlatformContext'
import { ProtectedRoute } from './components/auth/ProtectedRoute'
import { AppLayout } from './components/layout/AppLayout'
import { LoginPage } from './components/auth/LoginPage'
import { ConnectorPage } from './components/auth/ConnectorPage'
import { DashboardPage } from './components/dashboard/DashboardPage'
import { ProfilePage } from './components/profile/ProfilePage'
import { SettingsPage } from './components/settings/SettingsPage'
import { StacksPage } from './components/stacks/StacksPage'
import { EmulationsListPage } from './components/emulations/EmulationsListPage'
import { EmulationDetailPage } from './components/emulations/EmulationDetailPage'
import { PlaybookPage } from './components/playbooks/PlaybookPage'
import { DetectionsPage } from './components/detections/DetectionsPage'
import { GuardrailsPage } from './components/guardrails/GuardrailsPage'
import { EmulationsHub } from './components/emulations/EmulationsHub'
import { DetectionsHub } from './components/detections/DetectionsHub'
import { PlaybooksHub } from './components/playbooks/PlaybooksHub'
import { GuardrailsHub } from './components/guardrails/GuardrailsHub'
import { ComingSoon } from './components/common/ComingSoon'
import { ActiveRunsPage } from './components/operations/ActiveRunsPage'
import { ResultsPage } from './components/operations/ResultsPage'
import { PlatformOverviewPage } from './components/platforms/PlatformOverviewPage'
import { IconBarChart, IconBook } from './components/ui/Icons'

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <PlatformProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/connector" element={<ConnectorPage />} />
            <Route element={<ProtectedRoute />}>
              <Route element={<AppLayout />}>
                <Route index element={<DashboardPage />} />
                <Route path="me" element={<ProfilePage />} />
                <Route path="settings" element={<SettingsPage />} />
                <Route path="stacks" element={<StacksPage />} />

                {/* Operations */}
                <Route path="runs" element={<ActiveRunsPage />} />
                <Route path="results" element={<ResultsPage />} />

                {/* Platform overview (discovery entry point) */}
                <Route path="platforms/:platformId" element={<PlatformOverviewPage />} />

                {/* Security Content hubs (cross-platform) */}
                <Route path="emulations" element={<EmulationsHub />} />
                <Route path="detections" element={<DetectionsHub />} />
                <Route path="playbooks" element={<PlaybooksHub />} />
                <Route path="guardrails" element={<GuardrailsHub />} />

                {/* Administration */}
                <Route path="reports" element={
                  <ComingSoon
                    icon={<IconBarChart size={32} />}
                    title="Reports coming soon"
                    body="Exportable coverage and execution reports will be generated here in a future milestone."
                  />
                } />
                <Route path="docs" element={
                  <ComingSoon
                    icon={<IconBook size={32} />}
                    title="Documentation coming soon"
                    body="Platform and emulation documentation will be available here in a future milestone."
                  />
                } />

                {/* Platform-scoped pages (detail flows + per-platform entry) */}
                <Route path=":platformId/emulations" element={<EmulationsListPage />} />
                <Route path=":platformId/emulations/:emulationId" element={<EmulationDetailPage />} />
                <Route path=":platformId/emulations/:emulationId/playbook" element={<PlaybookPage />} />
                <Route path=":platformId/emulations/:emulationId/detections" element={<DetectionsPage />} />
                <Route path=":platformId/guardrails" element={<GuardrailsPage />} />
              </Route>
            </Route>
          </Routes>
        </PlatformProvider>
      </AuthProvider>
    </ThemeProvider>
  )
}
