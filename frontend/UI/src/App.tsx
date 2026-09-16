import { lazy, Suspense } from 'react'
import { Routes, Route } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { ThemeProvider } from './context/ThemeContext'
import { PlatformProvider } from './context/PlatformContext'
import { UiModeProvider } from './context/UiModeContext'
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
import { DetectionDetailPage } from './components/detections/DetectionDetailPage'
import { DetectionCoveragePage } from './components/emulations/DetectionCoveragePage'
import { GuardrailsPage } from './components/guardrails/GuardrailsPage'
import { EmulationsHub } from './components/emulations/EmulationsHub'
import { DetectionsHub } from './components/detections/DetectionsHub'
import { PlaybooksHub } from './components/playbooks/PlaybooksHub'
// Lazy-loaded: the block editor is only reached from the playbooks hub, so it
// stays out of the initial bundle that every page including login pays for.
const PlaybookEditorPage = lazy(() =>
  import('./components/playbooks/PlaybookEditorPage').then((m) => ({
    default: m.PlaybookEditorPage,
  })),
)
const UserPlaybookViewPage = lazy(() =>
  import('./components/playbooks/UserPlaybookViewPage').then((m) => ({
    default: m.UserPlaybookViewPage,
  })),
)
const DetectionStudioPage = lazy(() =>
  import('./components/detections/DetectionStudioPage').then((m) => ({
    default: m.DetectionStudioPage,
  })),
)

/** Fallback shown while the editor chunk loads. */
function EditorFallback() {
  return (
    <div className="py-16 text-center font-mono text-sm text-content-dim">
      Loading editor...
    </div>
  )
}
import { ReportsPage } from '@/components/reports/ReportsPage'
import { RunReportPage } from '@/components/reports/RunReportPage'
import { RunComparePage } from '@/components/reports/RunComparePage'
import { GuardrailsHub } from './components/guardrails/GuardrailsHub'
import { ComingSoon } from './components/common/ComingSoon'
import { ActiveRunsPage } from './components/operations/ActiveRunsPage'
import { ResultsPage } from './components/operations/ResultsPage'
import { SchedulesPage } from './components/operations/SchedulesPage'
import { PlatformOverviewPage } from './components/platforms/PlatformOverviewPage'
import { IconBook } from './components/ui/Icons'

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <PlatformProvider>
          <UiModeProvider>
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
                <Route path="schedules" element={<SchedulesPage />} />

                {/* Platform overview (discovery entry point) */}
                <Route path="platforms/:platformId" element={<PlatformOverviewPage />} />

                {/* Security Content hubs (cross-platform) */}
                <Route path="emulations" element={<EmulationsHub />} />
                <Route path="detections" element={<DetectionsHub />} />
                <Route
                  path="detections/studio/new"
                  element={
                    <Suspense fallback={<EditorFallback />}>
                      <DetectionStudioPage />
                    </Suspense>
                  }
                />
                <Route
                  path="detections/studio/:detectionId"
                  element={
                    <Suspense fallback={<EditorFallback />}>
                      <DetectionStudioPage />
                    </Suspense>
                  }
                />
                <Route path="playbooks" element={<PlaybooksHub />} />
                <Route
                  path="playbooks/new"
                  element={
                    <Suspense fallback={<EditorFallback />}>
                      <PlaybookEditorPage />
                    </Suspense>
                  }
                />
                <Route
                  path="playbooks/:playbookId"
                  element={
                    <Suspense fallback={<EditorFallback />}>
                      <UserPlaybookViewPage />
                    </Suspense>
                  }
                />
                <Route
                  path="playbooks/:playbookId/edit"
                  element={
                    <Suspense fallback={<EditorFallback />}>
                      <PlaybookEditorPage />
                    </Suspense>
                  }
                />
                <Route path="guardrails" element={<GuardrailsHub />} />

                {/* Administration */}
                {/* "compare" must precede ":runId" — otherwise the param route
                    swallows it and the page looks for a run with that id. */}
                <Route path="reports" element={<ReportsPage />} />
                <Route path="reports/compare" element={<RunComparePage />} />
                <Route path="reports/:runId" element={<RunReportPage />} />
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
                <Route path=":platformId/emulations/:emulationId/detections/:ruleId" element={<DetectionDetailPage />} />
                <Route path=":platformId/emulations/:emulationId/logging/:runId" element={<DetectionCoveragePage />} />
                <Route path=":platformId/guardrails" element={<GuardrailsPage />} />
                <Route path=":platformId/guardrails/:guardrailId" element={<GuardrailsPage />} />
              </Route>
            </Route>
          </Routes>
          </UiModeProvider>
        </PlatformProvider>
      </AuthProvider>
    </ThemeProvider>
  )
}
