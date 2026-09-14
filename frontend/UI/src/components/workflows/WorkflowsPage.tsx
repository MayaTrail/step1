import { useMemo, useState } from 'react'
import { useEmulations } from '@/hooks/usePlatformData'
import { useAlertEndpoints, useWorkflowRuns } from '@/hooks/useWorkflows'
import { startWorkflowRun } from '@/services/workflow.service'
import { Card } from '@/components/ui/Card'
import { Combobox } from '@/components/ui/Combobox'
import { EndpointsSection } from './EndpointsSection'
import { RunsSection } from './RunsSection'

/**
 * Workflows, the detection-validation pipeline.
 *
 * A workflow runs an emulation in the customer's account and reports which of
 * that emulation's expected detections their own SIEM actually caught. Running
 * the attack alone tells them nothing; their SIEM's response to it is the
 * finding.
 *
 * Split into two tabs because the surfaces have different lifetimes. Endpoints
 * are configuration, set once and rarely revisited; runs are the working
 * history. Sharing one scroll meant a team with several SIEMs pushed their own
 * results off the page.
 */

/** Refresh cadence while at least one run is still moving. */
const LIST_POLL_MS = 20_000

type Tab = 'runs' | 'endpoints'

export function WorkflowsPage() {
  const [tab, setTab] = useState<Tab>('runs')
  // Bumped after a mutation. It forms part of each hook's cache key, so the
  // data refetches without remounting anything, which is what an earlier
  // version did and why a newly created secret vanished before it rendered.
  const [version, setVersion] = useState(0)

  const { data: runs, loading } = useWorkflowRuns(LIST_POLL_MS, version)
  const { data: endpoints, loading: endpointsLoading } = useAlertEndpoints(version)
  const { data: emulations } = useEmulations('aws')

  const [selected, setSelected] = useState('')
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const list = useMemo(() => runs ?? [], [runs])
  const hasEndpoint = (endpoints?.length ?? 0) > 0

  async function start() {
    if (!selected || starting) return
    setStarting(true)
    setError(null)
    try {
      await startWorkflowRun(selected)
      setVersion((current) => current + 1)
    } catch {
      setError('Could not start the workflow.')
    } finally {
      setStarting(false)
    }
  }

  return (
    <div className="animate-fadeIn flex flex-col gap-5">
      <div>
        <div className="font-mono text-2xs uppercase tracking-label text-accent-blue font-medium mb-2">
          Operations
        </div>
        <h1 className="font-display text-2xl font-semibold text-content-primary leading-tight">
          Workflows
        </h1>
        <p className="text-sm text-content-dim mt-1">
          Run an emulation and find out which of its expected detections your SIEM caught
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2" role="tablist" aria-label="Workflows view">
        <TabButton id="runs" active={tab} count={list.length} onSelect={setTab}>
          Runs
        </TabButton>
        <TabButton
          id="endpoints"
          active={tab}
          count={endpoints?.length ?? 0}
          onSelect={setTab}
        >
          Endpoints
        </TabButton>
      </div>

      {tab === 'runs' ? (
        <>
          <Card className="p-5">
            <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-3">
              Start a workflow
            </h2>
            <div className="flex flex-wrap items-center gap-2">
              {/* Fifty emulations is too many to recognise in a dropdown, so
                  this filters as you type. The hint line carries the registry
                  id, which is what distinguishes the several near-identical
                  IAM techniques from one another. */}
              <Combobox
                options={(emulations ?? []).map((emulation) => ({
                  value: emulation.id,
                  label: emulation.name,
                  hint: emulation.id,
                }))}
                value={selected}
                onChange={setSelected}
                placeholder="Search emulations…"
                ariaLabel="Choose an emulation to validate"
              />
              <button
                type="button"
                onClick={start}
                disabled={!selected || starting}
                className="px-4 py-2 rounded-btn text-sm font-medium tracking-btn border border-border
                  text-content-primary shadow-button transition-opacity hover:opacity-60
                  disabled:opacity-30 disabled:cursor-not-allowed"
              >
                {starting ? 'Starting…' : 'Start workflow'}
              </button>
            </div>
            {/* Said before the run, not after it reports nothing. */}
            {!endpointsLoading && !hasEndpoint && (
              <p className="text-xs text-warning mt-2">
                No alert endpoint is configured yet. A workflow will still run, but it cannot
                report which detections your SIEM caught until one exists.
              </p>
            )}
            <p className="text-xs text-content-dim mt-2">
              This deploys real infrastructure into your connected account and runs a real attack
              against it.
            </p>
            {error && <p className="text-xs text-danger mt-2">{error}</p>}
          </Card>

          <RunsSection runs={list} loading={loading} />
        </>
      ) : (
        <EndpointsSection
          endpoints={endpoints}
          loading={endpointsLoading}
          onCreated={() => setVersion((current) => current + 1)}
        />
      )}
    </div>
  )
}

interface TabButtonProps {
  id: Tab
  active: Tab
  count: number
  onSelect: (tab: Tab) => void
  children: React.ReactNode
}

function TabButton({ id, active, count, onSelect, children }: TabButtonProps) {
  const selected = active === id
  return (
    <button
      type="button"
      role="tab"
      aria-selected={selected}
      onClick={() => onSelect(id)}
      className={`px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn border
        transition-opacity hover:opacity-60
        ${selected
          ? 'border-border-active bg-surface-card text-content-primary'
          : 'border-border bg-transparent text-content-secondary'}`}
    >
      {children}
      <span className="ml-1.5 font-mono text-content-dim">{count}</span>
    </button>
  )
}
