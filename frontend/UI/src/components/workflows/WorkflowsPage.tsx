import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useEmulations } from '@/hooks/usePlatformData'
import { useAlertEndpoints, useWorkflowRuns } from '@/hooks/useWorkflows'
import { startWorkflowRun } from '@/services/workflow.service'
import type { WorkflowRun } from '@/types/workflow'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { IconActivity } from '@/components/ui/Icons'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import { AlertEndpointPanel } from './AlertEndpointPanel'
import {
  STATUS_LABEL,
  STATUS_TONE,
  formatCoverage,
  isOpen,
  untilDeadline,
} from './workflowMeta'

/**
 * Workflows, the detection-validation pipeline.
 *
 * A workflow runs an emulation in the client's account and then reports which
 * of that emulation's expected detections their own SIEM actually caught.
 * Running the attack alone tells a client nothing; their SIEM's response to it
 * is the finding.
 *
 * The list polls while any run is open, because a workflow advances on a
 * scheduled job rather than in response to anything the browser does, and a run
 * can take the better part of an hour.
 */

/** Refresh cadence while at least one run is still moving. */
const LIST_POLL_MS = 20_000

export function WorkflowsPage() {
  const { data: endpoints, loading: endpointsLoading } = useAlertEndpoints()
  const [refreshKey, setRefreshKey] = useState(0)
  const { data: runs, loading } = useWorkflowRuns(LIST_POLL_MS)
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
      setRefreshKey((key) => key + 1)
    } catch {
      setError('Could not start the workflow.')
    } finally {
      setStarting(false)
    }
  }

  return (
    <div className="animate-fadeIn flex flex-col gap-6" key={refreshKey}>
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

      <AlertEndpointPanel endpoints={endpoints} onCreated={() => setRefreshKey((k) => k + 1)} />

      <Card className="p-5">
        <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-3">
          Start a workflow
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={selected}
            onChange={(event) => setSelected(event.target.value)}
            className="flex-1 min-w-[240px] bg-surface-base border border-border rounded-btn px-3 py-2
              text-sm text-content-primary outline-none transition-colors focus:border-border-active"
          >
            <option value="">Choose an emulation…</option>
            {(emulations ?? []).map((emulation) => (
              <option key={emulation.id} value={emulation.id}>
                {emulation.name}
              </option>
            ))}
          </select>
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
        {/* Stated before the run, not after it fails to report anything. */}
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

      {loading && list.length === 0 ? (
        <div className="text-center py-12 text-content-dim font-mono text-sm">Loading workflows…</div>
      ) : list.length === 0 ? (
        <EmptyState
          icon={<IconActivity size={32} />}
          title="No workflows yet"
          body="Start one above to validate an emulation against the detections you already run."
        />
      ) : (
        <div className="flex flex-col gap-3">
          {list.map((run) => (
            <RunRow key={run.id} run={run} />
          ))}
        </div>
      )}
    </div>
  )
}

/** One workflow as a row: what it validated, where it is, and what it found. */
function RunRow({ run }: { run: WorkflowRun }) {
  const waiting = run.status === 'awaiting_alerts' ? untilDeadline(run.alertDeadline) : ''

  return (
    <Link
      to={`/workflows/${run.id}`}
      className="block no-underline transition-opacity hover:opacity-60"
    >
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-display text-sm font-semibold text-content-primary tracking-body">
            {run.emulationType}
          </span>
          <Badge tone={STATUS_TONE[run.status]} mono dot pulse={isOpen(run.status)}>
            {STATUS_LABEL[run.status]}
          </Badge>
          {waiting && (
            <span className="font-mono text-2xs text-content-dim">{waiting}</span>
          )}
          <span className="ml-auto font-mono text-2xs text-content-muted">
            {formatWhen(run.createdAt)}
          </span>
        </div>

        <p className="text-xs text-content-secondary leading-relaxed mt-2">
          {run.summary || run.detail || 'Running…'}
        </p>

        {run.score && (
          <div className="flex flex-wrap items-center gap-4 mt-3 pt-3 border-t border-border">
            <Figure label="Coverage" value={formatCoverage(run.score.detectionCoverage)} />
            <Figure label="Caught" value={String(run.score.counts.fired ?? 0)} />
            <Figure label="Missed" value={String(run.score.counts.silent ?? 0)} />
            <Figure label="Alerts received" value={String(run.score.alertsReceived)} />
          </div>
        )}
      </Card>
    </Link>
  )
}

/** One labelled figure in a row's result strip. */
function Figure({ label, value }: { label: string; value: string }) {
  return (
    <span className="flex flex-col">
      <span className="font-mono text-2xs uppercase tracking-caps text-content-dim">{label}</span>
      <span className="font-display text-sm font-semibold text-content-primary">{value}</span>
    </span>
  )
}
