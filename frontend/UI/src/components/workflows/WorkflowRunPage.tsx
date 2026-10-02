import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import { useCachedResource } from '@/hooks/useCachedResource'
import { useWorkflowRun } from '@/hooks/useWorkflows'
import { getEmulationTechniques } from '@/services/emulation.service'
import { getPrevention } from '@/services/prevention.service'
import { deleteWorkflowRun } from '@/services/workflow.service'
import type { WorkflowRunDetail } from '@/types/workflow'
import {
  STATUS_LABEL,
  STATUS_TONE,
  isOpen,
  stageState,
  untilDeadline,
  untilScheduled,
} from './workflowMeta'
import { AttackPhases } from './AttackPhases'
import { CloseTheGap } from './CloseTheGap'
import { PipelineGraph } from './PipelineGraph'
import { UnattributedAlerts } from './UnattributedAlerts'

/**
 * One workflow run, on a page of its own.
 *
 * The page discloses in step with the run. While infrastructure deploys and
 * the attack runs, only the pipeline shows, because nothing below it exists
 * yet. Once the emulation has finished, the attack phases appear with their
 * prevention and detection lanes, and the phase data is fetched only then.
 * The prevention data is the exception: the account check runs before the
 * deploy, and its details need each phase's actions as soon as it has passed.
 */

/** "9 min 50 s" between two timestamps, or an empty string if either is missing. */
function duration(start: string | null, end: string | null): string {
  if (!start || !end) return ''
  const seconds = Math.round((new Date(end).getTime() - new Date(start).getTime()) / 1000)
  if (Number.isNaN(seconds) || seconds < 0) return ''
  return `${Math.floor(seconds / 60)} min ${seconds % 60} s`
}

/** Route element for `/workflows/:runId`. */
export function WorkflowRunPage() {
  const { runId = '' } = useParams<{ runId: string }>()
  // Poll while the run is moving, stop once it has settled: a finished run
  // left open in a tab has nothing left to fetch.
  const [polling, setPolling] = useState(true)
  const { data: run, loading } = useWorkflowRun(runId || null, polling)

  useEffect(() => {
    if (run) setPolling(isOpen(run.status))
  }, [run])

  if (!run) {
    return (
      <div className="animate-fadeIn flex flex-col gap-5">
        <Crumbs label={runId ? 'Run' : ''} />
        <p className="py-16 text-center font-mono text-sm text-content-dim">
          {loading ? 'Loading…' : 'Workflow not found.'}
        </p>
      </div>
    )
  }

  return <RunView run={run} />
}

/** The page once the run has loaded. */
function RunView({ run }: { run: WorkflowRunDetail }) {
  const attackDone = stageState(run, 'attack') === 'done'
  const type = attackDone ? run.emulationType : null
  const preventionType = attackDone || run.accountCheck?.status === 'checked' ? run.emulationType : null

  const techniques = useCachedResource(
    type ? `emulation-techniques:${type}` : null,
    () => getEmulationTechniques(type as string),
  )
  // Prevention is supplementary: a refusal (it needs a verified account) or a
  // failure leaves the page intact and simply omits the Prevention lane.
  const prevention = useCachedResource(
    preventionType ? `prevention:${preventionType}` : null,
    () => getPrevention(preventionType as string),
  )

  const silent = run.score?.counts.silent ?? 0
  const took = run.status === 'completed' ? duration(run.startedAt, run.completedAt) : ''
  const waiting =
    run.status === 'awaiting_alerts'
      ? untilDeadline(run.alertDeadline)
      : run.status === 'scheduled'
        ? untilScheduled(run.scheduledFor)
        : ''

  return (
    <div className="animate-fadeIn flex flex-col gap-5">
      <div>
        <Crumbs label={run.emulationType} />
        <div className="flex flex-wrap items-start justify-between gap-4 mt-3.5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="font-display text-2xl font-medium text-content-primary">{run.emulationType}</h1>
              <Badge tone={STATUS_TONE[run.status]} mono dot pulse={isOpen(run.status)}>
                {STATUS_LABEL[run.status]}
              </Badge>
            </div>
            <p className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-content-dim tracking-body mt-2">
              <span>Started <span className="font-mono text-content-secondary">{formatWhen(run.createdAt)}</span></span>
              {took && <span>Took <span className="font-mono text-content-secondary">{took}</span></span>}
              {waiting && <span>{waiting}</span>}
            </p>
          </div>
          <RemoveRun run={run} />
        </div>
      </div>

      <PipelineGraph run={run} prevention={prevention.data ?? null} />

      {!attackDone ? (
        <p className="text-xs text-content-dim tracking-body px-1">
          {run.status === 'failed'
            ? 'The run stopped before the attack finished, so there are no phase results.'
            : 'The attack phases appear here once the emulation has finished.'}
        </p>
      ) : techniques.data ? (
        <AttackPhases run={run} phases={techniques.data.attackPath} prevention={prevention.data ?? null} />
      ) : (
        <p className="text-xs text-content-dim tracking-body px-1">
          {techniques.failed ? 'The attack phases could not be loaded.' : 'Loading attack phases…'}
        </p>
      )}

      {silent > 0 && (
        <Card className="p-5">
          <CloseTheGap workflowId={run.id} silentCount={silent} />
        </Card>
      )}

      {run.score && run.score.unattributedCount > 0 && <UnattributedAlerts score={run.score} />}
    </div>
  )
}

/** Breadcrumb back to the run list. */
function Crumbs({ label }: { label: string }) {
  return (
    <nav className="text-xs text-content-dim tracking-body">
      <Link to="/workflows" className="text-content-secondary no-underline transition-opacity hover:opacity-60">
        Workflows
      </Link>
      {label && <span> / {label}</span>}
    </nav>
  )
}

/**
 * Removing a run that owns nothing.
 *
 * Only failed and scheduled runs qualify. Failed runs pile up while an
 * integration is being set up, and a scheduled run needs a way out before its
 * time arrives. The stack reference is SET_NULL, so any infrastructure a run
 * created stays on the Stacks page.
 */
function RemoveRun({ run }: { run: WorkflowRunDetail }) {
  const navigate = useNavigate()
  const [confirming, setConfirming] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (run.status !== 'failed' && run.status !== 'scheduled') return null

  async function remove() {
    if (removing) return
    setRemoving(true)
    setError(null)
    try {
      await deleteWorkflowRun(run.id)
      navigate('/workflows')
    } catch (caught) {
      const detail = (caught as { response?: { data?: { detail?: string } } }).response?.data?.detail
      setError(detail ?? 'Could not remove this run.')
      setConfirming(false)
      setRemoving(false)
    }
  }

  const button = 'px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn transition-opacity hover:opacity-60'
  return (
    <div className="flex flex-col items-end gap-1.5">
      <div className="flex items-center gap-2">
        {confirming ? (
          <>
            <button
              type="button"
              onClick={() => setConfirming(false)}
              className={`${button} text-content-dim`}
            >
              Keep it
            </button>
            <button
              type="button"
              onClick={remove}
              disabled={removing}
              className={`${button} border border-danger/30 text-danger disabled:opacity-30 disabled:cursor-not-allowed`}
            >
              {removing ? 'Removing…' : 'Confirm remove'}
            </button>
          </>
        ) : (
          <button
            type="button"
            onClick={() => setConfirming(true)}
            className={`${button} border border-danger/30 text-danger`}
          >
            {run.status === 'scheduled' ? 'Cancel this run' : 'Remove this run'}
          </button>
        )}
      </div>
      <span className="text-2xs text-content-muted">
        {run.stackId ? 'Any infrastructure it created stays on the Stacks page.' : 'Nothing was deployed by this run.'}
      </span>
      {error && <span className="text-xs text-danger">{error}</span>}
    </div>
  )
}
