import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import type {
  AttackPhase,
  DetectionCheck,
  DetectionRuleSummary,
  Emulation,
  EmulationRunRecord,
  EmulationRunStatus,
  MitreMapping,
} from '@/types'
import {
  getEmulationRun,
  listEmulationRuns,
  pollEmulationRunUntilDone,
} from '@/services/emulation.service'
import { fetchDetections } from '@/services/platform.service'
import { servicesForPlatform, type AwsService } from '@/data/awsServices'

const ACTIVE_STATUSES: EmulationRunStatus[] = ['pending', 'running']

// Poll cadence for an active run. This bounds how briefly a phase can be visible:
// a phase shorter than one interval can start and finish between two polls and
// never render as active, so it is kept at or below the backend's phase pacing
// (EMULATION_PHASE_PACING_SECONDS) rather than above it.
const POLL_INTERVAL_MS = 1000

// Equal, viewport-adaptive height for the phase-detail and live-output panels,
// with a floor so they never collapse on short screens (both scroll inside).
const PANEL_HEIGHT = 'h-[calc(100vh-520px)] min-h-[360px]'

type PhaseState = 'done' | 'active' | 'pending' | 'failed'

/**
 * Live emulation view.
 *
 * Finds the most recent run for this emulation and, while it is active, polls
 * the run record so the user can watch the attack travel through its kill
 * chain. Phases render as a left-to-right node flow: each node lights up as the
 * worker reports progress, and selecting one shows the techniques plus the AWS
 * services that phase touches (with service metadata from the catalogue).
 */
export function LiveEmulationTab({
  emulation,
  onRun,
  refreshKey = 0,
}: {
  emulation: Emulation
  onRun: () => void
  /** Changes when a run is triggered elsewhere, forcing this view to refetch. */
  refreshKey?: number
}) {
  const [run, setRun] = useState<EmulationRunRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<number | null>(null)
  const [rulesByTechnique, setRulesByTechnique] = useState<Map<string, DetectionRuleSummary>>(new Map())
  const consoleRef = useRef<HTMLPreElement>(null)

  useEffect(() => {
    const controller = new AbortController()
    let cancelled = false

    async function load() {
      setLoading(true)
      try {
        const runs = await listEmulationRuns()
        const latest = runs
          .filter((r) => r.emulation_type === emulation.id)
          .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))[0]
        if (!latest) {
          if (!cancelled) setRun(null)
          return
        }
        const initial = await getEmulationRun(latest.id)
        if (cancelled) return
        setRun(initial)
        if (ACTIVE_STATUSES.includes(initial.status)) {
          await pollEmulationRunUntilDone(
            latest.id,
            POLL_INTERVAL_MS,
            (updated) => !cancelled && setRun(updated),
            controller.signal,
          )
        }
      } catch (err) {
        if ((err as Error).name === 'AbortError') return
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    return () => {
      cancelled = true
      controller.abort()
    }
  }, [emulation.id, refreshKey])

  // Detection rules are static per emulation, so they load once rather than on
  // every poll. Keyed by normalised technique id so a phase's technique can be
  // matched against the rule written for it.
  useEffect(() => {
    let cancelled = false

    async function loadRules() {
      const data = await fetchDetections(emulation.id)
      if (cancelled || !data) return
      setRulesByTechnique(
        new Map(data.rules.map((rule) => [normaliseTechniqueId(rule.technique.id), rule])),
      )
    }

    loadRules()
    return () => {
      cancelled = true
    }
  }, [emulation.id])

  // Keep the console pinned to the newest output as it streams.
  useEffect(() => {
    if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight
  }, [run?.stdout])

  // Segment stdout per phase. Computed before any early return so the hook
  // order stays stable across renders (run is null on the first pass).
  const logByPhase = useMemo(() => segmentByPhase(run?.stdout ?? ''), [run?.stdout])

  if (loading && !run) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading run...</div>
  }

  if (!run) {
    return (
      <div className="bg-surface-card border border-border rounded-card p-10 text-center">
        <div className="text-content-primary text-[1rem] font-semibold mb-1.5">No runs yet</div>
        <p className="text-content-secondary text-[0.85rem] mb-5">
          Run {emulation.name} to watch it execute across your infrastructure, phase by phase.
        </p>
        <button
          onClick={onRun}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-semibold cursor-pointer border-none
            bg-danger text-white transition-all hover:-translate-y-px"
        >
          &#9654; Run Emulation
        </button>
      </div>
    )
  }

  const phases = emulation.attackPath
  const mapById = new Map<string, MitreMapping>(emulation.mitreMappings.map((m) => [m.id, m]))
  const activeIndex = activePhaseIndex(run, phases.length)
  const displayedIndex = Math.min(selected ?? activeIndex, phases.length - 1)
  const displayedPhase = phases[displayedIndex]
  const phaseLog = displayedPhase ? logByPhase.get(displayedPhase.phase) ?? '' : ''

  return (
    <div className="flex flex-col gap-4">
      <RunHeader run={run} phases={phases} />

      {/* Attack flow: left-to-right node graph, starting from the attacker */}
      <div className="bg-surface-card border border-border rounded-card p-6 overflow-x-auto">
        <div className="flex items-stretch min-w-min">
          <OriginNode />
          <FlowEdge state={phases.length ? phaseState(phases[0]!.phase, run) : 'pending'} />
          {phases.map((phase, i) => {
            const state = phaseState(phase.phase, run)
            const next = phases[i + 1]
            const nextState = next ? phaseState(next.phase, run) : null
            return (
              <div key={phase.phase} className="flex items-stretch">
                <PhaseNode
                  phase={phase}
                  state={state}
                  selected={i === displayedIndex}
                  services={phaseServices(phase, mapById)}
                  hits={successCount(logByPhase.get(phase.phase) ?? '')}
                  onClick={() => setSelected(i)}
                />
                {nextState && <FlowEdge state={nextState} />}
              </div>
            )
          })}
        </div>
      </div>

      {/* Selected phase detail + live console (equal, viewport-adaptive height) */}
      <div className="grid gap-4 lg:grid-cols-2 items-stretch">
        {displayedPhase && (
          <PhaseDetail
            phase={displayedPhase}
            mapById={mapById}
            phaseLog={phaseLog}
            rulesByTechnique={rulesByTechnique}
            detectionsBase={`/${emulation.platform}/emulations/${emulation.id}/detections`}
            className={PANEL_HEIGHT}
          />
        )}

        <div className={`bg-surface-card border border-border rounded-card p-5 flex flex-col ${PANEL_HEIGHT}`}>
          <div className="flex items-center gap-2 mb-3 shrink-0">
            <span className="text-[0.8rem] font-semibold tracking-[0.3px] text-content-secondary">Live Output</span>
            {run.status === 'running' && <span className="w-1.5 h-1.5 rounded-full bg-green animate-pulse" />}
          </div>
          <pre
            ref={consoleRef}
            className="flex-1 min-h-0 bg-[rgba(0,0,0,0.4)] border border-border rounded-btn p-4 font-mono text-[0.72rem] text-content-secondary
              leading-[1.6] whitespace-pre-wrap overflow-auto"
          >
            {run.stdout || 'Waiting for output...'}
            {run.stderr ? `\n${run.stderr}` : ''}
          </pre>
        </div>
      </div>

      {/* Once the run settles, point the operator at the validation loop: the
          attack is only half the exercise, the other half is checking whether
          their defenses saw it. */}
      {(run.status === 'completed' || run.status === 'failed') && <NextSteps emulation={emulation} run={run} />}
    </div>
  )
}

/**
 * Post-run guidance shown when a run reaches a terminal state. Directs the user
 * to the three things worth doing after an attack fires: work the IR playbook,
 * review the detection rules that should have caught it, and go check their own
 * logging to confirm the activity was recorded. The first two deep-link into
 * existing pages; the logging step is guidance because that lives in the user's
 * own environment, not this platform.
 */
function NextSteps({ emulation, run }: { emulation: Emulation; run: EmulationRunRecord }) {
  const base = `/${emulation.platform}/emulations/${emulation.id}`
  const check = run.detection_check
  // Only a completed check has something to show, so the tile stays plain
  // guidance until then rather than linking to an empty page.
  const coverage = check?.status === 'ok' ? check : null
  return (
    <div className="bg-surface-card border border-border rounded-card p-5">
      <div className="text-[0.85rem] font-semibold text-content-primary mb-1">What to do next</div>
      <p className="text-[0.78rem] text-content-secondary leading-[1.55] mb-4">
        The attack has run. Now validate whether your defenses caught it.
      </p>
      <div className="grid gap-3 sm:grid-cols-3">
        <NextStep
          to={`${base}/playbook`}
          title="Open the IR playbook"
          body="Work the detection and response steps mapped to this technique."
        />
        <NextStep
          to={`${base}/detections`}
          title="Review detection rules"
          body="Check the Sigma and KQL rules that should fire on this activity."
        />
        <NextStep
          to={coverage ? `${base}/logging/${run.id}` : undefined}
          title="Check your logging"
          body={
            coverage
              ? 'See which of this run’s detections actually fired in your logs.'
              : 'Search your SIEM or CloudTrail for the API calls above to confirm they were recorded.'
          }
          result={coverage ? coverageSummary(coverage) : undefined}
        />
      </div>
    </div>
  )
}

/**
 * Headline counts for the tile, so the answer is visible without leaving the run.
 *
 * @param check - A completed coverage report.
 */
function coverageSummary(check: DetectionCheck): string {
  const counts = check.counts ?? { fired: 0, silent: 0, no_logs: 0 }
  return `${counts.fired} fired · ${counts.silent} silent · ${counts.no_logs} no logs`
}

/** One "what next" tile. Renders as a link when `to` is set, else static guidance. */
function NextStep({
  to,
  title,
  body,
  result,
}: {
  to?: string
  title: string
  body: string
  /** Optional one-line outcome shown under a divider. */
  result?: string
}) {
  const inner = (
    <>
      <div className="text-[0.8rem] font-semibold text-content-primary mb-1">{title}</div>
      <div className="text-[0.72rem] text-content-secondary leading-[1.5]">{body}</div>
      {result && (
        <div className="font-mono text-[0.65rem] text-content-dim mt-2 pt-2 border-t border-border">
          {result}
        </div>
      )}
    </>
  )
  const cls = 'block border border-border rounded-btn px-3.5 py-3 bg-[rgba(255,255,255,0.01)] h-full'
  return to ? (
    <Link to={to} className={`${cls} no-underline transition-colors hover:border-accent-blue/40`}>
      {inner}
    </Link>
  ) : (
    <div className={cls}>{inner}</div>
  )
}

/* Progress helpers */

/** Index of the phase to treat as active/current, for header and follow. */
function activePhaseIndex(run: EmulationRunRecord, count: number): number {
  if (run.status === 'completed') return count - 1
  if (run.phase_current > 0) return Math.min(run.phase_current, count) - 1
  return 0
}

/** Determine a phase's state from the run's current phase and status. */
function phaseState(phaseNum: number, run: EmulationRunRecord): PhaseState {
  if (run.status === 'completed') return 'done'
  if (run.status === 'failed') {
    if (phaseNum < run.phase_current) return 'done'
    if (phaseNum === run.phase_current) return 'failed'
    return 'pending'
  }
  if (phaseNum < run.phase_current) return 'done'
  if (phaseNum === run.phase_current && run.phase_current > 0) return 'active'
  return 'pending'
}

/** Distinct AWS services a phase touches, resolved from its techniques' platforms. */
function phaseServices(phase: AttackPhase, mapById: Map<string, MitreMapping>): AwsService[] {
  const byLabel = new Map<string, AwsService>()
  for (const tech of phase.techniques) {
    const mapping = mapById.get(tech.id)
    if (!mapping?.platform) continue
    const resolved = servicesForPlatform(mapping.platform)
    if (resolved.length) {
      resolved.forEach((svc) => byLabel.set(svc.label, svc))
    } else {
      byLabel.set(mapping.platform, { label: mapping.platform, category: '', summary: '' })
    }
  }
  return Array.from(byLabel.values())
}

/* Header */

const STATUS_STYLE: Record<EmulationRunStatus, string> = {
  pending: 'text-yellow bg-yellow/10',
  running: 'text-accent-blue bg-accent-blue/[0.12]',
  completed: 'text-green bg-green/10',
  failed: 'text-danger bg-danger/10',
}

function RunHeader({ run, phases }: { run: EmulationRunRecord; phases: AttackPhase[] }) {
  const current = phases.find((p) => p.phase === run.phase_current)
  const total = phases.length

  let title: string
  let sub: string
  if (run.status === 'completed') {
    title = 'Emulation complete'
    sub = `${total} of ${total} phases executed`
  } else if (run.status === 'failed') {
    title = current ? `Failed at Phase ${run.phase_current} · ${current.name}` : 'Failed during setup'
    sub = current ? `${run.phase_current} of ${total} phases` : 'no phase reached'
  } else if (run.phase_current > 0 && current) {
    title = `Executing Phase ${run.phase_current} · ${current.name}`
    sub = `${run.phase_current} of ${total} phases`
  } else {
    title = run.status === 'pending' ? 'Queued' : 'Starting...'
    sub = 'initializing attack'
  }

  const started = run.started_at ? new Date(run.started_at) : null
  const ended = run.completed_at ? new Date(run.completed_at) : new Date()
  const elapsed = started ? Math.max(0, Math.round((ended.getTime() - started.getTime()) / 1000)) : null

  return (
    <div className="bg-surface-card border border-border rounded-card">
      <div className="p-5 flex items-center gap-5 flex-wrap">
        <span className={`font-mono text-[0.7rem] font-bold uppercase tracking-[1px] px-2.5 py-1 rounded ${STATUS_STYLE[run.status]}`}>
          {run.status}
        </span>
        <div>
          <div className="text-[1.15rem] font-[800] text-content-primary leading-tight tracking-[-0.3px]">{title}</div>
          <div className="font-mono text-[0.62rem] uppercase tracking-[1px] text-content-dim mt-1">{sub}</div>
        </div>
        {elapsed !== null && (
          <div className="ml-auto text-right">
            <div className="text-[1rem] font-[700] text-content-primary">{formatElapsed(elapsed)}</div>
            <div className="font-mono text-[0.62rem] uppercase tracking-[1px] text-content-dim mt-1">
              {run.status === 'running' ? 'Elapsed' : 'Duration'}
            </div>
          </div>
        )}
      </div>
      <RunMeta run={run} />
    </div>
  )
}

/**
 * Provenance section of the run header: who ran this, when it started and ended,
 * and what it ran against. Answers "what am I looking at" for anyone joining
 * mid-run, and gives the run an auditable identity via its stack and run id.
 *
 * Rendered inside RunHeader's card, below a divider, because status and
 * provenance describe the same run and reading as one block beats two stacked
 * headers competing for the top of the page.
 */
function RunMeta({ run }: { run: EmulationRunRecord }) {
  const items: { key: string; value: string; mono?: boolean }[] = [
    { key: 'Operator', value: run.triggered_by_email ?? 'Unknown' },
    { key: 'Started', value: formatTimestamp(run.started_at) },
    { key: 'Ended', value: run.completed_at ? formatTimestamp(run.completed_at) : 'In progress' },
    { key: 'Stack', value: run.stack_name || 'Unknown', mono: true },
    { key: 'Run ID', value: shortId(run.id), mono: true },
  ]
  return (
    <div className="border-t border-border px-5 py-3.5 flex gap-7 flex-wrap">
      {items.map((item) => (
        <div key={item.key}>
          <div className="font-mono text-[0.58rem] uppercase tracking-[1px] text-content-dim">{item.key}</div>
          <div className={`text-[0.8rem] font-semibold text-content-primary mt-0.5 ${item.mono ? 'font-mono' : ''}`}>
            {item.value}
          </div>
        </div>
      ))}
    </div>
  )
}

/** Render an ISO timestamp as a short local date and time, or a dash if absent. */
function formatTimestamp(iso: string | null): string {
  if (!iso) return '-'
  return new Date(iso).toLocaleString(undefined, {
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** Abbreviate a UUID to its first and last block, enough to match against logs. */
function shortId(id: string): string {
  return id.length > 13 ? `${id.slice(0, 8)}...${id.slice(-4)}` : id
}

function formatElapsed(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return m > 0 ? `${m}m ${String(s).padStart(2, '0')}s` : `${s}s`
}

/* Node flow */

const NODE_STATE: Record<PhaseState, { node: string; dot: string; name: string }> = {
  done: { node: 'border-green/40', dot: 'bg-green', name: 'text-content-primary' },
  active: { node: 'border-accent-blue bg-accent-blue/[0.06] animate-nodeGlow', dot: 'bg-accent-blue shadow-[0_0_8px_rgba(85,179,255,0.9)]', name: 'text-content-primary' },
  failed: { node: 'border-danger/50', dot: 'bg-danger', name: 'text-content-primary' },
  pending: { node: 'border-border opacity-50', dot: 'bg-content-dim', name: 'text-content-secondary' },
}

/**
 * Where the attack starts from. The kill chain begins with a principal the
 * attacker already controls, so showing it makes the first phase a consequence
 * of something rather than an unexplained starting point.
 */
function OriginNode() {
  return (
    <div className="w-[132px] min-h-[120px] rounded-[14px] border border-danger/40 bg-[#0d0e0f] p-3.5 flex flex-col gap-2 shrink-0">
      <div className="font-mono text-[0.6rem] uppercase tracking-[1px] text-content-dim flex items-center gap-1.5">
        <span className="w-[7px] h-[7px] rounded-full bg-danger" />
        Origin
      </div>
      <div className="text-[0.82rem] font-semibold leading-tight text-content-primary">Compromised credential</div>
      <div className="flex flex-wrap gap-1 mt-auto">
        <span className="font-mono text-[0.58rem] px-1.5 py-0.5 rounded bg-[rgba(255,255,255,0.05)] text-content-secondary">
          IAM
        </span>
      </div>
    </div>
  )
}

function PhaseNode({
  phase,
  state,
  selected,
  services,
  hits,
  onClick,
}: {
  phase: AttackPhase
  state: PhaseState
  selected: boolean
  services: AwsService[]
  hits: number
  onClick: () => void
}) {
  const style = NODE_STATE[state]
  return (
    <button
      onClick={onClick}
      className={`w-[170px] min-h-[120px] rounded-[14px] border bg-[#0d0e0f] p-3.5 flex flex-col gap-2 text-left transition-all cursor-pointer
        ${style.node} ${selected ? 'ring-1 ring-accent-blue/60' : ''}`}
    >
      <div className="font-mono text-[0.6rem] uppercase tracking-[1px] text-content-dim flex items-center gap-1.5">
        <span className={`w-[7px] h-[7px] rounded-full ${style.dot}`} />
        Phase {phase.phase}
      </div>
      <div className={`text-[0.82rem] font-semibold leading-tight ${style.name}`}>{phase.name}</div>
      {hits > 0 && (
        <div className="text-[0.66rem] text-danger leading-[1.4]">
          {hits} {hits === 1 ? 'action' : 'actions'} succeeded
        </div>
      )}
      <div className="flex flex-wrap gap-1 mt-auto">
        {services.map((svc) => (
          <span key={svc.label} className="font-mono text-[0.58rem] px-1.5 py-0.5 rounded bg-[rgba(255,255,255,0.05)] text-content-secondary">
            {svc.label}
          </span>
        ))}
      </div>
    </button>
  )
}

function FlowEdge({ state }: { state: PhaseState }) {
  const base = 'relative self-center w-10 h-[2px] shrink-0'
  if (state === 'done') return <div className={`${base} bg-green`} />
  if (state === 'active') {
    return (
      <div className={`${base} bg-gradient-to-r from-green to-accent-blue`}>
        <span className="absolute -top-[2px] w-2 h-1.5 rounded-full bg-accent-blue shadow-[0_0_8px_rgba(85,179,255,0.9)] animate-travel" />
      </div>
    )
  }
  return <div className={`${base} bg-[rgba(255,255,255,0.08)]`} />
}

/* Per-phase findings: impact is derived from each technique's MITRE tactic. */

const TACTIC_IMPACT: Record<string, { label: string; cls: string }> = {
  'Initial Access': { label: 'Compromised', cls: 'text-danger bg-danger/10' },
  'Execution': { label: 'Executed', cls: 'text-yellow bg-yellow/10' },
  'Persistence': { label: 'Created', cls: 'text-green bg-green/10' },
  'Privilege Escalation': { label: 'Escalated', cls: 'text-danger bg-danger/10' },
  'Defense Evasion': { label: 'Modified', cls: 'text-yellow bg-yellow/10' },
  'Credential Access': { label: 'Compromised', cls: 'text-danger bg-danger/10' },
  'Discovery': { label: 'Observed', cls: 'text-accent-blue bg-accent-blue/[0.12]' },
  'Lateral Movement': { label: 'Moved', cls: 'text-danger bg-danger/10' },
  'Collection': { label: 'Collected', cls: 'text-yellow bg-yellow/10' },
  'Exfiltration': { label: 'Exfiltrated', cls: 'text-danger bg-danger/10' },
  'Impact': { label: 'Impacted', cls: 'text-danger bg-danger/10' },
  'Resource Development': { label: 'Staged', cls: 'text-accent-blue bg-accent-blue/[0.12]' },
}

/**
 * Split a run's stdout into per-phase slices using the same "PHASE N" markers
 * the worker uses to track progress, so each phase shows the log lines it
 * actually produced. Returns phase number -> log text.
 */
function segmentByPhase(stdout: string): Map<number, string> {
  const lines = new Map<number, string[]>()
  let current = 0
  for (const line of stdout.split('\n')) {
    const match = line.match(/\bPHASE\s+(\d+)/i)
    if (match) current = parseInt(match[1] ?? '0', 10)
    if (current > 0) {
      const bucket = lines.get(current) ?? []
      bucket.push(line)
      lines.set(current, bucket)
    }
  }
  const out = new Map<number, string>()
  lines.forEach((bucket, phase) => {
    // Drop decorative banner rules; keep the substance.
    out.set(phase, bucket.filter((l) => !/^\s*=+\s*$/.test(l)).join('\n').trim())
  })
  return out
}

/* Detection coverage: does a rule exist for this technique */

/**
 * Reduce a technique id to a form both sides can be matched on.
 *
 * A rule's technique id comes from its detection filename, where the
 * sub-technique separator must be a dot (t1552.005) to match the MANIFEST.
 * Underscores are tolerated here so a newly authored rule that gets the
 * separator wrong still links instead of silently reporting no coverage.
 *
 * The rule's own ruleId builds the URL, so the API receives the form it stores.
 */
function normaliseTechniqueId(id: string): string {
  return id.toUpperCase().replace(/_/g, '.')
}

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'text-danger bg-danger/10',
  high: 'text-danger bg-danger/10',
  medium: 'text-yellow bg-yellow/10',
  low: 'text-accent-blue bg-accent-blue/[0.12]',
}

/**
 * Link from a technique to the detection rule written for it, or state plainly
 * that none exists.
 *
 * The absence of a rule is deliberately shown rather than hidden: a technique
 * with no detection is a coverage gap, which is exactly what a defender needs to
 * notice after watching the attack succeed.
 *
 * The rule's own ruleId is used to build the URL rather than lower-casing the
 * technique id, since the id is derived from the detection filename and the API
 * looks it up in that exact form.
 */
function DetectionLink({
  rule,
  detectionsBase,
}: {
  rule: DetectionRuleSummary | undefined
  detectionsBase: string
}) {
  if (!rule) {
    return (
      <div className="text-[0.72rem] text-content-dim mt-2">No detection rule written for this technique yet.</div>
    )
  }

  const severity = rule.severity?.toLowerCase() ?? ''
  const formats = [rule.formats.sigma && 'Sigma', rule.formats.kql && 'KQL'].filter(Boolean).join(' + ')

  return (
    <Link
      to={`${detectionsBase}/${rule.ruleId}`}
      className="flex items-center gap-2 flex-wrap mt-2 no-underline transition-opacity hover:opacity-60"
    >
      <span className="text-[0.72rem] text-accent-blue font-semibold">Detection rule: {rule.title}</span>
      {severity && SEVERITY_STYLE[severity] && (
        <span className={`font-mono text-[0.56rem] uppercase font-bold tracking-[0.5px] px-1.5 py-0.5 rounded ${SEVERITY_STYLE[severity]}`}>
          {severity}
        </span>
      )}
      {formats && <span className="font-mono text-[0.6rem] text-content-dim">{formats}</span>}
    </Link>
  )
}

/* API calls: extracted from the phase's log text */

// AWS API calls are printed as service:Action, e.g. iam:CreateAccessKey.
const API_CALL_PATTERN = /\b([a-z][a-z0-9-]{1,30}):([A-Z][A-Za-z0-9]{2,60})\b/g

// ARNs are colon-separated and their trailing segments mimic the pattern above
// (arn:aws:secretsmanager:us-east-1:123456789012:secret:MyDbPassword would
// otherwise yield a bogus "secret:MyDbPassword" call), so they are removed
// before scanning rather than filtered out afterwards.
const ARN_PATTERN = /\barn:aws[a-z-]*:\S+/g

// AWS filter syntax borrows the same shape without describing a call: an EC2
// describe filter named "tag:Name" is not an API action.
const NOT_API_PREFIXES = new Set(['tag'])

/**
 * Extract the distinct AWS API calls a phase's log mentions, in the order they
 * first appear.
 *
 * First-seen order is kept rather than sorting alphabetically because it traces
 * the sequence the attacker actually called, which is what makes the list
 * readable as a story. These are the exact strings an analyst searches for in
 * CloudTrail or a SIEM, so they are shown verbatim.
 */
function extractApiCalls(phaseLog: string): string[] {
  const withoutArns = phaseLog.replace(ARN_PATTERN, ' ')
  const calls = new Set<string>()
  for (const match of withoutArns.matchAll(API_CALL_PATTERN)) {
    const service = match[1] ?? ''
    if (NOT_API_PREFIXES.has(service)) continue
    calls.add(`${service}:${match[2]}`)
  }
  return Array.from(calls)
}

/** Chip row of the API calls a phase generated, for SIEM and CloudTrail lookup. */
function ApiCalls({ phaseLog }: { phaseLog: string }) {
  const calls = useMemo(() => extractApiCalls(phaseLog), [phaseLog])
  if (!calls.length) return null
  return (
    <div>
      <div className="font-mono text-[0.6rem] uppercase tracking-[1px] text-content-dim mb-2">API calls observed</div>
      <div className="flex flex-wrap gap-1.5">
        {calls.map((call) => (
          <span
            key={call}
            className="font-mono text-[0.66rem] px-2 py-1 rounded border border-border bg-accent-blue/[0.06] text-accent-blue select-all"
          >
            {call}
          </span>
        ))}
      </div>
      <div className="text-[0.72rem] text-content-secondary leading-[1.5] mt-2">
        Search these in CloudTrail or your SIEM to confirm the activity was recorded.
      </div>
    </div>
  )
}

/* Observed results: parsed from the phase's log lines */

type ObservedKind = 'success' | 'failure' | 'warning' | 'info'

interface Observation {
  kind: ObservedKind
  text: string
}

const OBSERVED_STYLE: Record<ObservedKind, { label: string; cls: string }> = {
  success: { label: 'Success', cls: 'text-danger bg-danger/10' },
  failure: { label: 'Failed', cls: 'text-content-secondary bg-[rgba(255,255,255,0.05)]' },
  warning: { label: 'Warning', cls: 'text-yellow bg-yellow/10' },
  info: { label: 'Info', cls: 'text-accent-blue bg-accent-blue/[0.12]' },
}

// Attack modules mark each printed result with a prefix: [+] the step worked,
// [-] the step failed, [!] a warning or error note, [*] progress information.
// A successful attacker step is styled as danger, not green, because from the
// defender's point of view it is the bad outcome.
const OBSERVED_PREFIX: Record<string, ObservedKind> = {
  '+': 'success',
  '-': 'failure',
  '!': 'warning',
  '*': 'info',
}

/**
 * Extract structured observations from a phase's raw log text.
 *
 * Only prefixed lines are treated as results; everything else (banners, blank
 * lines, free-form narration) is left for the raw log view. Modules that do not
 * use the prefix convention yield an empty list, and the caller falls back to
 * showing the raw log on its own.
 */
function parseObservations(phaseLog: string): Observation[] {
  const observations: Observation[] = []
  for (const line of phaseLog.split('\n')) {
    const match = line.match(/^\s*\[([+\-!*])\]\s*(.+)$/)
    if (!match) continue
    const kind = OBSERVED_PREFIX[match[1] ?? '']
    const text = (match[2] ?? '').trim()
    if (kind && text) observations.push({ kind, text })
  }
  return observations
}

/** Count of attacker steps that succeeded in a phase, for the node summary. */
function successCount(phaseLog: string): number {
  return parseObservations(phaseLog).filter((o) => o.kind === 'success').length
}

/**
 * One-line verdict summarising what a phase achieved, in defender terms.
 *
 * Reads as plain counts rather than jargon so a non-specialist can follow what
 * the attacker got and what the environment refused.
 */
function observedVerdict(observations: Observation[]): string {
  const succeeded = observations.filter((o) => o.kind === 'success').length
  const failed = observations.filter((o) => o.kind === 'failure').length
  const warned = observations.filter((o) => o.kind === 'warning').length

  const parts: string[] = []
  if (succeeded) parts.push(`${succeeded} attacker ${succeeded === 1 ? 'action' : 'actions'} succeeded`)
  if (failed) parts.push(`${failed} failed`)
  if (warned) parts.push(`${warned} ${warned === 1 ? 'warning' : 'warnings'}`)
  return parts.length ? parts.join(', ') : 'No results reported for this phase.'
}

/** Findings list for the selected phase, with the raw log kept behind a toggle. */
function ObservedResults({ phaseLog }: { phaseLog: string }) {
  const [showRaw, setShowRaw] = useState(false)
  const observations = useMemo(() => parseObservations(phaseLog), [phaseLog])

  if (!phaseLog) {
    return <div className="text-[0.75rem] text-content-dim">No activity captured for this phase yet.</div>
  }

  const rawLines = phaseLog.split('\n').length

  return (
    <div className="flex flex-col gap-2.5">
      {observations.length > 0 && (
        <>
          <div className="text-[0.8rem] font-semibold text-content-primary leading-[1.5]">
            {observedVerdict(observations)}
          </div>
          <div className="flex flex-col gap-1.5">
            {observations.map((obs, i) => {
              const style = OBSERVED_STYLE[obs.kind]
              return (
                <div key={`${i}-${obs.text}`} className="flex items-start gap-2">
                  <span
                    className={`font-mono text-[0.56rem] uppercase font-bold tracking-[0.5px] px-1.5 py-0.5 rounded shrink-0 mt-px ${style.cls}`}
                  >
                    {style.label}
                  </span>
                  <span className="text-[0.75rem] text-content-secondary leading-[1.5] break-words min-w-0">
                    {obs.text}
                  </span>
                </div>
              )
            })}
          </div>
        </>
      )}

      {observations.length > 0 ? (
        <button
          onClick={() => setShowRaw((v) => !v)}
          className="self-start font-mono text-[0.62rem] uppercase tracking-[1px] text-content-dim bg-transparent border-none p-0 cursor-pointer transition-opacity hover:opacity-60"
        >
          {showRaw ? 'Hide' : 'Show'} raw log ({rawLines} {rawLines === 1 ? 'line' : 'lines'})
        </button>
      ) : null}

      {(showRaw || observations.length === 0) && (
        <pre className="bg-[rgba(0,0,0,0.3)] border border-border rounded-btn p-3 font-mono text-[0.68rem] text-content-secondary leading-[1.55] whitespace-pre-wrap overflow-x-auto">
          {phaseLog}
        </pre>
      )}
    </div>
  )
}

/* Selected-phase detail: services, findings (impact + techniques), observed log */

function PhaseDetail({
  phase,
  mapById,
  phaseLog,
  rulesByTechnique,
  detectionsBase,
  className = '',
}: {
  phase: AttackPhase
  mapById: Map<string, MitreMapping>
  phaseLog: string
  rulesByTechnique: Map<string, DetectionRuleSummary>
  detectionsBase: string
  className?: string
}) {
  const services = phaseServices(phase, mapById)
  return (
    <div className={`bg-surface-card border border-border rounded-card p-5 flex flex-col ${className}`}>
      <div className="text-[0.8rem] font-semibold tracking-[0.3px] text-content-secondary mb-3 shrink-0">
        Phase {phase.phase} · {phase.name}
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto flex flex-col gap-4 pr-1">
        {/* Services engaged */}
        {services.length > 0 && (
          <div>
            <div className="font-mono text-[0.6rem] uppercase tracking-[1px] text-content-dim mb-2">Services engaged</div>
            <div className="flex flex-col gap-2">
              {services.map((svc) => (
                <div key={svc.label} className="border border-border rounded-btn px-3 py-2.5 bg-[rgba(255,255,255,0.01)]">
                  <div className="flex items-center gap-2">
                    <span className="text-[0.82rem] font-semibold text-content-primary">{svc.label}</span>
                    {svc.category && (
                      <span className="font-mono text-[0.58rem] uppercase tracking-[0.5px] px-1.5 py-0.5 rounded bg-accent-blue/[0.12] text-accent-blue">
                        {svc.category}
                      </span>
                    )}
                  </div>
                  {svc.summary && <div className="text-[0.75rem] text-content-secondary leading-[1.55] mt-1">{svc.summary}</div>}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Findings: what this phase does, classified by MITRE tactic */}
        <div>
          <div className="font-mono text-[0.6rem] uppercase tracking-[1px] text-content-dim mb-2">Findings</div>
          <div className="flex flex-col gap-2">
            {phase.techniques.map((tech) => {
              const mapping = mapById.get(tech.id)
              const impact = mapping ? TACTIC_IMPACT[mapping.tactic] : undefined
              return (
                <div key={tech.id} className="border border-border rounded-btn px-3 py-2.5 bg-[rgba(255,255,255,0.01)]">
                  <div className="flex items-center gap-2 flex-wrap">
                    {impact && (
                      <span className={`font-mono text-[0.56rem] uppercase font-bold tracking-[0.5px] px-1.5 py-0.5 rounded ${impact.cls}`}>
                        {impact.label}
                      </span>
                    )}
                    <span className="font-mono text-[0.66rem] text-accent-blue">{tech.id}</span>
                    <span className="text-[0.78rem] text-content-primary">{tech.name}</span>
                  </div>
                  {mapping?.platform && (
                    <div className="font-mono text-[0.62rem] text-content-dim mt-1">Service: {mapping.platform}</div>
                  )}
                  {mapping?.description && (
                    <div className="text-[0.75rem] text-content-secondary leading-[1.55] mt-1">{mapping.description}</div>
                  )}
                  <DetectionLink
                    rule={rulesByTechnique.get(normaliseTechniqueId(tech.id))}
                    detectionsBase={detectionsBase}
                  />
                </div>
              )
            })}
          </div>
        </div>

        {/* Derived from the run: the API calls this phase actually generated */}
        <ApiCalls phaseLog={phaseLog} />

        {/* Observed: the actual log lines this phase produced during the run */}
        <div>
          <div className="font-mono text-[0.6rem] uppercase tracking-[1px] text-content-dim mb-2">Observed in this run</div>
          <ObservedResults phaseLog={phaseLog} />
        </div>
      </div>
    </div>
  )
}
