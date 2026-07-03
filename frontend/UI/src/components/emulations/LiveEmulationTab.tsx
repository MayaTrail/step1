import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import type {
  AttackPhase,
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
import { servicesForPlatform, type AwsService } from '@/data/awsServices'

const ACTIVE_STATUSES: EmulationRunStatus[] = ['pending', 'running']

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
export function LiveEmulationTab({ emulation, onRun }: { emulation: Emulation; onRun: () => void }) {
  const [run, setRun] = useState<EmulationRunRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<number | null>(null)
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
            2000,
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

      {/* Attack flow: left-to-right node graph */}
      <div className="bg-surface-card border border-border rounded-card p-6 overflow-x-auto">
        <div className="flex items-stretch min-w-min">
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
          <PhaseDetail phase={displayedPhase} mapById={mapById} phaseLog={phaseLog} className={PANEL_HEIGHT} />
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
      {(run.status === 'completed' || run.status === 'failed') && <NextSteps emulation={emulation} />}
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
function NextSteps({ emulation }: { emulation: Emulation }) {
  const base = `/${emulation.platform}/emulations/${emulation.id}`
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
          title="Check your logging"
          body="Search your SIEM or CloudTrail for the API calls above to confirm they were recorded."
        />
      </div>
    </div>
  )
}

/** One "what next" tile. Renders as a link when `to` is set, else static guidance. */
function NextStep({ to, title, body }: { to?: string; title: string; body: string }) {
  const inner = (
    <>
      <div className="text-[0.8rem] font-semibold text-content-primary mb-1">{title}</div>
      <div className="text-[0.72rem] text-content-secondary leading-[1.5]">{body}</div>
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
    <div className="bg-surface-card border border-border rounded-card p-5 flex items-center gap-5 flex-wrap">
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
  )
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

function PhaseNode({
  phase,
  state,
  selected,
  services,
  onClick,
}: {
  phase: AttackPhase
  state: PhaseState
  selected: boolean
  services: AwsService[]
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

/* Selected-phase detail: services, findings (impact + techniques), observed log */

function PhaseDetail({
  phase,
  mapById,
  phaseLog,
  className = '',
}: {
  phase: AttackPhase
  mapById: Map<string, MitreMapping>
  phaseLog: string
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
                </div>
              )
            })}
          </div>
        </div>

        {/* Observed: the actual log lines this phase produced during the run */}
        <div>
          <div className="font-mono text-[0.6rem] uppercase tracking-[1px] text-content-dim mb-2">Observed in this run</div>
          {phaseLog ? (
            <pre className="bg-[rgba(0,0,0,0.3)] border border-border rounded-btn p-3 font-mono text-[0.68rem] text-content-secondary leading-[1.55] whitespace-pre-wrap overflow-x-auto">
              {phaseLog}
            </pre>
          ) : (
            <div className="text-[0.75rem] text-content-dim">No activity captured for this phase yet.</div>
          )}
        </div>
      </div>
    </div>
  )
}
