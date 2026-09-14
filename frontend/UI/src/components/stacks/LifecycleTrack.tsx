import type { Stack, StackPhase, StackStatus } from '@/types'

/**
 * A stack's measured progress, on the card itself.
 *
 * Every phase here is a recorded status transition with a real timestamp, so
 * the durations are measured. The component it replaced drew six phases
 * inferred from the current status, which meant it could show "Provisioning
 * Resources" as complete without ever having timed it.
 *
 * The question this is built to answer is where a deploy is stuck and how long
 * it has been there, so the duration under each phase is the point of the
 * component, not decoration on it.
 */

/** Reader-facing name per status. Longer labels would wrap the track. */
const PHASE_LABEL: Partial<Record<StackStatus, string>> = {
  pending: 'Created',
  deploying: 'Deploying',
  ec2_booting: 'Booting',
  ready: 'Ready',
  ready_for_attack: 'Ready',
  attacking: 'Attacking',
  attack_complete: 'Attacked',
  refreshing: 'Refreshing',
  destroying: 'Destroying',
  destroyed: 'Destroyed',
  failed: 'Failed',
}

/**
 * Render a duration at the precision a reader can act on.
 *
 * @param seconds - Elapsed seconds, or null when the phase never started.
 * @returns For example "11s", "6m 41s", "1h 12m". Sub-minute values keep their
 *   seconds because the difference between 2s and 40s in a queue is a signal.
 */
export function formatDuration(seconds: number | null): string {
  if (seconds === null || Number.isNaN(seconds)) return ''
  const total = Math.floor(seconds)
  if (total < 60) return `${total}s`
  if (total < 3600) {
    const minutes = Math.floor(total / 60)
    const rest = total % 60
    return rest ? `${minutes}m ${rest}s` : `${minutes}m`
  }
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  return minutes ? `${hours}h ${minutes}m` : `${hours}h`
}

/**
 * Describe what the track shows, in one sentence.
 *
 * The sentence carries the finding the graphic only implies. A reader looking
 * at a slow deploy should not have to work out that it is slow.
 *
 * @param phases - The stack's measured phases.
 * @returns A sentence and the tone to render it in.
 */
function summarise(phases: StackPhase[]): { tone: string; text: string } | null {
  const current = phases[phases.length - 1]
  if (!current) return null

  const label = PHASE_LABEL[current.status] ?? current.status
  const elapsed = formatDuration(current.seconds)

  if (current.status === 'failed') {
    const previous = phases[phases.length - 2]
    const where = previous ? PHASE_LABEL[previous.status] ?? previous.status : 'setup'
    const took = previous ? formatDuration(previous.seconds) : ''
    return {
      tone: 'text-danger',
      text: current.detail
        ? `Failed during ${where}${took ? `, ${took} in` : ''}. ${current.detail}`
        : `Failed during ${where}${took ? `, ${took} in` : ''}.`,
    }
  }

  if (current.current && current.slow) {
    return {
      tone: 'text-warning',
      text: `Stuck in ${label} for ${elapsed}. This emulation usually clears it in about ${formatDuration(current.baselineSeconds)}.`,
    }
  }

  if (current.current) {
    return { tone: 'text-content-secondary', text: `In ${label} for ${elapsed}.` }
  }

  // A settled stack: report how long it took to get here, which is the figure
  // worth comparing between runs.
  const total = phases
    .slice(0, -1)
    .reduce((sum, phase) => sum + (phase.seconds ?? 0), 0)
  return {
    tone: 'text-content-secondary',
    text: `Reached ${label} in ${formatDuration(total)}.`,
  }
}

interface LifecycleTrackProps {
  stack: Stack
}

export function LifecycleTrack({ stack }: LifecycleTrackProps) {
  const phases = stack.lifecycle ?? []

  /*
   * A stack that predates this recording has nothing measured to draw, and the
   * card renders no track at all rather than a sentence explaining the absence.
   * The explanation lives in the Details tab, where it does not split the card.
   * Drawing phases from the current status instead is what this replaced.
   */
  if (phases.length === 0) return null

  const summary = summarise(phases)

  return (
    <div>
      <div className="flex items-start">
        {phases.map((phase, index) => (
          <Phase
            key={`${phase.status}-${phase.at}`}
            phase={phase}
            first={index === 0}
            last={index === phases.length - 1}
          />
        ))}
      </div>

      {summary && (
        <p className={`text-xs leading-relaxed tracking-body mt-3 ${summary.tone}`}>
          {summary.text}
        </p>
      )}
    </div>
  )
}

/** One phase: a pip on the track, its name, and the time spent in it. */
function Phase({ phase, first, last }: { phase: StackPhase; first: boolean; last: boolean }) {
  const failed = phase.status === 'failed'
  const running = phase.current && !failed

  const pip = failed
    ? 'border-danger bg-danger'
    : running
      ? 'border-accent-blue bg-accent-blue animate-pulse'
      : 'border-safe bg-safe'

  const line = failed ? 'bg-danger' : 'bg-safe'

  const label = failed
    ? 'text-danger font-semibold'
    : running
      ? 'text-accent-blue font-semibold'
      : 'text-content-secondary'

  const duration = phase.slow ? 'text-warning' : running ? 'text-accent-blue' : 'text-content-muted'

  return (
    <div className="flex-1 min-w-0 relative pt-4">
      {/* The rail is clipped at the ends so the track does not float past the
          first and last pips. */}
      <span
        aria-hidden="true"
        className={`absolute top-[5px] h-0.5 ${line} ${first ? 'left-1/2' : 'left-0'} ${last ? 'right-1/2' : 'right-0'}`}
      />
      <span
        aria-hidden="true"
        className={`absolute top-0 left-[calc(50%-6px)] w-3 h-3 rounded-full border-2 ${pip}`}
      />
      <span className={`block text-center text-2xs mt-0.5 truncate ${label}`}>
        {PHASE_LABEL[phase.status] ?? phase.status}
      </span>
      <span className={`block text-center font-mono text-2xs mt-0.5 ${duration}`}>
        {formatDuration(phase.seconds) || ' '}
      </span>
    </div>
  )
}
