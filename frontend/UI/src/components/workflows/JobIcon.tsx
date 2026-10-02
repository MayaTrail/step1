import type { CSSProperties, ReactNode } from 'react'
import type { StepKey, StepState } from './workflowMeta'

/**
 * The status icon of one pipeline job.
 *
 * A running job gets a small animation themed on what it is doing: blocks
 * stacking while infrastructure deploys, a radar sweep while the attack runs,
 * a bell ringing while MayaTrail waits for the SIEM. Every animation stops for
 * readers who ask their system to reduce motion.
 */

/** SVG groups rotate around their own anchor, not the corner of the icon. */
function pivot(x: number, y: number): CSSProperties {
  return { transformBox: 'view-box', transformOrigin: `${x}px ${y}px` }
}

/** The shared 18px outline icon; its colour comes from the text colour class. */
function Frame({ className, children }: { className: string; children: ReactNode }) {
  return (
    <svg
      width={18}
      height={18}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={`shrink-0 overflow-visible ${className}`}
    >
      {children}
    </svg>
  )
}

/** The animated icon for the job that is running right now. */
function Running({ stage }: { stage: StepKey }) {
  const still = 'motion-reduce:animate-none'
  if (stage === 'deploy') {
    return (
      <Frame className="text-accent-blue">
        <rect x="5" y="15" width="14" height="5" rx="1.2" className="fill-accent-blue-glow" />
        <rect x="5" y="9" width="14" height="5" rx="1.2" className={`fill-accent-blue-glow animate-stackBlockMid ${still}`} />
        <rect x="5" y="3" width="14" height="5" rx="1.2" className={`fill-accent-blue-glow animate-stackBlockTop ${still}`} />
      </Frame>
    )
  }
  if (stage === 'attack') {
    return (
      <Frame className="text-accent-blue">
        <circle cx="12" cy="12" r="9" />
        <circle cx="12" cy="12" r="4.5" opacity={0.35} />
        <g className={`animate-radarSweep ${still}`} style={pivot(12, 12)}>
          <line x1="12" y1="12" x2="12" y2="3" />
        </g>
        <circle cx="16" cy="8" r="1.5" fill="currentColor" stroke="none" className={`animate-radarBlip ${still}`} />
      </Frame>
    )
  }
  if (stage === 'alerts') {
    return (
      <Frame className="text-accent-blue">
        <g className={`animate-bellRing ${still}`} style={pivot(12, 4)}>
          <path d="M6 16v-5a6 6 0 1 1 12 0v5l1.5 2h-15z" className="fill-accent-blue-glow" />
          <path d="M10 20.5a2 2 0 0 0 4 0" />
        </g>
      </Frame>
    )
  }
  return (
    <Frame className="text-accent-blue">
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="3.5" fill="currentColor" stroke="none" className={`animate-pulse ${still}`} />
    </Frame>
  )
}

/**
 * @param stage - Which job the icon belongs to, which picks its animation.
 * @param state - Where the job is. `skipped` is grey, never red: a skipped
 *   account check let the run carry on. `unchecked` shares the pending outline.
 */
export function JobIcon({ stage, state }: { stage: StepKey; state: StepState }) {
  if (state === 'active') return <Running stage={stage} />
  if (state === 'skipped') {
    return (
      <Frame className="text-content-dim">
        <circle cx="12" cy="12" r="9" />
        <path d="M8 12h8" />
      </Frame>
    )
  }
  if (state === 'done') {
    return (
      <Frame className="text-safe">
        <circle cx="12" cy="12" r="9" />
        <path d="M8 12l3 3 5-6" />
      </Frame>
    )
  }
  if (state === 'failed') {
    return (
      <Frame className="text-danger">
        <circle cx="12" cy="12" r="9" />
        <path d="M9 9l6 6M15 9l-6 6" />
      </Frame>
    )
  }
  return (
    <Frame className="text-content-muted">
      <circle cx="12" cy="12" r="9" strokeDasharray="3 3" />
    </Frame>
  )
}
