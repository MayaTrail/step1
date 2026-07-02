import { useState } from 'react'
import type { PlaybookSection as Section } from '@/types'
import { Markdown } from '@/components/common/Markdown'
import { CommandBlock } from './CommandBlock'

/** One H4 sub-step parsed out of a section: a heading plus its markdown body. */
interface Step {
  /** Sequential number shown in the badge. */
  n: number
  /** Heading with any "Query N —" / "Step N —" prefix stripped. */
  title: string
  /** The step body (prose "what to look for" plus command blocks) as markdown. */
  body: string
}

/**
 * Split a section's markdown into an intro preamble and its H4 sub-steps.
 *
 * Composite playbooks structure each phase as "#### Query N — ..." or
 * "#### Step N — ..." blocks, optionally preceded by intro prose (detection
 * triggers, "immediate actions", etc.). Splitting on the H4 boundary keeps that
 * intro as `preamble` and turns each block into a numbered Step. A section with
 * no H4 headings yields zero steps, and the caller falls back to a plain render.
 */
function splitSteps(markdown: string): { preamble: string; steps: Step[] } {
  const parts = markdown.split(/^####\s+/m)
  const preamble = (parts[0] ?? '').trim()
  const steps: Step[] = parts.slice(1).map((part, i) => {
    const nl = part.indexOf('\n')
    const rawTitle = (nl === -1 ? part : part.slice(0, nl)).trim()
    const body = (nl === -1 ? '' : part.slice(nl + 1)).trim()
    // Drop a leading "Query 3 — " / "Step 3 - " so the badge carries the number.
    const title = rawTitle.replace(/^(query|step)\s+\d+\s*[—:-]\s*/i, '')
    return { n: i + 1, title, body }
  })
  return { preamble, steps }
}

/** Read/persist which steps of a section are checked off, keyed in localStorage. */
function useChecklist(storageKey: string, count: number) {
  const [done, setDone] = useState<Set<number>>(() => {
    try {
      const raw = localStorage.getItem(storageKey)
      if (!raw) return new Set()
      return new Set((JSON.parse(raw) as number[]).filter((i) => i < count))
    } catch {
      return new Set()
    }
  })

  const toggle = (i: number) => {
    setDone((prev) => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      try {
        localStorage.setItem(storageKey, JSON.stringify([...next]))
      } catch {
        // localStorage may be unavailable (private mode); progress is best-effort.
      }
      return next
    })
  }

  return { done, toggle }
}

/**
 * Split a step body into alternating prose and fenced-code segments so code
 * blocks can render as runnable CommandBlocks while prose stays plain markdown.
 */
function splitProseAndCode(markdown: string): Array<{ type: 'prose' | 'code'; content: string }> {
  const out: Array<{ type: 'prose' | 'code'; content: string }> = []
  const fence = /```[\w-]*\n([\s\S]*?)```/g
  let last = 0
  let m: RegExpExecArray | null
  while ((m = fence.exec(markdown)) !== null) {
    if (m.index > last) out.push({ type: 'prose', content: markdown.slice(last, m.index) })
    out.push({ type: 'code', content: (m[1] ?? '').replace(/\n+$/, '') })
    last = fence.lastIndex
  }
  if (last < markdown.length) out.push({ type: 'prose', content: markdown.slice(last) })
  return out
}

function StepBody({ markdown, emulationId }: { markdown: string; emulationId: string }) {
  const segments = splitProseAndCode(markdown)
  return (
    <>
      {segments.map((seg, i) =>
        seg.type === 'code' ? (
          <CommandBlock key={i} code={seg.content} emulationType={emulationId} />
        ) : seg.content.trim() ? (
          <Markdown key={i} content={seg.content} />
        ) : null,
      )}
    </>
  )
}

function CheckIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
      <path d="M2.5 6.2l2.3 2.3 4.7-5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

/**
 * Renders one playbook section. Sections with "#### " sub-steps become a
 * checkable step list with progress; anything else renders as plain markdown.
 */
export function PlaybookSection({ emulationId, section }: { emulationId: string; section: Section }) {
  const { preamble, steps } = splitSteps(section.markdown)
  const { done, toggle } = useChecklist(`mt:pb:${emulationId}:${section.id}`, steps.length)

  if (steps.length === 0) {
    return (
      <div className="bg-surface-card border border-border rounded-card shadow-ring p-6">
        <Markdown content={section.markdown} />
      </div>
    )
  }

  const pct = Math.round((done.size / steps.length) * 100)

  return (
    <div className="flex flex-col gap-3">
      {/* Section header with progress — sticky so it stays visible while scrolling. */}
      <div className="sticky top-0 z-10 flex items-center gap-4 flex-wrap bg-surface-deep/95 backdrop-blur-sm py-2.5 border-b border-border">
        <div className="font-display text-sm font-semibold text-content-primary">{section.title}</div>
        <div className="flex items-center gap-2.5 ml-auto min-w-[180px]">
          <span className="font-mono text-2xs text-content-dim whitespace-nowrap">
            {done.size} of {steps.length} done
          </span>
          <div className="flex-1 h-1 rounded-full bg-surface-elevated overflow-hidden">
            <div className="h-full bg-safe/60 transition-all" style={{ width: `${pct}%` }} />
          </div>
        </div>
      </div>

      {/* Intro prose that preceded the first step (detection triggers, etc.). */}
      {preamble && (
        <div className="bg-surface-card border border-border rounded-card shadow-ring px-6 py-5">
          <Markdown content={preamble} />
        </div>
      )}

      {/* Steps as rows in one card: a short step stays a compact row; a step with
          a command expands its content beneath the row instead of forcing every
          step into a full-height block. */}
      <div className="bg-surface-card border border-border rounded-card shadow-ring overflow-hidden">
        {steps.map((step) => {
          const checked = done.has(step.n - 1)
          return (
            <div key={step.n} className="border-b border-border last:border-b-0">
              <div className="flex items-center gap-3 px-5 py-3.5">
                <button
                  onClick={() => toggle(step.n - 1)}
                  aria-label={checked ? 'Mark step incomplete' : 'Mark step complete'}
                  className={`w-5 h-5 rounded-md border flex items-center justify-center shrink-0 transition-all
                    ${checked
                      ? 'bg-safe/20 border-safe/50 text-safe'
                      : 'border-border-active text-transparent hover:border-content-dim'
                    }`}
                >
                  <CheckIcon />
                </button>
                <span className="font-mono text-[12px] text-content-dim shrink-0 w-6">{String(step.n).padStart(2, '0')}</span>
                <span
                  className={`text-[0.9rem] font-semibold ${checked ? 'text-content-dim line-through' : 'text-content-primary'}`}
                >
                  {step.title}
                </span>
              </div>
              {step.body && (
                <div className="px-5 pb-4 pl-[52px] -mt-1">
                  <StepBody markdown={step.body} emulationId={emulationId} />
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
