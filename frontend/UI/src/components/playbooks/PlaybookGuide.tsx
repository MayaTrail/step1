import { useEffect } from 'react'

import { BLOCK_LABELS, type BlockType } from './playbookBlocks'

/**
 * The playbook cheatsheet.
 *
 * A slide-over rather than a separate page, because the question it answers -
 * "which block do I use for this?" - is asked while editing, and sending
 * someone to another route to find out would lose their work's context.
 *
 * It documents what each block becomes for a reader, since that is the part
 * that is not visible from the editor alone.
 */

interface GuideEntry {
  type: BlockType
  becomes: string
  use: string
  avoid: string
}

const ENTRIES: GuideEntry[] = [
  {
    type: 'phase',
    becomes: 'A tab across the top of the playbook.',
    use: 'The stages of the response: Preparation, Identification, Containment, Eradication, Recovery, Lessons learned.',
    avoid: 'Do not use a phase for a single action - that is a Step. Six or seven phases is a normal playbook; twenty means some are really steps.',
  },
  {
    type: 'step',
    becomes: 'A checkable row with a progress bar across the phase.',
    use: 'One action a responder performs. Title it as an imperative: "Revoke the backdoor role".',
    avoid: 'Do not put three actions in one step - the person working the incident cannot half-tick a box.',
  },
  {
    type: 'command',
    becomes: 'A code block with a copy button.',
    use: 'The exact invocation, with real flags. Put it directly under the step it belongs to.',
    avoid: 'Do not paraphrase a command in prose. At 3am nobody wants to reconstruct the flags.',
  },
  {
    type: 'decision',
    becomes: 'An If / Then table.',
    use: 'Any point where the response branches: what you saw, and where it sends you next.',
    avoid: 'Do not bury a branch in prose. If the next action depends on what was found, it is a decision.',
  },
  {
    type: 'text',
    becomes: 'Prose, with an optional sub-heading.',
    use: 'Context that is not an action: detection triggers, prerequisites, who to call, what "normal" looks like here.',
    avoid: 'Do not use it for actions - they will not be checkable.',
  },
]

const TONE: Record<BlockType, string> = {
  phase: 'text-accent-blue border-accent-blue/40 bg-accent-blue/10',
  step: 'text-safe border-safe/40 bg-safe/10',
  command: 'text-warning border-warning/40 bg-warning/10',
  decision: 'text-danger border-danger/40 bg-danger/10',
  text: 'text-content-secondary border-border-active bg-surface-elevated',
}

export function PlaybookGuide({ onClose }: { onClose: () => void }) {
  // Escape closes, and the body must not scroll behind the panel.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      window.removeEventListener('keydown', onKey)
      document.body.style.overflow = previous
    }
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <button
        type="button"
        aria-label="Close the guide"
        onClick={onClose}
        className="absolute inset-0 bg-black/50"
      />

      <aside
        role="dialog"
        aria-label="Playbook guide"
        className="relative w-full max-w-[34rem] h-full overflow-y-auto bg-surface-base border-l border-border shadow-float"
      >
        <div className="sticky top-0 flex items-center gap-3 px-5 py-4 bg-surface-deep border-b border-border">
          <div>
            <div className="font-display text-[1.05rem] font-semibold text-content-primary">
              Writing a playbook
            </div>
            <div className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim mt-0.5">
              What each block becomes
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="ml-auto w-8 h-8 flex items-center justify-center rounded-btn text-content-dim hover:text-content-primary hover:bg-surface-elevated transition-colors"
          >
            &times;
          </button>
        </div>

        <div className="px-5 py-5 flex flex-col gap-5">
          <p className="text-[0.9rem] text-content-secondary leading-relaxed">
            A playbook is a list of blocks. The structure you build here is the
            structure a responder reads, so the block you choose decides how the
            content behaves during an incident.
          </p>

          {ENTRIES.map((entry) => (
            <div
              key={entry.type}
              className="border border-border-subtle rounded-card bg-surface-card overflow-hidden"
            >
              <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border-subtle bg-surface-deep">
                <span
                  className={[
                    'font-mono text-[0.65rem] uppercase tracking-[1.5px] px-2 py-0.5 rounded-btn border',
                    TONE[entry.type],
                  ].join(' ')}
                >
                  {BLOCK_LABELS[entry.type]}
                </span>
                <span className="text-[0.8rem] text-content-dim">
                  {entry.becomes}
                </span>
              </div>
              <dl className="px-4 py-3 text-[0.85rem] leading-relaxed">
                <dt className="font-mono text-[0.62rem] uppercase tracking-[1.5px] text-content-dim">
                  Use it for
                </dt>
                <dd className="text-content-secondary mt-1 mb-3">{entry.use}</dd>
                <dt className="font-mono text-[0.62rem] uppercase tracking-[1.5px] text-content-dim">
                  Watch out
                </dt>
                <dd className="text-content-secondary mt-1">{entry.avoid}</dd>
              </dl>
            </div>
          ))}

          <div className="border border-border-subtle rounded-card bg-surface-card p-4">
            <div className="font-display text-sm font-semibold text-content-primary mb-2">
              Three things worth knowing
            </div>
            <ul className="text-[0.85rem] text-content-secondary leading-relaxed flex flex-col gap-2 list-disc pl-4">
              <li>
                <b className="text-content-primary">Numbers are automatic.</b>{' '}
                Phase and step numbers come from position, so reorder freely and
                everything renumbers itself.
              </li>
              <li>
                <b className="text-content-primary">Start from a real one.</b>{' '}
                Every emulation ships a playbook. Forking one and adapting it is
                usually faster and better than a blank page.
              </li>
              <li>
                <b className="text-content-primary">It exports as Markdown.</b>{' '}
                Download gives you a <code>PLAYBOOK.md</code> that drops straight
                into a detection repo &mdash; the same format the shipped ones use.
              </li>
            </ul>
          </div>
        </div>
      </aside>
    </div>
  )
}
