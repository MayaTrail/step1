import { useEffect, useMemo, useState } from 'react'
import { BlockEditor } from './BlockEditor'
import type { Block } from './playbookBlocks'
import {
  addPhase,
  groupIntoPhases,
  removePhase,
  renamePhase,
  replaceGroupBlocks,
} from './phaseGroups'

/**
 * The editor's blocks, one phase at a time.
 *
 * A playbook of any length is twenty or more blocks in one column, and the
 * author is almost always working inside a single phase: writing Containment
 * means scrolling past Identification every time. Tabs scope the canvas to the
 * phase in hand, and mirror what the reader sees, since the reader renders
 * phases as tabs too.
 *
 * The flat `Block[]` remains the single source of truth. This slices it for
 * display and splices edits back, because that array is what serialises to the
 * `## Phase` / `#### Step N -` Markdown the shared reader parses. A nested
 * phase structure would be a second representation to keep in step and would
 * break the byte-for-byte round trip of a forked PLAYBOOK.md.
 */

interface PhaseTabsProps {
  blocks: Block[]
  onChange: (next: Block[]) => void
  disabled?: boolean
}

export function PhaseTabs({ blocks, onChange, disabled = false }: PhaseTabsProps) {
  const groups = useMemo(() => groupIntoPhases(blocks), [blocks])
  const [active, setActive] = useState(0)

  // Keep the selection inside the list as phases are added or removed, so a
  // deleted phase does not leave the canvas pointing past the end.
  useEffect(() => {
    if (active >= groups.length) setActive(Math.max(0, groups.length - 1))
  }, [active, groups.length])

  const group = groups[active]

  if (groups.length === 0) {
    return (
      <div className="border border-dashed border-border-active rounded-card px-6 py-10 text-center">
        <p className="text-sm text-content-secondary">This playbook has no phases yet.</p>
        <p className="text-xs text-content-dim mt-1.5 leading-relaxed">
          A phase is a stage of the response, and becomes a tab for whoever works the incident.
        </p>
        <button
          type="button"
          disabled={disabled}
          onClick={() => onChange(addPhase(blocks))}
          className="mt-4 px-3 py-1.5 rounded-btn font-mono text-2xs uppercase tracking-label
            border border-border-active text-content-primary transition-opacity hover:opacity-60
            disabled:opacity-30"
        >
          Add the first phase
        </button>
      </div>
    )
  }

  return (
    <div>
      <div
        role="tablist"
        aria-label="Playbook phases"
        className="flex flex-wrap items-center gap-1 border-b border-border mb-5"
      >
        {groups.map((entry, index) => (
          <button
            key={entry.phase?.id ?? 'lead-in'}
            type="button"
            role="tab"
            aria-selected={index === active}
            onClick={() => setActive(index)}
            className={`px-3 py-2.5 text-[0.8rem] border-b-2 bg-transparent cursor-pointer
              transition-opacity hover:opacity-60
              ${index === active
                ? 'text-content-primary border-b-accent-blue font-semibold'
                : 'text-content-dim border-b-transparent'}`}
          >
            {entry.phase ? entry.phase.title || 'Untitled phase' : 'Before the first phase'}
            <span className="ml-1.5 font-mono text-2xs text-content-muted font-normal">
              {entry.blocks.length}
            </span>
          </button>
        ))}

        <button
          type="button"
          disabled={disabled}
          onClick={() => {
            onChange(addPhase(blocks))
            setActive(groups.length)
          }}
          className="px-3 py-2.5 text-[0.8rem] bg-transparent border-none text-accent-blue
            cursor-pointer transition-opacity hover:opacity-60 disabled:opacity-30"
        >
          + Add phase
        </button>
      </div>

      {group && (
        <>
          <div className="flex items-center gap-3 mb-1">
            {group.phase ? (
              <input
                value={group.phase.title}
                disabled={disabled}
                onChange={(event) => onChange(renamePhase(blocks, group, event.target.value))}
                placeholder="Phase name, for example Containment"
                className="flex-1 min-w-0 bg-transparent border-none outline-none
                  font-display text-[1.15rem] font-bold tracking-tight text-content-primary
                  placeholder:text-content-muted placeholder:font-normal py-0.5"
              />
            ) : (
              /* Content a fork carried above its first heading: a classification
                 table or a trigger note. Editable, but it has no name to set. */
              <span className="flex-1 font-display text-[1.15rem] font-bold text-content-dim">
                Before the first phase
              </span>
            )}

            {group.phase && (
              <button
                type="button"
                disabled={disabled}
                onClick={() => {
                  onChange(removePhase(blocks, group))
                  setActive((current) => Math.max(0, current - 1))
                }}
                className="shrink-0 px-2.5 py-1 rounded-btn font-mono text-2xs uppercase
                  tracking-label border border-danger/30 text-danger bg-transparent
                  cursor-pointer transition-opacity hover:opacity-60 disabled:opacity-30"
              >
                Remove phase
              </button>
            )}
          </div>

          <p className="font-mono text-2xs text-content-muted mb-4">
            {group.blocks.length} block{group.blocks.length === 1 ? '' : 's'}
            {' / '}
            {group.blocks.filter((block) => block.type === 'step').length} step
            {group.blocks.filter((block) => block.type === 'step').length === 1 ? '' : 's'}
          </p>

          {/* The palette offers no phase: phases are created from the tab strip,
              so a phase can never be nested inside the phase being edited. */}
          <BlockEditor
            blocks={group.blocks}
            onChange={(next) => onChange(replaceGroupBlocks(blocks, group, next))}
            disabled={disabled}
            allowPhase={false}
          />
        </>
      )}
    </div>
  )
}
