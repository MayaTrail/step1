import { type Block, emptyBlock } from './playbookBlocks'

/**
 * Phases as a view over the flat block list.
 *
 * A playbook is stored, serialised and parsed as one ordered `Block[]`, because
 * that is what round-trips to the `## Phase` / `#### Step N -` Markdown the
 * shared reader already understands. Phases are not a separate data structure
 * and must not become one: introducing a nested shape here would mean two
 * representations to keep in step, and a forked PLAYBOOK.md would stop coming
 * apart and going back out unchanged.
 *
 * So the editor slices the same array by phase to show one at a time, and
 * splices edits back into it. The array stays the single source of truth.
 */

export interface PhaseGroup {
  /** The phase block itself, or null for blocks written before any phase. */
  phase: Block | null
  /** Index of the phase block in the flat list, or -1 for the lead-in group. */
  phaseIndex: number
  /** The blocks belonging to this phase, excluding the phase block. */
  blocks: Block[]
  /** Index in the flat list where this group's child blocks begin. */
  start: number
}

/**
 * Split a flat block list into phases.
 *
 * Anything before the first phase block becomes a lead-in group with a null
 * phase, rather than being dropped or silently absorbed into the first phase.
 * A forked playbook commonly opens with a classification table or a trigger
 * note above its first heading, and that content has to stay editable.
 *
 * @param blocks - The playbook's flat block list.
 * @returns One group per phase, in document order.
 */
export function groupIntoPhases(blocks: Block[]): PhaseGroup[] {
  const groups: PhaseGroup[] = []
  let current: PhaseGroup | null = null

  blocks.forEach((block, index) => {
    if (block.type === 'phase') {
      current = { phase: block, phaseIndex: index, blocks: [], start: index + 1 }
      groups.push(current)
      return
    }
    if (!current) {
      current = { phase: null, phaseIndex: -1, blocks: [], start: 0 }
      groups.push(current)
    }
    current.blocks.push(block)
  })

  return groups
}

/**
 * Replace one phase's child blocks, returning a new flat list.
 *
 * @param blocks - The current flat block list.
 * @param group - The group being edited, as returned by groupIntoPhases.
 * @param next - The group's blocks after editing.
 * @returns A new flat list with that slice swapped.
 */
export function replaceGroupBlocks(
  blocks: Block[],
  group: PhaseGroup,
  next: Block[],
): Block[] {
  return [
    ...blocks.slice(0, group.start),
    ...next,
    ...blocks.slice(group.start + group.blocks.length),
  ]
}

/**
 * Rename one phase, returning a new flat list.
 *
 * @param blocks - The current flat block list.
 * @param group - The group whose phase heading changed.
 * @param title - The new heading.
 * @returns A new flat list, unchanged when the group has no phase block.
 */
export function renamePhase(blocks: Block[], group: PhaseGroup, title: string): Block[] {
  const existing = blocks[group.phaseIndex]
  if (group.phaseIndex < 0 || !existing) return blocks
  const next = [...blocks]
  next[group.phaseIndex] = { ...existing, title }
  return next
}

/**
 * Append an empty phase to the end of the playbook.
 *
 * @param blocks - The current flat block list.
 * @returns A new flat list with one more phase block.
 */
export function addPhase(blocks: Block[]): Block[] {
  return [...blocks, emptyBlock('phase')]
}

/**
 * Remove a phase and everything under it.
 *
 * @param blocks - The current flat block list.
 * @param group - The group to remove.
 * @returns A new flat list without that phase or its children.
 */
export function removePhase(blocks: Block[], group: PhaseGroup): Block[] {
  const from = group.phaseIndex < 0 ? group.start : group.phaseIndex
  const count = group.blocks.length + (group.phaseIndex < 0 ? 0 : 1)
  return [...blocks.slice(0, from), ...blocks.slice(from + count)]
}
