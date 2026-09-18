import { useMemo } from 'react'

import { RichTextEditor } from './RichTextEditor'

import {
  BLOCK_HINTS,
  BLOCK_LABELS,
  type Block,
  type BlockType,
  emptyBlock,
} from './playbookBlocks'

/**
 * Block-based playbook editor.
 *
 * A playbook is authored as a sequence of typed blocks rather than as one
 * undivided document, so the structure the reader renders - phases, checkable
 * steps, commands, decision points - is the structure the author manipulates.
 *
 * Each block knows what it is, so it can offer the right fields: a command
 * block gets a language and a monospace body, a decision gets condition/action
 * rows, a step gets a title and notes. Phase and step numbers are never typed;
 * they are derived from order, so moving a block renumbers everything.
 */

interface BlockEditorProps {
  blocks: Block[]
  onChange: (blocks: Block[]) => void
  disabled?: boolean
  /**
   * Whether the palette offers a phase. False when the editor is scoped to one
   * phase by PhaseTabs, since a phase inside a phase has no meaning and would
   * serialise to a heading in the middle of another heading's section.
   */
  allowPhase?: boolean
}

const INPUT =
  'w-full bg-surface-base border border-border-subtle rounded-btn px-3 py-2 text-[0.875rem] ' +
  'text-content-primary placeholder:text-content-muted focus:outline-none focus:border-accent-blue transition-colors'

const TEXTAREA = `${INPUT} resize-y min-h-[5rem] leading-relaxed`

/** Tone per block type so the spine reads at a glance. */
const TONE: Record<BlockType, string> = {
  phase: 'text-accent-blue border-accent-blue/40 bg-accent-blue/10',
  step: 'text-safe border-safe/40 bg-safe/10',
  command: 'text-warning border-warning/40 bg-warning/10',
  decision: 'text-danger border-danger/40 bg-danger/10',
  text: 'text-content-secondary border-border-active bg-surface-elevated',
}

function IconBtn({
  onClick,
  title,
  disabled,
  children,
  danger,
}: {
  onClick: () => void
  title: string
  disabled?: boolean
  children: React.ReactNode
  danger?: boolean
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-label={title}
      disabled={disabled}
      className={[
        'w-7 h-7 flex items-center justify-center rounded-btn text-[0.8rem] transition-colors',
        'disabled:opacity-30 disabled:cursor-not-allowed',
        danger
          ? 'text-content-dim hover:text-danger hover:bg-danger/10'
          : 'text-content-dim hover:text-content-primary hover:bg-surface-elevated',
      ].join(' ')}
    >
      {children}
    </button>
  )
}

/** The fields for one block, chosen by its type. */
function BlockFields({
  block,
  update,
  disabled,
}: {
  block: Block
  update: (patch: Partial<Block>) => void
  disabled?: boolean
}) {
  switch (block.type) {
    case 'command':
      return (
        <div className="flex flex-col gap-2">
          <input
            className={INPUT}
            value={block.title}
            disabled={disabled}
            placeholder="What this command is for (optional)"
            onChange={(e) => update({ title: e.target.value })}
          />
          <div className="flex items-center gap-2">
            <span className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim">
              Language
            </span>
            <select
              className={`${INPUT} w-auto py-1`}
              value={block.language ?? 'bash'}
              disabled={disabled}
              onChange={(e) => update({ language: e.target.value })}
            >
              {['bash', 'json', 'yaml', 'sql', 'python', 'text'].map((l) => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
          </div>
          <textarea
            className={`${TEXTAREA} font-mono text-[0.8rem]`}
            value={block.body}
            disabled={disabled}
            placeholder="aws cloudtrail describe-trails --region us-east-1"
            spellCheck={false}
            onChange={(e) => update({ body: e.target.value })}
          />
        </div>
      )

    case 'decision': {
      const branches = block.branches ?? []
      const setBranch = (i: number, patch: Partial<{ condition: string; action: string }>) =>
        update({ branches: branches.map((b, j) => (j === i ? { ...b, ...patch } : b)) })
      return (
        <div className="flex flex-col gap-2">
          <input
            className={INPUT}
            value={block.title}
            disabled={disabled}
            placeholder="What is being decided, e.g. 'Was CloudTrail actually stopped?'"
            onChange={(e) => update({ title: e.target.value })}
          />
          <div className="border border-border-subtle rounded-btn overflow-hidden">
            <div className="grid grid-cols-[1fr_1fr_2rem] gap-px bg-border-subtle">
              <div className="bg-surface-deep px-3 py-1.5 font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim">
                If
              </div>
              <div className="bg-surface-deep px-3 py-1.5 font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim">
                Then
              </div>
              <div className="bg-surface-deep" />
              {branches.map((b, i) => (
                <BranchRow
                  key={i}
                  branch={b}
                  disabled={disabled}
                  onChange={(patch) => setBranch(i, patch)}
                  onRemove={
                    branches.length > 1
                      ? () => update({ branches: branches.filter((_, j) => j !== i) })
                      : undefined
                  }
                />
              ))}
            </div>
          </div>
          <button
            type="button"
            disabled={disabled}
            onClick={() => update({ branches: [...branches, { condition: '', action: '' }] })}
            className="self-start font-mono text-[0.7rem] text-accent-blue hover:underline disabled:opacity-40"
          >
            + condition
          </button>
        </div>
      )
    }

    case 'phase':
    case 'step':
      return (
        <div className="flex flex-col gap-2">
          <input
            className={INPUT}
            value={block.title}
            disabled={disabled}
            placeholder={block.type === 'phase' ? 'Containment' : 'Revoke the backdoor role'}
            onChange={(e) => update({ title: e.target.value })}
          />
          <RichTextEditor

            value={block.body}
            disabled={disabled}
            onChange={(markdown) => update({ body: markdown })}
            placeholder={
              block.type === 'phase'
                ? 'What this phase is for (optional)'
                : 'What to look for, what "good" looks like (optional)'
            }
          />
        </div>
      )

    case 'text':
    default:
      return (
        <div className="flex flex-col gap-2">
          <input
            className={INPUT}
            value={block.title}
            disabled={disabled}
            placeholder="Sub-heading (optional)"
            onChange={(e) => update({ title: e.target.value })}
          />
          <RichTextEditor

            value={block.body}
            disabled={disabled}
            onChange={(markdown) => update({ body: markdown })}
            placeholder="Context, detection triggers, prerequisites..."
          />
        </div>
      )
  }
}

function BranchRow({
  branch,
  onChange,
  onRemove,
  disabled,
}: {
  branch: { condition: string; action: string }
  onChange: (patch: Partial<{ condition: string; action: string }>) => void
  onRemove?: () => void
  disabled?: boolean
}) {
  const cell =
    'bg-surface-base px-3 py-2 text-[0.85rem] text-content-primary placeholder:text-content-muted ' +
    'focus:outline-none focus:bg-surface-elevated transition-colors'
  return (
    <>
      <input
        className={cell}
        value={branch.condition}
        disabled={disabled}
        placeholder="StopLogging in the last 24h"
        onChange={(e) => onChange({ condition: e.target.value })}
      />
      <input
        className={cell}
        value={branch.action}
        disabled={disabled}
        placeholder="Treat as confirmed; go to Containment"
        onChange={(e) => onChange({ action: e.target.value })}
      />
      <div className="bg-surface-base flex items-center justify-center">
        {onRemove && (
          <IconBtn onClick={onRemove} title="Remove condition" disabled={disabled} danger>
            &times;
          </IconBtn>
        )}
      </div>
    </>
  )
}

export function BlockEditor({ blocks, onChange, disabled, allowPhase = true }: BlockEditorProps) {
  // Derived numbering, so the author never types a number and reordering is free.
  const numbering = useMemo(() => {
    const out: Record<string, string> = {}
    let phase = 0
    let step = 0
    for (const b of blocks) {
      if (b.type === 'phase') {
        phase += 1
        step = 0
        out[b.id] = String(phase)
      } else if (b.type === 'step') {
        step += 1
        out[b.id] = `${phase || 1}.${step}`
      }
    }
    return out
  }, [blocks])

  const update = (id: string, patch: Partial<Block>) =>
    onChange(blocks.map((b) => (b.id === id ? { ...b, ...patch } : b)))

  const remove = (id: string) => onChange(blocks.filter((b) => b.id !== id))

  const move = (index: number, delta: number) => {
    const to = index + delta
    if (to < 0 || to >= blocks.length) return
    const next = [...blocks]
    const [moved] = next.splice(index, 1)
    next.splice(to, 0, moved as Block)
    onChange(next)
  }

  const insertAfter = (index: number, type: BlockType) => {
    const next = [...blocks]
    next.splice(index + 1, 0, emptyBlock(type))
    onChange(next)
  }

  return (
    <div className="flex flex-col gap-3">
      {blocks.length === 0 && (
        <div className="border border-dashed border-border-active rounded-card p-10 text-center">
          <div className="text-[0.95rem] text-content-secondary mb-1">
            An empty playbook.
          </div>
          <div className="text-[0.85rem] text-content-dim mb-5">
            Start with a phase &mdash; Preparation, Identification, Containment &mdash;
            then add the steps that belong to it.
          </div>
          <Palette onAdd={(t) => onChange([emptyBlock(t)])} disabled={disabled} allowPhase={allowPhase} />
        </div>
      )}

      {blocks.map((block, i) => (
        <div key={block.id}>
          <div
            className={[
              'border rounded-card bg-surface-card overflow-hidden',
              block.type === 'phase' ? 'border-accent-blue/30' : 'border-border-subtle',
            ].join(' ')}
          >
            <div className="flex items-center gap-2 px-3 py-2 border-b border-border-subtle bg-surface-deep">
              <span
                className={[
                  'font-mono text-[0.65rem] uppercase tracking-[1.5px] px-2 py-0.5 rounded-btn border',
                  TONE[block.type],
                ].join(' ')}
              >
                {BLOCK_LABELS[block.type]}
              </span>
              {numbering[block.id] && (
                <span className="font-mono text-[0.7rem] text-content-dim">
                  {numbering[block.id]}
                </span>
              )}
              <span className="text-[0.8rem] text-content-dim truncate">
                {block.title || BLOCK_HINTS[block.type]}
              </span>
              <div className="ml-auto flex items-center gap-0.5">
                <IconBtn onClick={() => move(i, -1)} title="Move up" disabled={disabled || i === 0}>
                  &uarr;
                </IconBtn>
                <IconBtn
                  onClick={() => move(i, 1)}
                  title="Move down"
                  disabled={disabled || i === blocks.length - 1}
                >
                  &darr;
                </IconBtn>
                <IconBtn onClick={() => remove(block.id)} title="Delete block" disabled={disabled} danger>
                  &times;
                </IconBtn>
              </div>
            </div>
            <div className="p-3">
              <BlockFields
                block={block}
                disabled={disabled}
                update={(patch) => update(block.id, patch)}
              />
            </div>
          </div>

          <div className="flex justify-center py-1.5">
            <Palette compact onAdd={(t) => insertAfter(i, t)} disabled={disabled} allowPhase={allowPhase} />
          </div>
        </div>
      ))}
    </div>
  )
}

/** The add-a-block control. Compact form sits between blocks. */
function Palette({
  onAdd,
  disabled,
  compact,
  allowPhase = true,
}: {
  onAdd: (type: BlockType) => void
  disabled?: boolean
  compact?: boolean
  allowPhase?: boolean
}) {
  const types: BlockType[] = allowPhase
    ? ['phase', 'step', 'command', 'decision', 'text']
    : ['step', 'command', 'decision', 'text']
  return (
    <div
      className={[
        'flex items-center gap-1 flex-wrap justify-center',
        compact ? 'opacity-40 hover:opacity-100 transition-opacity' : '',
      ].join(' ')}
    >
      {!compact && (
        <span className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim mr-1">
          Add
        </span>
      )}
      {types.map((t) => (
        <button
          key={t}
          type="button"
          disabled={disabled}
          onClick={() => onAdd(t)}
          title={BLOCK_HINTS[t]}
          className={[
            'font-mono text-[0.7rem] px-2 py-1 rounded-btn border border-border-subtle',
            'text-content-secondary hover:text-content-primary hover:border-border-active',
            'transition-colors disabled:opacity-40 disabled:cursor-not-allowed',
          ].join(' ')}
        >
          + {BLOCK_LABELS[t]}
        </button>
      ))}
    </div>
  )
}
