/**
 * The block model behind the playbook editor.
 *
 * An IR playbook is authored as an ordered list of typed blocks - phases,
 * steps, prose, commands and decision points - rather than as one undivided
 * document. The author works with those blocks; Markdown is only ever the
 * serialisation.
 *
 * Serialisation deliberately targets the conventions the existing reader
 * already understands, because the reader is shared with the playbooks that
 * ship inside the emulation packages:
 *
 *   phase    ->  "## 3. Containment"        (parsePlaybookMarkdown section)
 *   step     ->  "#### Step 2 - Title"      (PlaybookSection checkable step)
 *   command  ->  fenced code block          (CommandBlock, copy/run affordance)
 *   decision ->  bolded prompt + a table    (renders as a table)
 *   text     ->  plain markdown
 *
 * That is what makes a playbook authored here render identically to a shipped
 * one, and what lets a forked PLAYBOOK.md come apart into blocks and go back
 * out byte-for-byte comparable.
 *
 * Phase and step numbers are derived at serialisation time from position, never
 * stored, so reordering blocks renumbers them automatically.
 */

export type BlockType = 'phase' | 'step' | 'text' | 'command' | 'decision'

/** One branch of a decision block: a condition and what to do about it. */
export interface DecisionBranch {
  /** The condition to evaluate, e.g. "StopLogging seen in the last 24h". */
  condition: string
  /** What to do when it holds. */
  action: string
}

export interface Block {
  /** Stable within an editing session; not persisted. */
  id: string
  type: BlockType
  /** Heading text for phase and step; the prompt for a decision. */
  title: string
  /** Prose for text, the step's body, or the code for a command. */
  body: string
  /** Fence language for a command block. */
  language?: string
  /** Branches for a decision block. */
  branches?: DecisionBranch[]
}

let seq = 0
/** Generate an id unique within this session. */
export function newBlockId(): string {
  seq += 1
  return `b${seq}-${Math.random().toString(36).slice(2, 8)}`
}

/** An empty block of the given type, ready to edit. */
export function emptyBlock(type: BlockType): Block {
  const base: Block = { id: newBlockId(), type, title: '', body: '' }
  if (type === 'command') return { ...base, language: 'bash' }
  if (type === 'decision') {
    return { ...base, branches: [{ condition: '', action: '' }] }
  }
  return base
}

/** Human label for a block type, used by the palette and the block header. */
export const BLOCK_LABELS: Record<BlockType, string> = {
  phase: 'Phase',
  step: 'Step',
  text: 'Notes',
  command: 'Command',
  decision: 'Decision',
}

export const BLOCK_HINTS: Record<BlockType, string> = {
  phase: 'A stage of the response. Becomes a tab in the reader.',
  step: 'A single action. Becomes a checkable item with progress.',
  text: 'Context, triggers, or anything that is not an action.',
  command: 'A shell or CLI command, shown with a copy button.',
  decision: 'A branch point: conditions and what each one means.',
}

// ---------------------------------------------------------------- serialise

function fence(code: string, language: string): string {
  // If the body itself contains a fence, widen ours so it still nests cleanly.
  const longest = (code.match(/`{3,}/g) ?? []).reduce((n, m) => Math.max(n, m.length), 0)
  const ticks = '`'.repeat(Math.max(3, longest + 1))
  return `${ticks}${language}\n${code.replace(/\s+$/, '')}\n${ticks}`
}

/** Serialise a decision block to a bolded prompt plus an If/Then table. */
function decisionToMarkdown(block: Block): string {
  const rows = (block.branches ?? []).filter((b) => b.condition.trim() || b.action.trim())
  const head = `**Decision - ${block.title.trim() || 'Untitled decision'}**`
  if (rows.length === 0) return head
  const escape = (s: string) => s.replace(/\|/g, '\\|').trim()
  const body = rows
    .map((r) => `| ${escape(r.condition)} | ${escape(r.action)} |`)
    .join('\n')
  return `${head}\n\n| If | Then |\n| --- | --- |\n${body}`
}

/**
 * Render blocks to a PLAYBOOK.md-shaped Markdown document.
 *
 * @param blocks - The ordered blocks.
 * @param title - Optional H1 for the document.
 */
export function blocksToMarkdown(blocks: Block[], title?: string): string {
  const out: string[] = []
  if (title?.trim()) out.push(`# ${title.trim()}`)

  let phaseNo = 0
  let stepNo = 0

  for (const block of blocks) {
    switch (block.type) {
      case 'phase': {
        phaseNo += 1
        stepNo = 0 // step numbering restarts inside each phase
        out.push(`## ${phaseNo}. ${block.title.trim() || 'Untitled phase'}`)
        if (block.body.trim()) out.push(block.body.trim())
        break
      }
      case 'step': {
        stepNo += 1
        out.push(`#### Step ${stepNo} - ${block.title.trim() || 'Untitled step'}`)
        if (block.body.trim()) out.push(block.body.trim())
        break
      }
      case 'command': {
        if (block.title.trim()) out.push(block.title.trim())
        if (block.body.trim()) out.push(fence(block.body, block.language || 'bash'))
        break
      }
      case 'decision':
        out.push(decisionToMarkdown(block))
        break
      case 'text':
      default:
        if (block.title.trim()) out.push(`### ${block.title.trim()}`)
        if (block.body.trim()) out.push(block.body.trim())
        break
    }
  }

  return out.join('\n\n').replace(/\n{3,}/g, '\n\n').trim() + '\n'
}

// ------------------------------------------------------------------- parse

/** Strip a leading "3. " ordinal from a phase heading. */
function stripOrdinal(s: string): string {
  return s.replace(/^\d+\.\s*/, '').trim()
}

/** Strip a leading "Step 2 - " / "Query 2 — " prefix from a step heading. */
function stripStepPrefix(s: string): string {
  return s.replace(/^(step|query)\s+\d+\s*[—:-]\s*/i, '').trim()
}

/** Parse an If/Then markdown table into decision branches. */
function parseBranches(lines: string[]): DecisionBranch[] {
  const branches: DecisionBranch[] = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed.startsWith('|')) continue
    // Skip the header row and the --- separator.
    if (/^\|\s*-{2,}/.test(trimmed) || /^\|\s*if\s*\|/i.test(trimmed)) continue
    const cells = trimmed.replace(/^\||\|$/g, '').split(/(?<!\\)\|/)
    if (cells.length < 2) continue
    branches.push({
      condition: (cells[0] ?? '').replace(/\\\|/g, '|').trim(),
      action: (cells[1] ?? '').replace(/\\\|/g, '|').trim(),
    })
  }
  return branches
}

/**
 * Parse a Markdown playbook back into blocks.
 *
 * Used when opening an existing playbook in the editor, including one just
 * forked from an emulation package. Anything the block model does not model
 * explicitly survives as a `text` block holding its original Markdown, so a
 * round trip never destroys content it did not understand.
 *
 * @param markdown - The document.
 * @returns The parsed blocks and the document's H1, if it declared one.
 */
export function markdownToBlocks(markdown: string): { blocks: Block[]; title?: string } {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n')
  const blocks: Block[] = []
  let title: string | undefined

  let buffer: string[] = []

  /** Flush accumulated prose into a text block. */
  const flush = () => {
    const body = buffer.join('\n').trim()
    buffer = []
    if (!body) return
    // Prose immediately after a phase/step heading belongs to that heading.
    const last = blocks[blocks.length - 1]
    if (last && (last.type === 'phase' || last.type === 'step') && !last.body) {
      last.body = body
      return
    }
    blocks.push({ ...emptyBlock('text'), body })
  }

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? ''

    // Fenced code -> command block
    const fenceOpen = line.match(/^(\s*)(`{3,})(\w*)\s*$/)
    if (fenceOpen) {
      const ticks = fenceOpen[2] as string
      const language = fenceOpen[3] || 'bash'
      const code: string[] = []
      i += 1
      while (i < lines.length && !new RegExp(`^\\s*${ticks}\\s*$`).test(lines[i] ?? '')) {
        code.push(lines[i] ?? '')
        i += 1
      }
      flush()
      blocks.push({ ...emptyBlock('command'), language, body: code.join('\n').trim() })
      continue
    }

    // Decision marker -> decision block (consume the table that follows)
    const decision = line.match(/^\*\*Decision\s*[-—]\s*(.+?)\*\*\s*$/)
    if (decision) {
      flush()
      const table: string[] = []
      let j = i + 1
      while (j < lines.length && !(lines[j] ?? '').trim()) j += 1
      while (j < lines.length && (lines[j] ?? '').trim().startsWith('|')) {
        table.push(lines[j] as string)
        j += 1
      }
      const branches = parseBranches(table)
      blocks.push({
        ...emptyBlock('decision'),
        title: (decision[1] as string).trim(),
        branches: branches.length ? branches : [{ condition: '', action: '' }],
      })
      i = j - 1
      continue
    }

    const h1 = line.match(/^#\s+(.+)$/)
    if (h1 && title === undefined && blocks.length === 0 && !buffer.join('').trim()) {
      title = (h1[1] as string).trim()
      continue
    }

    const h2 = line.match(/^##\s+(.+)$/)
    if (h2) {
      flush()
      blocks.push({ ...emptyBlock('phase'), title: stripOrdinal(h2[1] as string) })
      continue
    }

    const h4 = line.match(/^####\s+(.+)$/)
    if (h4) {
      flush()
      blocks.push({ ...emptyBlock('step'), title: stripStepPrefix(h4[1] as string) })
      continue
    }

    const h3 = line.match(/^###\s+(.+)$/)
    if (h3) {
      flush()
      blocks.push({ ...emptyBlock('text'), title: (h3[1] as string).trim() })
      continue
    }

    buffer.push(line)
  }

  flush()
  return { blocks, title }
}
