import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'

import { AiDraftDialog } from './AiDraftDialog'
import { PhaseTabs } from './PhaseTabs'
import { PlaybookGuide, GUIDE_PANEL_WIDTH_PX } from './PlaybookGuide'
import {
  type Block,
  blocksToMarkdown,
  emptyBlock,
  markdownToBlocks,
} from './playbookBlocks'
import {
  createPlaybook,
  forkPlaybook,
  getPlaybook,
  updatePlaybook,
} from '@/services/playbook.service'
import type { UserPlaybook, UserPlaybookStatus, UserPlaybookVisibility } from '@/types'

/**
 * Author or edit an incident-response playbook.
 *
 * Entry points:
 *   /playbooks/new                  a blank playbook
 *   /playbooks/new?fork=ambersquid  a copy of that emulation's shipped PLAYBOOK.md
 *   /playbooks/:id/edit             an existing one
 *
 * The document is edited as blocks and serialised to Markdown on save, so what
 * the author arranges here is exactly what the reader renders. Saving is
 * explicit: an IR playbook is followed during an incident, so a stray keystroke
 * should not silently become the live version.
 */

/** A blank playbook starts with the phases a responder expects to find. */
function starterBlocks(): Block[] {
  return [
    {
      ...emptyBlock('phase'),
      title: 'Preparation',
      body: 'What has to be true before this incident happens.',
    },
    {
      ...emptyBlock('phase'),
      title: 'Identification',
      body: 'How the team recognises it.',
    },
    { ...emptyBlock('step'), title: 'Confirm the alert is not a false positive' },
    { ...emptyBlock('phase'), title: 'Containment' },
    { ...emptyBlock('phase'), title: 'Eradication' },
    { ...emptyBlock('phase'), title: 'Recovery' },
  ]
}

const INPUT =
  'w-full bg-surface-base border border-border-subtle rounded-btn px-3 py-2 text-[0.875rem] ' +
  'text-content-primary placeholder:text-content-muted focus:outline-none focus:border-accent-blue transition-colors'

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim">
        {label}
      </span>
      {children}
    </label>
  )
}

export function PlaybookEditorPage() {
  const { playbookId } = useParams<{ playbookId: string }>()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()

  const forkSource = searchParams.get('fork')

  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState<null | UserPlaybookStatus>(null)
  const [error, setError] = useState<string | null>(null)
  const [playbook, setPlaybook] = useState<UserPlaybook | null>(null)

  const [title, setTitle] = useState('')
  const [summary, setSummary] = useState('')
  const [blocks, setBlocks] = useState<Block[]>([])
  const [status, setStatus] = useState<UserPlaybookStatus>('draft')
  const [visibility, setVisibility] = useState<UserPlaybookVisibility>('private')

  const [showGuide, setShowGuide] = useState(false)
  const [showAi, setShowAi] = useState(false)
  // Reviewer notes attached to the last AI draft. Cleared once the author
  // saves, because by then they have accepted the content as their own.
  const [aiNotes, setAiNotes] = useState<string[]>([])

  // What the server currently holds, so "unsaved" is a comparison rather than a
  // flag someone forgets to clear.
  const saved = useRef({ title: '', summary: '', body: '', visibility: '' })
  const body = blocksToMarkdown(blocks, title)
  const dirty =
    title !== saved.current.title ||
    summary !== saved.current.summary ||
    body !== saved.current.body ||
    visibility !== saved.current.visibility

  const adopt = useCallback((pb: UserPlaybook) => {
    setPlaybook(pb)
    setTitle(pb.title)
    setSummary(pb.summary)
    setStatus(pb.status)
    setVisibility(pb.visibility)
    const parsed = markdownToBlocks(pb.body)
    setBlocks(parsed.blocks)
    saved.current = {
      title: pb.title,
      summary: pb.summary,
      body: blocksToMarkdown(parsed.blocks, pb.title),
      visibility: pb.visibility,
    }
  }, [])

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError(null)
      try {
        if (playbookId) {
          const pb = await getPlaybook(playbookId)
          if (!cancelled) adopt(pb)
        } else if (forkSource) {
          // The fork is created server-side (it reads the shipped file), then we
          // move onto its own URL so a refresh cannot fork a second copy.
          const pb = await forkPlaybook(forkSource)
          if (!cancelled) {
            adopt(pb)
            navigate(`/playbooks/${pb.id}/edit`, { replace: true })
          }
        } else if (!cancelled) {
          const initial = starterBlocks()
          setBlocks(initial)
          saved.current = {
            title: '',
            summary: '',
            body: blocksToMarkdown(initial, ''),
            visibility: 'private',
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Could not load this playbook.')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void load()
    return () => {
      cancelled = true
    }
  }, [playbookId, forkSource, adopt, navigate])

  useEffect(() => {
    if (!dirty) return
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', onBeforeUnload)
    return () => window.removeEventListener('beforeunload', onBeforeUnload)
  }, [dirty])

  /**
   * Leave the editor, confirming first if there is unsaved work.
   *
   * The beforeunload handler above only covers closing the tab; an in-app
   * navigation never reaches it, so without this a back click silently drops
   * everything typed since the last save.
   */
  function leave(to: string) {
    if (dirty && !window.confirm('You have unsaved changes. Leave without saving?')) {
      return
    }
    navigate(to)
  }

  async function save(nextStatus: UserPlaybookStatus, thenView = false) {
    if (!title.trim()) {
      setError('Give the playbook a title before saving.')
      return
    }
    setSaving(nextStatus)
    setError(null)
    try {
      const draft = {
        title: title.trim(),
        summary,
        body,
        status: nextStatus,
        visibility,
      }
      const pb = playbook
        ? await updatePlaybook(playbook.id, draft)
        : await createPlaybook(draft)
      adopt(pb)
      setAiNotes([])
      if (thenView) navigate(`/playbooks/${pb.id}`)
      else if (!playbook) navigate(`/playbooks/${pb.id}/edit`, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed.')
    } finally {
      setSaving(null)
    }
  }

  if (loading) {
    return (
      <div className="py-16 text-center font-mono text-sm text-content-dim">
        {forkSource ? 'Forking playbook...' : 'Loading playbook...'}
      </div>
    )
  }

  const phases = blocks.filter((b) => b.type === 'phase').length
  const steps = blocks.filter((b) => b.type === 'step').length

  return (
    <div
      style={{ marginRight: showGuide ? GUIDE_PANEL_WIDTH_PX : 0 }}
      className="max-w-[72rem] transition-[margin] duration-300 ease-out"
    >
      {/* Sticky action bar - save stays reachable however far down you are. */}
      <div className="sticky top-0 z-20 -mx-1 px-1 py-3 bg-surface-deep/95 backdrop-blur border-b border-border mb-5">
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => leave(playbook ? `/playbooks/${playbook.id}` : '/playbooks')}
            title={playbook ? 'Back to this playbook' : 'Back to playbooks'}
            aria-label={playbook ? 'Back to this playbook' : 'Back to playbooks'}
            className="w-9 h-9 shrink-0 flex items-center justify-center rounded-btn border border-border-subtle text-content-secondary hover:text-content-primary hover:border-border-active transition-colors"
          >
            &larr;
          </button>

          <div className="min-w-0">
            <div className="font-mono text-[0.65rem] text-content-dim mb-0.5 flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => leave('/playbooks')}
                className="hover:text-content-secondary transition-colors"
              >
                Playbooks
              </button>
              <span aria-hidden="true">/</span>
              <span>{playbook ? 'Edit' : 'New'}</span>
            </div>
            <div className="font-display text-[1.15rem] font-semibold text-content-primary leading-tight truncate">
              {title || (playbook ? 'Untitled playbook' : 'New playbook')}
            </div>
            <div className="font-mono text-[0.68rem] text-content-dim mt-0.5">
              {phases} phase{phases === 1 ? '' : 's'} &middot; {steps} step
              {steps === 1 ? '' : 's'} &middot;{' '}
              {dirty ? (
                <span className="text-warning">unsaved changes</span>
              ) : (
                <span>all changes saved</span>
              )}
            </div>
          </div>

          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowGuide(true)}
              title="What each block becomes for a reader"
              className="border border-border-subtle text-content-secondary hover:text-content-primary rounded-btn px-3 py-2 text-[0.85rem] transition-colors"
            >
              Guide
            </button>
            <button
              type="button"
              onClick={() => setShowAi(true)}
              title="Describe the incident and let AI draft the structure"
              className="border border-accent-blue/40 text-accent-blue hover:bg-accent-blue/10 rounded-btn px-3 py-2 text-[0.85rem] transition-colors"
            >
              Draft with AI
            </button>
            {playbook && (
              <button
                type="button"
                onClick={() => leave(`/playbooks/${playbook.id}`)}
                className="border border-border-subtle text-content-secondary hover:text-content-primary rounded-btn px-3 py-2 text-[0.85rem] transition-colors"
              >
                Preview
              </button>
            )}
            <button
              type="button"
              onClick={() => void save('draft')}
              disabled={saving !== null || (!dirty && status === 'draft')}
              className="border border-border-subtle text-content-secondary hover:text-content-primary rounded-btn px-3 py-2 text-[0.85rem] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {saving === 'draft' ? 'Saving...' : 'Save as draft'}
            </button>
            <button
              type="button"
              onClick={() => void save('published', true)}
              disabled={saving !== null}
              className="bg-accent-blue text-button-fg rounded-btn px-4 py-2 text-[0.85rem] font-medium disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {saving === 'published'
                ? 'Publishing...'
                : status === 'published'
                  ? 'Save & view'
                  : 'Publish'}
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="mb-4 border border-danger/40 bg-danger/10 text-danger rounded-btn px-3 py-2 text-[0.85rem]"
        >
          {error}
        </div>
      )}

      {aiNotes.length > 0 && (
        <div className="mb-4 border border-warning/40 bg-warning/10 rounded-card px-4 py-3">
          <div className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-warning mb-2">
            AI draft &mdash; review before anyone follows this
          </div>
          <ul className="text-[0.85rem] text-content-secondary leading-relaxed list-disc pl-4 flex flex-col gap-1">
            {aiNotes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="grid gap-4 mb-5 md:grid-cols-[2fr_1fr]">
        <Field label="Title">
          <input
            className={INPUT}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="AMBERSQUID - our response"
          />
        </Field>
        <Field label="Visible to">
          <select
            className={INPUT}
            value={visibility}
            onChange={(e) => setVisibility(e.target.value as UserPlaybookVisibility)}
          >
            <option value="private">Only me</option>
            <option value="organization">My organisation</option>
          </select>
        </Field>
        <div className="md:col-span-2">
          <Field label="Summary">
            <input
              className={INPUT}
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              placeholder="One line, shown on the playbook card."
              maxLength={400}
            />
          </Field>
        </div>
      </div>

      <PhaseTabs blocks={blocks} onChange={setBlocks} disabled={saving !== null} />

      {showGuide && <PlaybookGuide onClose={() => setShowGuide(false)} />}

      {showAi && (
        <AiDraftDialog
          hasContent={blocks.length > 0}
          onClose={() => setShowAi(false)}
          onDraft={(markdown, notes) => {
            const parsed = markdownToBlocks(markdown)
            setBlocks(parsed.blocks)
            if (parsed.title && !title.trim()) setTitle(parsed.title)
            setAiNotes(notes)
            setShowAi(false)
          }}
        />
      )}
    </div>
  )
}
