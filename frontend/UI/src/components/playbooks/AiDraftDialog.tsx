import { useEffect, useState } from 'react'

import { generatePlaybook } from '@/services/playbook.service'

/**
 * Draft a playbook with the user's AI connector.
 *
 * Collects a brief, optional reference links and optional pasted material,
 * and hands back a Markdown draft the editor loads as blocks.
 *
 * Two things this dialog is explicit about, because both change what a user
 * should expect:
 *
 *   1. Links are cited, not read. Nothing fetches them - a backend that
 *      retrieves user-supplied URLs is an SSRF primitive, and this one holds
 *      an EC2 role. Material the model must actually work from is pasted.
 *   2. The result is a draft. It replaces the editor's contents and is never
 *      saved or published on the user's behalf.
 */

interface AiDraftDialogProps {
  /** Whether the editor already has content that would be replaced. */
  hasContent: boolean
  onClose: () => void
  /** Called with the generated Markdown and the reviewer notes. */
  onDraft: (markdown: string, notes: string[]) => void
}

const INPUT =
  'w-full bg-surface-base border border-border-subtle rounded-btn px-3 py-2 text-[0.875rem] ' +
  'text-content-primary placeholder:text-content-muted focus:outline-none focus:border-accent-blue transition-colors'

export function AiDraftDialog({ hasContent, onClose, onDraft }: AiDraftDialogProps) {
  const [brief, setBrief] = useState('')
  const [urls, setUrls] = useState('')
  const [referenceText, setReferenceText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose, busy])

  async function run() {
    setBusy(true)
    setError(null)
    try {
      const parsedUrls = urls
        .split(/[\s,]+/)
        .map((u) => u.trim())
        .filter(Boolean)

      const draft = await generatePlaybook({
        brief: brief.trim(),
        ...(parsedUrls.length ? { reference_urls: parsedUrls } : {}),
        ...(referenceText.trim() ? { reference_text: referenceText.trim() } : {}),
      })
      onDraft(draft.body, draft.notes ?? [])
    } catch (err) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(detail || (err instanceof Error ? err.message : 'Generation failed.'))
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <button
        type="button"
        aria-label="Close"
        onClick={() => !busy && onClose()}
        className="absolute inset-0 bg-black/50"
      />

      <div
        role="dialog"
        aria-label="Draft with AI"
        className="relative w-full max-w-[40rem] max-h-full overflow-y-auto bg-surface-base border border-border rounded-card shadow-float"
      >
        <div className="flex items-center gap-3 px-5 py-4 border-b border-border bg-surface-deep">
          <div>
            <div className="font-display text-[1.05rem] font-semibold text-content-primary">
              Draft with AI
            </div>
            <div className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim mt-0.5">
              Produces a draft for you to review
            </div>
          </div>
          <button
            type="button"
            onClick={() => !busy && onClose()}
            aria-label="Close"
            disabled={busy}
            className="ml-auto w-8 h-8 flex items-center justify-center rounded-btn text-content-dim hover:text-content-primary hover:bg-surface-elevated transition-colors disabled:opacity-40"
          >
            &times;
          </button>
        </div>

        <div className="px-5 py-5 flex flex-col gap-4">
          {error && (
            <div
              role="alert"
              className="border border-danger/40 bg-danger/10 text-danger rounded-btn px-3 py-2 text-[0.85rem]"
            >
              {error}
            </div>
          )}

          {hasContent && (
            <div className="border border-warning/40 bg-warning/10 text-warning rounded-btn px-3 py-2 text-[0.85rem]">
              This replaces everything currently in the editor. Nothing is saved
              until you save it, so closing without saving leaves the stored
              playbook untouched.
            </div>
          )}

          <label className="flex flex-col gap-1">
            <span className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim">
              What should this playbook cover?
            </span>
            <textarea
              className={`${INPUT} resize-y min-h-[6rem] leading-relaxed`}
              value={brief}
              disabled={busy}
              autoFocus
              placeholder="An attacker used a leaked long-term access key to create a backdoor IAM user and an admin role, then disabled CloudTrail in two regions. We run everything in one AWS account with GuardDuty on and Security Hub off."
              onChange={(e) => setBrief(e.target.value)}
            />
            <span className="text-[0.75rem] text-content-dim">
              The more you say about your environment, the less generic the
              result. {brief.trim().length < 20 && 'At least a sentence.'}
            </span>
          </label>

          <label className="flex flex-col gap-1">
            <span className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim">
              Reference links <span className="normal-case tracking-normal">(optional)</span>
            </span>
            <textarea
              className={`${INPUT} resize-y min-h-[3.5rem] font-mono text-[0.8rem]`}
              value={urls}
              disabled={busy}
              placeholder="https://unit42.paloaltonetworks.com/...&#10;https://aws.amazon.com/security/security-bulletins/..."
              onChange={(e) => setUrls(e.target.value)}
            />
            <span className="text-[0.75rem] text-content-dim">
              These are passed to the model as citations &mdash;{' '}
              <b className="text-content-secondary">nothing fetches them</b>. A
              server that retrieves links you hand it can be pointed at its own
              internal endpoints, so we do not. If the model needs to read
              something, paste it below.
            </span>
          </label>

          <label className="flex flex-col gap-1">
            <span className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim">
              Reference material <span className="normal-case tracking-normal">(optional)</span>
            </span>
            <textarea
              className={`${INPUT} resize-y min-h-[5rem]`}
              value={referenceText}
              disabled={busy}
              placeholder="Paste the advisory, the incident write-up, or your existing runbook..."
              onChange={(e) => setReferenceText(e.target.value)}
            />
            <span className="text-[0.75rem] text-content-dim">
              This is the part the model actually works from.
            </span>
          </label>

          <div className="border-t border-border-subtle pt-4 text-[0.8rem] text-content-dim leading-relaxed">
            A generated playbook is a starting point, not an answer. Commands
            and log-source names are the parts models get wrong most often, and
            these get executed during an incident &mdash; check every one before
            anyone follows this.
          </div>
        </div>

        <div className="flex items-center gap-2 px-5 py-4 border-t border-border bg-surface-deep">
          <button
            type="button"
            onClick={() => !busy && onClose()}
            disabled={busy}
            className="border border-border-subtle text-content-secondary hover:text-content-primary rounded-btn px-3 py-2 text-[0.85rem] transition-colors disabled:opacity-40"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => void run()}
            disabled={busy || brief.trim().length < 20}
            className="ml-auto bg-accent-blue text-button-fg rounded-btn px-4 py-2 text-[0.85rem] font-medium disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {busy ? 'Drafting...' : 'Draft playbook'}
          </button>
        </div>
      </div>
    </div>
  )
}
