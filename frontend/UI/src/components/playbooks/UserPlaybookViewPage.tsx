import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { PlaybookSection } from './PlaybookSection'
import { Markdown } from '@/components/common/Markdown'
import { EmptyState } from '@/components/ui/EmptyState'
import { parsePlaybookMarkdown } from '@/services/platform.service'
import {
  deletePlaybook,
  downloadPlaybook,
  getPlaybook,
} from '@/services/playbook.service'
import type { UserPlaybook } from '@/types'

/**
 * Read a user-authored playbook.
 *
 * Deliberately renders through the same parser and the same PlaybookSection
 * component as the playbooks that ship inside the emulation packages, so an
 * authored playbook is not a second-class citizen: phases become tabs, steps
 * become checkable items with progress, and commands get the copy affordance.
 * That is only possible because the stored format is the same Markdown the
 * shipped ones use.
 *
 * The emulation-specific chrome (MITRE counts, kill chain, services) has no
 * analogue here, so the sidebar carries the playbook's own provenance instead.
 */

function TabButton({
  label,
  active,
  onClick,
}: {
  label: string
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        'px-4 py-2.5 text-[0.85rem] whitespace-nowrap border-b-2 transition-colors',
        active
          ? 'border-accent-blue text-content-primary'
          : 'border-transparent text-content-secondary hover:text-content-primary',
      ].join(' ')}
    >
      {label}
    </button>
  )
}

function DetailRow({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-2 border-b border-border-subtle last:border-b-0">
      <span className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim shrink-0">
        {k}
      </span>
      <span className="text-[0.85rem] text-content-secondary text-right">{v}</span>
    </div>
  )
}

export function UserPlaybookViewPage() {
  const { playbookId } = useParams<{ playbookId: string }>()
  const navigate = useNavigate()

  const [playbook, setPlaybook] = useState<UserPlaybook | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<string>('')

  useEffect(() => {
    let cancelled = false
    if (!playbookId) return
    setLoading(true)
    getPlaybook(playbookId)
      .then((pb) => {
        if (!cancelled) setPlaybook(pb)
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Could not load this playbook.')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [playbookId])

  const parsed = useMemo(
    () => (playbook ? parsePlaybookMarkdown(playbook.body) : null),
    [playbook],
  )
  const sections = parsed?.sections ?? []

  // Default to the first section once the document is known.
  useEffect(() => {
    if (!activeTab && sections.length > 0) setActiveTab(sections[0]!.id)
  }, [activeTab, sections])

  if (loading) {
    return (
      <div className="py-16 text-center font-mono text-sm text-content-dim">
        Loading playbook...
      </div>
    )
  }
  if (error || !playbook) {
    return (
      <EmptyState
        icon="&#128203;"
        title="Playbook not found"
        body={error ?? 'This playbook does not exist, or you do not have access to it.'}
      />
    )
  }

  const active = sections.find((s) => s.id === activeTab) ?? sections[0]
  const chip =
    'font-mono text-[11px] px-2 py-1 rounded-btn bg-surface-elevated border border-border text-content-secondary'

  async function handleDelete() {
    if (!playbook) return
    if (!window.confirm(`Delete "${playbook.title}"? This cannot be undone.`)) return
    await deletePlaybook(playbook.id)
    navigate('/playbooks')
  }

  return (
    <div>
      {/* Back control + breadcrumb, matching the editor so the two pages
          behave the same way round. */}
      <div className="flex items-center gap-3 mb-4">
        <Link
          to="/playbooks"
          title="Back to playbooks"
          aria-label="Back to playbooks"
          className="w-9 h-9 shrink-0 flex items-center justify-center rounded-btn border border-border-subtle text-content-secondary hover:text-content-primary hover:border-border-active transition-colors"
        >
          &larr;
        </Link>
        <div className="font-mono text-[11px] text-content-dim flex items-center gap-2 flex-wrap min-w-0">
          <Link to="/playbooks" className="hover:text-content-secondary transition-colors">
            Playbooks
          </Link>
          <span aria-hidden="true">/</span>
          <span className="text-content-secondary truncate">{playbook.title}</span>
        </div>
      </div>

      {/* Header + actions */}
      <div className="flex flex-wrap items-start justify-between gap-4 mb-5">
        <div className="min-w-0">
          <h1 className="font-display text-[1.6rem] font-[800] text-content-primary leading-tight tracking-[-0.5px]">
            {parsed?.title || playbook.title}
          </h1>
          <div className="flex items-center gap-2 flex-wrap mt-2.5">
            <span
              className={
                playbook.status === 'published'
                  ? 'font-mono text-[11px] px-2 py-1 rounded-btn bg-accent-blue/15 text-accent-blue border border-accent-blue/40'
                  : `${chip} text-content-dim`
              }
            >
              {playbook.status}
            </span>
            {playbook.is_fork && (
              <span className={chip}>forked from {playbook.source_emulation}</span>
            )}
            {playbook.is_example && (
              <span className={chip} title="A starter example - safe to edit or delete.">
                example
              </span>
            )}
            <span className={chip}>
              {playbook.visibility === 'organization' ? 'shared' : 'private'}
            </span>
          </div>
          {playbook.summary && (
            <p className="text-[0.9rem] text-content-secondary mt-2.5 max-w-[46rem]">
              {playbook.summary}
            </p>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Link
            to={`/playbooks/${playbook.id}/edit`}
            className="bg-accent-blue text-button-fg rounded-btn px-4 py-2 text-[0.85rem] font-medium"
          >
            Edit
          </Link>
          <button
            type="button"
            onClick={() => void downloadPlaybook(playbook.id, playbook.slug)}
            className="border border-border-subtle text-content-secondary hover:text-content-primary rounded-btn px-3 py-2 text-[0.85rem] transition-colors"
          >
            Download
          </button>
        </div>
      </div>

      {sections.length === 0 ? (
        <div className="bg-surface-card border border-border rounded-card shadow-ring p-6">
          {playbook.body.trim() ? (
            <Markdown content={playbook.body} />
          ) : (
            <div className="text-content-dim text-[0.9rem]">
              This playbook has no content yet.{' '}
              <Link to={`/playbooks/${playbook.id}/edit`} className="text-accent-blue hover:underline">
                Add its first phase.
              </Link>
            </div>
          )}
        </div>
      ) : (
        <>
          {/* Phase tabs — the same shape the shipped playbooks use. */}
          <div className="flex border-b border-border mb-5 overflow-x-auto">
            {sections.map((s) => (
              <TabButton
                key={s.id}
                label={s.title}
                active={active?.id === s.id}
                onClick={() => setActiveTab(s.id)}
              />
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-5 items-start">
            <div className="min-w-0">
              {active && (
                <PlaybookSection
                  key={active.id}
                  emulationId={`user:${playbook.id}`}
                  section={active}
                />
              )}
            </div>

            <aside className="flex flex-col gap-4">
              <div className="bg-surface-card border border-border rounded-card shadow-ring p-5">
                <div className="font-display text-sm font-semibold text-content-primary mb-3.5">
                  Playbook Details
                </div>
                <DetailRow k="Phases" v={String(sections.length)} />
                <DetailRow k="Status" v={playbook.status} />
                <DetailRow
                  k="Visible to"
                  v={playbook.visibility === 'organization' ? 'Organisation' : 'Only me'}
                />
                <DetailRow k="Author" v={playbook.owner_username} />
                {playbook.is_fork && <DetailRow k="Forked from" v={playbook.source_emulation} />}
                <DetailRow
                  k="Updated"
                  v={new Date(playbook.updated_at).toLocaleDateString()}
                />
              </div>

              <div className="bg-surface-card border border-border rounded-card shadow-ring p-5">
                <div className="font-display text-sm font-semibold text-content-primary mb-2">
                  Phases
                </div>
                <div className="flex flex-col">
                  {sections.map((s, i) => (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => setActiveTab(s.id)}
                      className={[
                        'text-left py-1.5 text-[0.85rem] transition-colors',
                        active?.id === s.id
                          ? 'text-accent-blue'
                          : 'text-content-secondary hover:text-content-primary',
                      ].join(' ')}
                    >
                      <span className="font-mono text-[0.7rem] text-content-dim mr-2">
                        {String(i + 1).padStart(2, '0')}
                      </span>
                      {s.title}
                    </button>
                  ))}
                </div>
              </div>

              <button
                type="button"
                onClick={handleDelete}
                className="self-start text-danger hover:underline text-[0.85rem]"
              >
                Delete playbook
              </button>
            </aside>
          </div>
        </>
      )}
    </div>
  )
}
