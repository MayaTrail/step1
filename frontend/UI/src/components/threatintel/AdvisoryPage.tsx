import { useState } from 'react'
import type { ReactNode } from 'react'
import { useParams } from 'react-router-dom'
import { useAdvisory } from '@/hooks/useThreatIntel'
import type { AdvisoryDetail } from '@/types'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { EmptyState } from '@/components/ui/EmptyState'
import { Markdown } from '@/components/common/Markdown'

/** Route back to the library, which lives behind a query param on the hub. */
const LIBRARY_PATH = '/threat-intel?view=advisory'

/**
 * Sections whose content is presented some other way, so they get no tab.
 *
 * "Intelligence Overview" is the orienting prose and belongs in the Overview
 * pane. "Overview" is the Field/Value table already parsed into the sidebar's
 * structured rows — as a tab it would repeat the sidebar in worse form.
 */
const FOLDED_SECTIONS = new Set(['intelligence overview', 'overview'])

/** Aliases listed in the sidebar before the rest collapse into a "+N" chip. */
const VISIBLE_ALIASES = 6

interface Section {
  id: string
  title: string
  markdown: string
}

/**
 * Split a dossier into its H2 sections, keeping the preamble.
 *
 * Deliberately not the playbook splitter in platform.service.ts: that one
 * discards everything before the first H2 and strips leading ordinals from
 * section titles. A dossier's preamble is its group ID and generation line,
 * which the Overview pane shows, and its headings carry no ordinals.
 *
 * @param content - The dossier markdown.
 * @returns The text before the first H2, and one entry per H2 with the
 *   markdown beneath it preserved verbatim.
 */
function splitSections(content: string): { preamble: string; sections: Section[] } {
  const parts = content.split(/^##\s+/m)
  const sections: Section[] = []

  for (const part of parts.slice(1)) {
    const nl = part.indexOf('\n')
    const title = (nl === -1 ? part : part.slice(0, nl)).trim()
    if (!title) continue
    sections.push({
      id: title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''),
      title,
      markdown: (nl === -1 ? '' : part.slice(nl + 1)).trim(),
    })
  }

  // The H1 is rendered as the page title, so drop it from the preamble rather
  // than showing the actor's name twice.
  const preamble = (parts[0] ?? '').replace(/^#\s+.*$/m, '').trim()
  return { preamble, sections }
}

/**
 * One APT dossier, rendered as a scoped reference page.
 *
 * Follows the IR playbook page: breadcrumb, title, a meta strip of the numbers
 * worth seeing at a glance, then the document's own H2 sections as tabs beside
 * a persistent detail sidebar. The dossier markdown is rendered through the
 * shared Markdown component, which has raw HTML disabled — the documents are
 * generated from third-party threat feeds, so their text is never trusted as
 * markup.
 */
export function AdvisoryPage() {
  const { advisoryId } = useParams<{ advisoryId: string }>()
  const { data: advisory, loading } = useAdvisory(advisoryId)
  const [activeTab, setActiveTab] = useState('overview')

  if (loading && !advisory) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading advisory...</div>
  }
  if (!advisory) {
    return (
      <EmptyState
        icon="&#9888;"
        title="Advisory not found"
        body={`No advisory with ID "${advisoryId}" is published.`}
      />
    )
  }

  const { preamble, sections } = splitSections(advisory.content)
  const intelligence = sections.find((s) => s.id === 'intelligence-overview')
  const tabSections = sections.filter((s) => !FOLDED_SECTIONS.has(s.title.toLowerCase()))
  const activeSection = tabSections.find((s) => s.id === activeTab)
  const showOverview = activeTab === 'overview' || !activeSection

  const chip =
    'font-mono text-[11px] px-2 py-1 rounded-btn bg-surface-elevated border border-border text-content-secondary'
  const label = 'font-mono text-2xs uppercase tracking-label text-content-dim'

  return (
    <div>
      <Breadcrumb
        items={[
          { label: 'Threat Intel', to: LIBRARY_PATH },
          { label: 'Advisory', to: LIBRARY_PATH },
          { label: advisory.reference },
        ]}
      />

      {/* Header */}
      <div className="mb-5">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          APT Dossier
        </div>
        <h1 className="font-display text-[1.6rem] font-[800] text-content-primary leading-tight tracking-[-0.5px]">
          {advisory.name}
        </h1>
        <div className="flex items-center gap-2 flex-wrap mt-2.5">
          <span className={label}>Reference</span>
          <span className={`${chip} text-content-primary`}>{advisory.reference}</span>
          {advisory.groupId && (
            <>
              <span className={`${label} ml-2`}>ATT&CK Group</span>
              <span className={chip}>{advisory.groupId}</span>
            </>
          )}
        </div>
      </div>

      {/* Meta strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 rounded-card overflow-hidden border border-border bg-border mb-6 gap-px">
        <MetaCell
          k="Techniques"
          v={String(advisory.techniqueCount)}
          sub={advisory.tactics.length ? `${advisory.tactics.length} tactics` : undefined}
        />
        <MetaCell k="Known Exploited CVEs" v={String(advisory.cveCount)} sub="CISA KEV" />
        <MetaCell k="Malware & Tools" v={String(advisory.malwareCount)} />
        <MetaCell
          k="Origin"
          v={advisory.origin || '—'}
          sub={advisory.firstSeen ? `first seen ${advisory.firstSeen}` : undefined}
        />
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border mb-5 overflow-x-auto">
        <TabButton label="Overview" active={showOverview} onClick={() => setActiveTab('overview')} />
        {tabSections.map((s) => (
          <TabButton
            key={s.id}
            label={s.title}
            active={activeTab === s.id}
            onClick={() => setActiveTab(s.id)}
          />
        ))}
      </div>

      {/* Content: main column + persistent sidebar */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-5 items-start">
        <div className="min-w-0">
          {showOverview ? (
            <OverviewPane advisory={advisory} preamble={preamble} intelligence={intelligence?.markdown} />
          ) : (
            <div key={activeSection!.id} className="bg-surface-card border border-border rounded-card shadow-ring p-6">
              <div className="font-display text-sm font-semibold text-content-primary mb-3">
                {activeSection!.title}
              </div>
              <Markdown content={activeSection!.markdown} />
            </div>
          )}
        </div>

        <aside className="flex flex-col gap-4">
          <div className="bg-surface-card border border-border rounded-card shadow-ring p-5">
            <div className="font-display text-sm font-semibold text-content-primary mb-3.5">Actor Details</div>
            <DetailRow k="Origin" v={advisory.origin || '—'} />
            {advisory.firstSeen && <DetailRow k="First Seen" v={advisory.firstSeen} />}
            {advisory.motivations.length > 0 && (
              <DetailRow
                k="Motivations"
                v={
                  <div className="flex gap-1.5 flex-wrap justify-end">
                    {advisory.motivations.map((m) => (
                      <span key={m} className={chip}>{m}</span>
                    ))}
                  </div>
                }
              />
            )}
            {advisory.groupId && <DetailRow k="ATT&CK Group" v={advisory.groupId} />}
            <DetailRow k="Techniques" v={String(advisory.techniqueCount)} />
            {advisory.sectors.length > 0 && (
              <DetailRow k="Targeted Sectors" v={String(advisory.sectors.length)} />
            )}
          </div>

          {advisory.aliases.length > 0 && (
            <div className="bg-surface-card border border-border rounded-card shadow-ring p-5">
              <div className="font-display text-sm font-semibold text-content-primary mb-3.5">
                Also Known As
              </div>
              <div className="flex gap-1.5 flex-wrap">
                {advisory.aliases.slice(0, VISIBLE_ALIASES).map((alias) => (
                  <span key={alias} className={chip}>{alias}</span>
                ))}
                {advisory.aliases.length > VISIBLE_ALIASES && (
                  <span
                    title={advisory.aliases.slice(VISIBLE_ALIASES).join(', ')}
                    className={chip}
                  >
                    +{advisory.aliases.length - VISIBLE_ALIASES}
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Provenance: a dossier is a merge of third-party catalogues, and a
              reader deciding how much weight to give it needs to know which
              ones, and how old the merge is. */}
          {(advisory.sources.length > 0 || advisory.generatedAt) && (
            <div className="bg-surface-card border border-border rounded-card shadow-ring p-5">
              <div className="font-display text-sm font-semibold text-content-primary mb-3.5">Provenance</div>
              {advisory.sources.length > 0 && (
                <DetailRow
                  k="Sources"
                  v={
                    <div className="flex gap-1.5 flex-wrap justify-end">
                      {advisory.sources.map((s) => (
                        <span key={s} className={chip}>{s}</span>
                      ))}
                    </div>
                  }
                />
              )}
              {advisory.generatedAt && <DetailRow k="Generated" v={advisory.generatedAt} />}
            </div>
          )}
        </aside>
      </div>
    </div>
  )
}

/**
 * Overview tab: the dossier's own preamble and Intelligence Overview prose,
 * plus the tactics it exercises.
 */
function OverviewPane({
  advisory,
  preamble,
  intelligence,
}: {
  advisory: AdvisoryDetail
  preamble: string
  intelligence?: string
}) {
  return (
    <div className="flex flex-col gap-4">
      <div className="bg-surface-card border border-border rounded-card shadow-ring p-6">
        <div className="font-display text-sm font-semibold text-content-primary mb-3">
          Intelligence Overview
        </div>
        {intelligence ? (
          <Markdown content={intelligence} />
        ) : (
          <p className="text-[0.85rem] text-content-dim">
            This dossier carries no intelligence overview — the sections below are what the
            upstream catalogues recorded for this actor.
          </p>
        )}
        {preamble && !intelligence && <Markdown content={preamble} />}
      </div>

      {advisory.tactics.length > 0 && (
        <div className="bg-surface-card border border-border rounded-card shadow-ring p-6">
          <div className="font-display text-sm font-semibold text-content-primary mb-3">
            MITRE Tactics ({advisory.tactics.length})
          </div>
          <div className="flex gap-1.5 flex-wrap">
            {advisory.tactics.map((tactic) => (
              <span
                key={tactic}
                className="font-mono text-[10px] text-accent-blue bg-accent-blue/[0.08] border border-accent-blue/20 rounded-md px-2 py-[3px]"
              >
                {tactic}
              </span>
            ))}
          </div>
        </div>
      )}

      {advisory.sectors.length > 0 && (
        <div className="bg-surface-card border border-border rounded-card shadow-ring p-6">
          <div className="font-display text-sm font-semibold text-content-primary mb-3">
            Targeted Sectors ({advisory.sectors.length})
          </div>
          <div className="flex gap-1.5 flex-wrap">
            {advisory.sectors.map((sector) => (
              <span
                key={sector}
                className="font-mono text-[11px] px-2 py-1 rounded-btn bg-surface-elevated border border-border text-content-secondary"
              >
                {sector}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function TabButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`px-[18px] py-2.5 text-xs font-semibold cursor-pointer border-b-2 -mb-px transition-all font-mono tracking-wider whitespace-nowrap
        ${active
          ? 'text-danger border-b-danger'
          : 'text-content-dim border-b-transparent hover:text-content-secondary'
        }`}
    >
      {label}
    </button>
  )
}

function MetaCell({ k, v, sub }: { k: string; v: ReactNode; sub?: string }) {
  return (
    <div className="bg-surface-card px-4 py-3.5">
      <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-1.5">{k}</div>
      <div className="text-sm font-semibold text-content-primary">{v}</div>
      {sub && <div className="text-[11px] text-content-dim mt-0.5">{sub}</div>}
    </div>
  )
}

function DetailRow({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-2.5 border-b border-border last:border-b-0">
      <div className="font-mono text-2xs uppercase tracking-label text-content-dim pt-0.5 shrink-0">{k}</div>
      <div className="text-[13px] font-medium text-content-primary text-right min-w-0 break-words">{v}</div>
    </div>
  )
}
