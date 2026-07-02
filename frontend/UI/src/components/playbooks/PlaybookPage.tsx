import { useState } from 'react'
import type { ReactNode } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useEmulations, usePlaybook } from '@/hooks/usePlatformData'
import { getPlatformMeta } from '@/data'
import type { PlatformId, Emulation } from '@/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { Markdown } from '@/components/common/Markdown'
import { PlaybookSection } from './PlaybookSection'

/**
 * Generic six-phase IR lifecycle shown for orientation on every playbook.
 * Each phase carries a semantic design-token tone (cool for observe, red for
 * act, green for restore) used only as a subtle tinted badge, not a fill.
 */
const IR_LIFECYCLE = [
  { n: 1, name: 'Detect', hint: 'Alert triggered', badge: 'bg-accent-blue-glow text-accent-blue' },
  { n: 2, name: 'Triage', hint: 'Validate & scope', badge: 'bg-warning-dim text-warning' },
  { n: 3, name: 'Investigate', hint: 'Collect evidence', badge: 'bg-accent-blue-glow text-accent-blue' },
  { n: 4, name: 'Contain', hint: 'Stop the threat', badge: 'bg-danger-dim text-danger' },
  { n: 5, name: 'Eradicate', hint: 'Remove access', badge: 'bg-danger-dim text-danger' },
  { n: 6, name: 'Recover', hint: 'Restore & harden', badge: 'bg-safe-dim text-safe' },
]

/**
 * Map a severity to a design-token text colour: CRITICAL/HIGH use the brand red
 * (danger), MEDIUM uses warning-yellow, anything lower stays muted.
 */
function severityClass(severity: string): string {
  const s = (severity ?? '').toUpperCase()
  if (s === 'CRITICAL' || s === 'HIGH') return 'text-danger'
  if (s === 'MEDIUM') return 'text-warning'
  return 'text-content-secondary'
}

/** Unique, order-preserving list of MITRE tactics referenced by the emulation. */
function tacticsOf(em: Emulation): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const m of em.mitreMappings ?? []) {
    const t = (m.tactic ?? '').trim()
    if (t && !seen.has(t)) {
      seen.add(t)
      out.push(t)
    }
  }
  return out
}

export function PlaybookPage() {
  const { platformId, emulationId } = useParams<{ platformId: string; emulationId: string }>()
  const pid = platformId as PlatformId
  const meta = getPlatformMeta(pid)
  const platformLabel = meta?.label ?? platformId?.toUpperCase() ?? ''

  const { data: emulations, loading: emLoading } = useEmulations(pid)
  const { data: playbook, loading: pbLoading } = usePlaybook(emulationId)
  const em = emulations?.find((e) => e.id === emulationId)

  const [activeTab, setActiveTab] = useState('overview')

  if (emLoading || pbLoading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading playbook...</div>
  }
  if (!em) {
    return (
      <EmptyState
        icon="&#128203;"
        title="Playbook not found"
        body={`No emulation with ID "${emulationId}" found.`}
      />
    )
  }

  // Tabs mirror whatever sections the playbook declares. A thin atomic yields a
  // few tabs, a rich composite yields the full NIST set — no fabricated content.
  // A playbook that declares its own "Overview" H2 gets it folded into the
  // synthetic Overview pane instead of a duplicate tab.
  const sections = playbook?.sections ?? []
  const overviewSection = sections.find((s) => s.id === 'overview')
  const tabSections = sections.filter((s) => s.id !== 'overview')
  const activeSection = tabSections.find((s) => s.id === activeTab)
  const showOverview = activeTab === 'overview' || !activeSection

  const tactics = tacticsOf(em)
  const killChain =
    tactics.length > 1 ? `${tactics[0]} → ${tactics[tactics.length - 1]}` : tactics[0] ?? '—'
  const category = em.tags?.[0] ?? tactics[0] ?? '—'
  const services = em.services ?? []

  const chip =
    'font-mono text-[11px] px-2 py-1 rounded-btn bg-surface-elevated border border-border text-content-secondary'
  const label = 'font-mono text-2xs uppercase tracking-label text-content-dim'

  return (
    <div>
      {/* Breadcrumb */}
      <div className="font-mono text-[11px] text-content-dim mb-4 flex items-center gap-2 flex-wrap">
        <Link to="/emulations" className="hover:text-content-secondary transition-colors">Emulations</Link>
        <span>/</span>
        <span>{platformLabel}</span>
        <span>/</span>
        <Link to={`/${pid}/emulations/${em.id}`} className="hover:text-content-secondary transition-colors">
          {em.id.toUpperCase()}
        </Link>
        <span>/</span>
        <span className="text-content-secondary">Playbook</span>
      </div>

      {/* Header */}
      <div className="mb-5">
        <h1 className="font-display text-[1.6rem] font-[800] text-content-primary leading-tight tracking-[-0.5px]">
          IR Playbook
        </h1>
        <div className="flex items-center gap-2 flex-wrap mt-2.5">
          <span className={label}>Scenario</span>
          <span className={`${chip} text-content-primary`}>{em.name}</span>
          <span className={`${label} ml-2`}>Emulation</span>
          <span className={chip}>{em.id}</span>
        </div>
      </div>

      {/* Meta strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 rounded-card overflow-hidden border border-border bg-border mb-6 gap-px">
        <MetaCell k="Techniques" v={String(em.techniqueCount)} sub="MITRE ATT&CK" />
        <MetaCell k="Kill Chain" v={killChain} sub={`${tactics.length} tactics`} />
        <MetaCell
          k="Severity"
          v={<span className={severityClass(em.severity)}>{em.severity}</span>}
        />
        <MetaCell k="Platform" v={platformLabel} sub={services.length ? `${services.length} services` : undefined} />
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
            <OverviewPane em={em} overviewMarkdown={overviewSection?.markdown} />
          ) : (
            <PlaybookSection key={activeSection!.id} emulationId={em.id} section={activeSection!} />
          )}
        </div>

        <aside className="flex flex-col gap-4">
          <div className="bg-surface-card border border-border rounded-card shadow-ring p-5">
            <div className="font-display text-sm font-semibold text-content-primary mb-3.5">Playbook Details</div>
            <DetailRow k="Category" v={category} />
            <DetailRow k="Severity" v={<span className={severityClass(em.severity)}>{em.severity}</span>} />
            <DetailRow k="Platform" v={platformLabel} />
            {services.length > 0 && (
              <DetailRow
                k="Data Sources"
                v={
                  <div className="flex gap-1.5 flex-wrap justify-end">
                    {services.slice(0, 4).map((s) => (
                      <span key={s} className={chip}>{s}</span>
                    ))}
                    {services.length > 4 && <span className={chip}>+{services.length - 4}</span>}
                  </div>
                }
              />
            )}
            <DetailRow k="Techniques" v={String(em.techniqueCount)} />
            {em.added && <DetailRow k="Added" v={em.added} />}
          </div>

          <div className="bg-surface-card border border-border rounded-card shadow-ring p-5">
            <div className="font-display text-sm font-semibold text-content-primary mb-3.5">Related</div>
            <RelatedLink to={`/${pid}/emulations/${em.id}`} label={`Emulation · ${em.id}`} />
            <RelatedLink to={`/${pid}/emulations/${em.id}/detections`} label="Detection rules" />
            <RelatedLink to={`/${pid}/guardrails`} label="Guardrails & scope" />
          </div>
        </aside>
      </div>
    </div>
  )
}

/** Overview tab: emulation summary, generic IR lifecycle, and the MITRE list. */
function OverviewPane({ em, overviewMarkdown }: { em: Emulation; overviewMarkdown?: string }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="bg-surface-card border border-border rounded-card shadow-ring p-6">
        <div className="font-display text-sm font-semibold text-content-primary mb-3">Playbook Overview</div>
        {em.description && (
          <p className="text-[0.95rem] leading-relaxed text-content-secondary font-medium mb-2">{em.description}</p>
        )}
        {em.attribution && <p className="text-[0.82rem] text-content-dim">{em.attribution}</p>}

        {/* Generic six-phase IR lifecycle (orientation chrome, same for all playbooks). */}
        <div className="flex items-stretch gap-2 mt-6 overflow-x-auto">
          {IR_LIFECYCLE.map((p, i) => (
            <div key={p.n} className="flex items-stretch gap-2 flex-1 min-w-[92px]">
              <div className="flex-1 flex flex-col items-center gap-2 text-center bg-surface-base border border-border rounded-[10px] px-2.5 py-4">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-mono text-[13px] font-semibold ${p.badge}`}>
                  {p.n}
                </div>
                <div className="text-[0.8rem] font-semibold text-content-primary mt-0.5">{p.name}</div>
                <div className="text-[10.5px] text-content-dim leading-tight">{p.hint}</div>
              </div>
              {i < IR_LIFECYCLE.length - 1 && (
                <span className="flex items-center text-content-dim shrink-0">{'→'}</span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* The playbook's own "Overview" section (if any) folds in here so it is not a duplicate tab. */}
      {overviewMarkdown && (
        <div className="bg-surface-card border border-border rounded-card shadow-ring p-6">
          <Markdown content={overviewMarkdown} />
        </div>
      )}

      {(em.mitreMappings?.length ?? 0) > 0 && (
        <div className="bg-surface-card border border-border rounded-card shadow-ring p-6">
          <div className="font-display text-sm font-semibold text-content-primary mb-3">
            MITRE Techniques ({em.mitreMappings.length})
          </div>
          {em.mitreMappings.map((m) => (
            <div
              key={m.id}
              className="flex items-center gap-3 py-2.5 border-b border-border last:border-b-0"
            >
              <span className="font-mono text-[12px] text-accent-blue shrink-0 w-[84px]">{m.id}</span>
              <span className="text-[13px] text-content-secondary">{m.name}</span>
              {m.tactic && <span className="ml-auto text-[11px] text-content-dim shrink-0">{m.tactic}</span>}
            </div>
          ))}
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
      <div className="text-[13px] font-medium text-content-primary text-right">{v}</div>
    </div>
  )
}

function RelatedLink({ to, label }: { to: string; label: string }) {
  return (
    <Link
      to={to}
      className="flex items-center justify-between px-3.5 py-2.5 mb-2 last:mb-0 rounded-[10px] border border-border
        text-[13px] text-content-secondary no-underline transition-all hover:border-border-active hover:opacity-60"
    >
      <span>{label}</span>
      <span className="text-content-dim">{'→'}</span>
    </Link>
  )
}
