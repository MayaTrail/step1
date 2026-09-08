import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useLibraryPlaybook } from '@/hooks/usePlatformData'
import { parsePlaybookMarkdown } from '@/services/platform.service'
import { EmptyState } from '@/components/ui/EmptyState'
import { Markdown } from '@/components/common/Markdown'
import { PlaybookSection } from './PlaybookSection'
import {
  DetailRow,
  IR_LIFECYCLE,
  MetaCell,
  RelatedLink,
  TabButton,
  severityClass,
} from './PlaybookPage'

/**
 * One standalone IR playbook from the reference library.
 *
 * Laid out to match PlaybookPage so a reader moving between an emulation
 * playbook and a reference one is not relearning the page: same breadcrumb,
 * meta strip, section tabs, and sidebar. The differences are only where the two
 * genuinely differ — there is no emulation to link back to, and the detection
 * rules here are unvalidated, which the Overview states plainly rather than
 * leaving the reader to assume parity with a shipped detection.
 */
export function LibraryPlaybookPage() {
  const { playbookId } = useParams<{ playbookId: string }>()
  const { data, loading, error } = useLibraryPlaybook(playbookId)
  const [activeTab, setActiveTab] = useState('overview')

  if (loading) {
    return (
      <div className="py-16 text-center font-mono text-sm text-content-dim">Loading playbook...</div>
    )
  }

  if (error || !data) {
    return (
      <EmptyState
        icon="&#128203;"
        title="Playbook not found"
        body={`No reference playbook matches "${playbookId ?? ''}".`}
      />
    )
  }

  // Same section split the emulation playbooks use, so the six NIST phases
  // become tabs here too rather than one long scroll.
  const parsed = parsePlaybookMarkdown(data.markdown ?? '')
  const sections = parsed.sections
  const overviewSection = sections.find((s) => s.id === 'overview')
  const tabSections = sections.filter((s) => s.id !== 'overview')
  const activeSection = tabSections.find((s) => s.id === activeTab)
  const showOverview = activeTab === 'overview' || !activeSection

  const title = data.title.replace(/^IR Playbook:\s*/i, '')
  const chip =
    'font-mono text-[11px] px-2 py-1 rounded-btn bg-surface-elevated border border-border text-content-secondary'
  const label = 'font-mono text-2xs uppercase tracking-label text-content-dim'

  return (
    <div>
      {/* Breadcrumb */}
      <div className="font-mono text-[11px] text-content-dim mb-4 flex items-center gap-2 flex-wrap">
        <Link to="/playbooks" className="hover:text-content-secondary transition-colors">
          Playbooks
        </Link>
        <span>/</span>
        <span>Reference Library</span>
        <span>/</span>
        <span className="text-content-secondary">{data.service.toUpperCase()}</span>
      </div>

      {/* Header */}
      <div className="mb-5">
        <h1 className="font-display text-[1.6rem] font-[800] text-content-primary leading-tight tracking-[-0.5px]">
          IR Playbook
        </h1>
        <div className="flex items-center gap-2 flex-wrap mt-2.5">
          <span className={label}>Use Case</span>
          <span className={`${chip} text-content-primary`}>{title}</span>
          <span className={`${label} ml-2`}>Reference</span>
          <span className={chip}>{data.id}</span>
        </div>
      </div>

      {/* Meta strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 rounded-card overflow-hidden border border-border bg-border mb-6 gap-px">
        <MetaCell
          k="Techniques"
          v={String(data.techniques.length)}
          sub={data.techniques.join(', ') || undefined}
        />
        <MetaCell k="Tactic" v={data.tactic || '—'} sub={data.tactics[0]} />
        <MetaCell
          k="Severity"
          v={<span className={severityClass(data.severity)}>{data.severity || '—'}</span>}
        />
        <MetaCell
          k="Service"
          v={data.service.toUpperCase()}
          sub={data.services.length ? `${data.services.length} in scope` : undefined}
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
            <ReferenceOverview
              incidentType={data.incidentType}
              detectionFiles={data.detectionFiles}
              overviewMarkdown={overviewSection?.markdown}
            />
          ) : (
            <PlaybookSection key={activeSection!.id} emulationId={data.id} section={activeSection!} />
          )}
        </div>

        <aside className="flex flex-col gap-4">
          <div className="bg-surface-card border border-border rounded-card shadow-ring p-5">
            <div className="font-display text-sm font-semibold text-content-primary mb-3.5">
              Playbook Details
            </div>
            <DetailRow k="Source" v="Reference library" />
            <DetailRow k="Tactic" v={data.tactic || '—'} />
            <DetailRow
              k="Severity"
              v={<span className={severityClass(data.severity)}>{data.severity || '—'}</span>}
            />
            <DetailRow k="Platform" v={(data.platform || 'aws').toUpperCase()} />
            {data.services.length > 0 && (
              <DetailRow
                k="Data Sources"
                v={
                  <div className="flex gap-1.5 flex-wrap justify-end">
                    {data.services.slice(0, 4).map((s) => (
                      <span key={s} className={chip}>
                        {s}
                      </span>
                    ))}
                    {data.services.length > 4 && (
                      <span className={chip}>+{data.services.length - 4}</span>
                    )}
                  </div>
                }
              />
            )}
            <DetailRow k="Techniques" v={String(data.techniques.length)} />
            <DetailRow k="Length" v={`${data.lineCount} lines`} />
          </div>

          <div className="bg-surface-card border border-border rounded-card shadow-ring p-5">
            <div className="font-display text-sm font-semibold text-content-primary mb-3.5">
              Related
            </div>
            <RelatedLink to="/playbooks" label="All playbooks" />
            <RelatedLink to="/detections" label="Detection coverage" />
            <RelatedLink to="/emulations" label="Emulation catalogue" />
          </div>
        </aside>
      </div>
    </div>
  )
}

/**
 * Overview tab for a reference playbook.
 *
 * Mirrors the emulation OverviewPane, minus the emulation summary it has no
 * equivalent for, plus the statement that the rules here are unvalidated. That
 * note is the only thing distinguishing this from a shipped detection, so it
 * leads rather than sits in a footer.
 */
function ReferenceOverview({
  incidentType,
  detectionFiles,
  overviewMarkdown,
}: {
  incidentType: string
  detectionFiles: string[]
  overviewMarkdown?: string
}) {
  return (
    <div className="flex flex-col gap-4">
      <div className="bg-surface-card border border-border rounded-card shadow-ring p-6">
        <div className="font-display text-sm font-semibold text-content-primary mb-3">
          Playbook Overview
        </div>
        {incidentType && (
          <p className="text-[0.95rem] leading-relaxed text-content-secondary font-medium mb-2">
            {incidentType}
          </p>
        )}
        {overviewMarkdown && <Markdown content={overviewMarkdown} />}
      </div>

      <div className="bg-surface-card border border-border rounded-card shadow-ring p-6">
        <div className="font-display text-sm font-semibold text-content-primary mb-3.5">
          IR Lifecycle
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2.5">
          {IR_LIFECYCLE.map((phase) => (
            <div
              key={phase.n}
              className="rounded-[10px] border border-border bg-surface-elevated px-3.5 py-3"
            >
              <div
                className={`inline-flex h-5 w-5 items-center justify-center rounded-full font-mono text-[11px] ${phase.badge}`}
              >
                {phase.n}
              </div>
              <div className="mt-2 text-[13px] font-semibold text-content-primary">{phase.name}</div>
              <div className="text-[11px] text-content-dim">{phase.hint}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-surface-card border border-warning/20 rounded-card shadow-ring p-6">
        <div className="font-display text-sm font-semibold text-warning mb-2">Documentation only</div>
        <p className="text-[0.9rem] leading-relaxed text-content-secondary">
          No emulation in the catalogue has been proven to fire the detection rules referenced here,
          so they are reference material rather than validated MayaTrail detections.
        </p>
        {detectionFiles.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {detectionFiles.map((f) => (
              <span
                key={f}
                className="font-mono text-[11px] px-2 py-1 rounded-btn bg-surface-elevated border border-border text-content-dim"
              >
                {f}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
