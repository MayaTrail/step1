import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useDetectionDetail } from '@/hooks/usePlatformData'
import type { DetectionDetail, DetectionValidation, ValidationScenario, ValidationVerdict } from '@/types'
import { CodeBlock } from '@/components/ui/CodeBlock'
import { EmptyState } from '@/components/ui/EmptyState'
import { severityTextClass } from './severity'
import { downloadText } from '@/utils/download'
import { validateDetection } from '@/services/ai.service'

type DetailTab = 'overview' | 'validate' | 'source'
type RuleFormat = 'sigma' | 'kql'

/** Read a server error detail off an axios-style rejection. */
function errorDetail(err: unknown): string {
  const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
  return detail || 'Validation failed. Please try again.'
}

/**
 * Detection detail page.
 *
 * Renders a single detection rule (grouped Sigma + KQL + note for one MITRE
 * technique) as an Overview, an AI Validation workspace, and a Rule Source
 * viewer. Metadata is parsed from the rule frontmatter and the emulation
 * MANIFEST; validation results are AI-generated and held only in memory.
 */
export function DetectionDetailPage() {
  const { platformId, emulationId, ruleId } = useParams<{
    platformId: string
    emulationId: string
    ruleId: string
  }>()
  const { data: detail, loading } = useDetectionDetail(emulationId, ruleId)
  const [tab, setTab] = useState<DetailTab>('overview')

  // Validation state is ephemeral: it lives here in memory and is lost on
  // navigation or refresh, matching the "nothing is stored" backend contract.
  const [validation, setValidation] = useState<DetectionValidation | null>(null)
  const [validating, setValidating] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)

  async function runValidation() {
    if (!emulationId || !ruleId) return
    setValidating(true)
    setValidationError(null)
    try {
      setValidation(await validateDetection(emulationId, ruleId))
    } catch (err) {
      setValidationError(errorDetail(err))
    } finally {
      setValidating(false)
    }
  }

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading detection...</div>
  }

  if (!detail) {
    return (
      <EmptyState
        icon="&#128269;"
        title="Detection not found"
        body="This detection rule is unavailable or the emulation ships no rule for it."
      />
    )
  }

  const detectionsPath = `/${platformId}/emulations/${emulationId}/detections`

  return (
    <div>
      <Hero detail={detail} backTo={detectionsPath} />

      <div className="flex gap-1 border-b border-border mb-7">
        <TabButton label="Overview" active={tab === 'overview'} onClick={() => setTab('overview')} />
        <TabButton label="AI Validation" active={tab === 'validate'} onClick={() => setTab('validate')} />
        <TabButton label="Rule Source" active={tab === 'source'} onClick={() => setTab('source')} />
      </div>

      {tab === 'overview' && (
        <OverviewPanel
          detail={detail}
          platformId={platformId}
          emulationId={emulationId}
          validation={validation}
          validating={validating}
          onOpenValidation={() => setTab('validate')}
        />
      )}
      {tab === 'validate' && (
        <ValidationPanel
          detail={detail}
          validation={validation}
          validating={validating}
          error={validationError}
          onRun={runValidation}
        />
      )}
      {tab === 'source' && <SourcePanel detail={detail} />}
    </div>
  )
}

function Hero({ detail, backTo }: { detail: DetectionDetail; backTo: string }) {
  const platform = [detail.logSource.product, detail.logSource.service]
    .filter(Boolean)
    .join(' · ')
    .toUpperCase()

  const exportName = detail.formats.sigma ? `sigma_${detail.ruleId}.yml` : `kql_${detail.ruleId}.kql`
  const exportCode = detail.formats.sigma ? detail.sigma : detail.kql

  return (
    <div className="flex items-start justify-between mb-7 gap-4">
      <div>
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          {detail.displayName} &middot; Detection Rule
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px] max-w-[820px]">
          {detail.title || detail.technique.id}
        </div>
        <div className="flex flex-wrap gap-2 mt-4">
          {detail.severity && (
            <Chip className={severityTextClass(detail.severity)}>{detail.severity.toUpperCase()}</Chip>
          )}
          {platform && <Chip>{platform}</Chip>}
          <Chip className="text-accent-blue">{detail.technique.id}</Chip>
          <Chip>
            {[detail.formats.sigma && 'SIGMA', detail.formats.kql && 'KQL'].filter(Boolean).join(' + ')}
          </Chip>
          {detail.status && <Chip className="text-warning">{detail.status.toUpperCase()}</Chip>}
          {detail.date && <Chip>Updated {detail.date}</Chip>}
        </div>
      </div>
      <div className="flex gap-3 shrink-0">
        <Link
          to={backTo}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer no-underline
            bg-transparent border border-border text-content-primary transition-all
            hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
        >
          &#8592; Back
        </Link>
        {exportCode && (
          <button
            onClick={() => downloadText(exportName, exportCode)}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer
              bg-transparent border border-border text-content-primary transition-all
              hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active"
          >
            &#11015; Export Rule
          </button>
        )}
      </div>
    </div>
  )
}

function OverviewPanel({
  detail,
  platformId,
  emulationId,
  validation,
  validating,
  onOpenValidation,
}: {
  detail: DetectionDetail
  platformId?: string
  emulationId?: string
  validation: DetectionValidation | null
  validating: boolean
  onOpenValidation: () => void
}) {
  const cov = detail.coverage
  return (
    <div className="flex flex-col gap-4">
      {/* Summary cards */}
      <div className="grid gap-4 grid-cols-[repeat(auto-fit,minmax(180px,1fr))]">
        <SummaryCard label="Rule Type">
          {[detail.formats.sigma && 'Sigma', detail.formats.kql && 'KQL'].filter(Boolean).join(' + ')}
        </SummaryCard>
        <SummaryCard label="Severity" valueClass={severityTextClass(detail.severity)}>
          {detail.severity ? detail.severity.toUpperCase() : '—'}
        </SummaryCard>
        <SummaryCard label="Technique" sub={detail.technique.tactic}>
          {detail.technique.id}
        </SummaryCard>
        <SummaryCard label="Log Source">
          {detail.logSource.service ? detail.logSource.service : detail.logSource.product ?? '—'}
        </SummaryCard>
      </div>

      <LatestValidationCard
        validation={validation}
        validating={validating}
        onOpenValidation={onOpenValidation}
      />

      <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
        {/* Description + metadata */}
        <div className="bg-surface-card border border-border rounded-card p-6">
          <SectionLabel>Description</SectionLabel>
          <p className="text-[0.85rem] text-content-secondary leading-[1.7] mt-3">
            {detail.description || 'No description provided in the rule.'}
          </p>
          <div className="mt-5 pt-5 border-t border-border flex flex-col">
            <MetaRow label="Associated Emulation">
              <Link to={`/${platformId}/emulations/${emulationId}`} className="text-accent-blue no-underline hover:underline">
                {detail.displayName}
              </Link>
            </MetaRow>
            {detail.threatActor && <MetaRow label="Threat Actor">{detail.threatActor}</MetaRow>}
            {detail.technique.tactic && <MetaRow label="MITRE Tactic">{detail.technique.tactic}</MetaRow>}
            {detail.hasPlaybook && (
              <MetaRow label="Related Playbook">
                <Link
                  to={`/${platformId}/emulations/${emulationId}/playbook`}
                  className="text-accent-blue no-underline hover:underline"
                >
                  {detail.displayName} IR Playbook
                </Link>
              </MetaRow>
            )}
            {detail.author && <MetaRow label="Author">{detail.author}</MetaRow>}
          </div>
        </div>

        {/* Coverage */}
        <div className="bg-surface-card border border-border rounded-card p-6">
          <SectionLabel>Coverage</SectionLabel>
          <div className="grid grid-cols-2 gap-3 mt-3">
            <MiniStat label="Techniques" value={`${cov.techniquesCovered}/${cov.techniquesTotal}`} />
            <MiniStat label="Attack Phases" value={`${cov.phasesCovered}/${cov.phasesTotal}`} />
          </div>
          {detail.services.length > 0 && (
            <div className="mt-5">
              <div className="text-[0.7rem] uppercase tracking-[1px] text-content-dim font-mono mb-2.5">
                AWS Services
              </div>
              <div className="flex flex-wrap gap-1.5">
                {detail.services.map((svc) => (
                  <span key={svc} className="font-mono text-[0.72rem] px-2.5 py-1 rounded-btn bg-[rgba(255,255,255,0.04)] text-content-secondary">
                    {svc}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Known false positives (from the rule's own falsepositives block) */}
      {detail.falsePositives.length > 0 && (
        <div className="bg-surface-card border border-border rounded-card p-6">
          <SectionLabel>Known False Positives</SectionLabel>
          <ul className="mt-3 flex flex-col gap-2">
            {detail.falsePositives.map((fp, i) => (
              <li key={i} className="text-[0.83rem] text-content-secondary leading-[1.6] pl-4 relative">
                <span className="absolute left-0 text-content-dim">&middot;</span>
                {fp}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Related techniques */}
      {detail.relatedTechniques.length > 0 && (
        <div>
          <div className="text-[0.7rem] uppercase tracking-[1px] text-content-dim font-mono mb-2.5">
            Related MITRE Techniques
          </div>
          <div className="flex flex-wrap gap-1.5">
            {detail.relatedTechniques.map((t) => (
              <span key={t.id} className="font-mono text-[0.72rem] px-2.5 py-1 rounded-btn bg-[rgba(255,255,255,0.04)] text-content-secondary">
                {t.id}{t.name ? ` ${t.name}` : ''}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function SourcePanel({ detail }: { detail: DetectionDetail }) {
  const available = (['sigma', 'kql'] as RuleFormat[]).filter((f) => detail.formats[f])
  const [format, setFormat] = useState<RuleFormat>(available[0] ?? 'sigma')
  const code = format === 'sigma' ? detail.sigma : detail.kql

  return (
    <div>
      <div className="flex gap-2 mb-5">
        {available.map((fmt) => {
          const active = format === fmt
          return (
            <button
              key={fmt}
              onClick={() => setFormat(fmt)}
              className={`px-4 py-2 rounded-btn font-mono text-[0.75rem] uppercase tracking-[1.5px] font-medium cursor-pointer border transition-all
                ${active
                  ? 'bg-accent-blue/[0.15] border-accent-blue/40 text-accent-blue'
                  : 'bg-transparent border-border text-content-dim hover:border-border-active hover:text-content-secondary'
                }`}
            >
              {fmt.toUpperCase()}
            </button>
          )
        })}
      </div>
      {code ? (
        <CodeBlock code={code} className="mt-0" />
      ) : (
        <div className="text-center py-12 text-content-dim font-mono text-sm">
          No {format.toUpperCase()} rule for this detection.
        </div>
      )}
    </div>
  )
}

/* Presentational helpers */

function TabButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`font-mono text-[0.72rem] uppercase tracking-[1px] font-medium px-4 py-3 cursor-pointer border-b-2 -mb-px transition-colors
        ${active ? 'text-content-primary border-danger' : 'text-content-dim border-transparent hover:text-content-secondary'}`}
    >
      {label}
    </button>
  )
}

function Chip({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={`font-mono text-[0.68rem] font-semibold tracking-[0.4px] uppercase px-2.5 py-1 rounded-btn bg-[rgba(255,255,255,0.05)] ${className || 'text-content-secondary'}`}>
      {children}
    </span>
  )
}

function SummaryCard({
  label,
  sub,
  valueClass = 'text-content-primary',
  children,
}: {
  label: string
  sub?: string
  valueClass?: string
  children: React.ReactNode
}) {
  return (
    <div className="border border-border rounded-card p-4 bg-[rgba(255,255,255,0.01)]">
      <div className="text-[0.65rem] uppercase tracking-[1px] text-content-dim font-mono">{label}</div>
      <div className={`text-[1.35rem] font-[700] mt-1.5 ${valueClass}`}>{children}</div>
      {sub && <div className="text-[0.75rem] text-content-secondary mt-0.5">{sub}</div>}
    </div>
  )
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-border rounded-card p-3 bg-[rgba(255,255,255,0.01)]">
      <div className="text-[0.65rem] uppercase tracking-[1px] text-content-dim font-mono">{label}</div>
      <div className="text-[1.1rem] font-[700] text-content-primary mt-1">{value}</div>
    </div>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="text-[0.8rem] font-semibold tracking-[0.3px] text-content-secondary">{children}</div>
}

function MetaRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-2.5 border-b border-border last:border-b-0">
      <span className="text-content-dim text-[0.8rem]">{label}</span>
      <span className="text-content-primary text-[0.8rem] text-right">{children}</span>
    </div>
  )
}

/* AI Validation */

function AiBadge() {
  return (
    <span className="font-mono text-[0.58rem] font-bold uppercase tracking-[0.5px] px-2 py-0.5 rounded bg-purple/10 text-purple">
      AI
    </span>
  )
}

const VERDICT_CLASS: Record<ValidationVerdict, string> = {
  matched: 'text-green',
  caught: 'text-green',
  quiet: 'text-green',
  missed: 'text-danger',
  'false positive': 'text-danger',
}

/** Compact validation summary shown on the Overview tab. */
function LatestValidationCard({
  validation,
  validating,
  onOpenValidation,
}: {
  validation: DetectionValidation | null
  validating: boolean
  onOpenValidation: () => void
}) {
  return (
    <div className="bg-surface-card border border-border rounded-card p-6">
      <div className="flex items-center gap-2 mb-3">
        <SectionLabel>Latest Validation</SectionLabel>
        <AiBadge />
        <span className="ml-auto text-[0.72rem] text-content-dim">ephemeral &middot; cleared on refresh</span>
      </div>
      {validating ? (
        <div className="text-content-dim font-mono text-sm py-2">Generating and testing sample logs...</div>
      ) : validation && validation.evaluable ? (
        <div className="flex items-center gap-6 flex-wrap">
          <div>
            <div className="text-[2.4rem] font-[800] text-purple leading-none">{validation.fidelity}</div>
            <div className="font-mono text-[0.62rem] uppercase tracking-[1px] text-content-dim mt-1">Fidelity</div>
          </div>
          <div className="flex gap-3 flex-wrap">
            <MiniStat label="Positives" value={validation.summary?.positiveHit ?? '—'} />
            <MiniStat label="Benign quiet" value={validation.summary?.benignQuiet ?? '—'} />
            <MiniStat label="Evasion caught" value={validation.summary?.evasionCaught ?? '—'} />
          </div>
          <button onClick={onOpenValidation} className="ml-auto text-[0.8rem] text-accent-blue hover:underline">
            View details &#8594;
          </button>
        </div>
      ) : validation && !validation.evaluable ? (
        <div className="text-[0.83rem] text-content-secondary">
          Not machine-testable ({validation.reason}). Its logic spans multiple events, so
          single-event testing does not apply and no fidelity score is produced.
        </div>
      ) : (
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <p className="text-[0.83rem] text-content-secondary max-w-[520px]">
            Generate synthetic logs from this rule and test the rule against them to measure its logic
            fidelity. Nothing is stored.
          </p>
          <button onClick={onOpenValidation} className="text-[0.8rem] text-accent-blue hover:underline shrink-0">
            Open AI Validation &#8594;
          </button>
        </div>
      )}
    </div>
  )
}

/** Full AI Validation workspace on the detail page. */
function ValidationPanel({
  detail,
  validation,
  validating,
  error,
  onRun,
}: {
  detail: DetectionDetail
  validation: DetectionValidation | null
  validating: boolean
  error: string | null
  onRun: () => void
}) {
  const runLabel = validating
    ? 'Generating and testing...'
    : validation
      ? 'Regenerate & Test'
      : 'Generate & Test Sample Logs'

  return (
    <div className="flex flex-col gap-4">
      <div className="bg-surface-card border border-border rounded-card p-6">
        <div className="flex items-center gap-2 mb-2">
          <SectionLabel>AI Validation</SectionLabel>
          <AiBadge />
        </div>
        <p className="text-[0.83rem] text-content-secondary leading-[1.7] max-w-[720px]">
          The AI generates synthetic CloudTrail events from this Sigma rule (positives that should match,
          benign look-alikes, and attacker evasion variants), then the rule is executed against each one.
          This measures rule logic, not production noise. Results are ephemeral and are cleared on refresh.
        </p>
        {!detail.formats.sigma ? (
          <div className="mt-4 text-[0.83rem] text-warning">
            This rule has no Sigma variant, so it cannot be executed. KQL execution is not supported.
          </div>
        ) : (
          <button
            onClick={onRun}
            disabled={validating}
            className="mt-4 inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer
              border border-purple/40 bg-purple/[0.08] text-purple transition-opacity hover:opacity-70
              disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {runLabel}
          </button>
        )}
        {error && <div className="mt-4 text-[0.82rem] text-danger">{error}</div>}
      </div>

      {validation && !validation.evaluable && (
        <div className="bg-surface-card border border-border rounded-card p-6">
          <SectionLabel>Not machine-testable</SectionLabel>
          <p className="text-[0.83rem] text-content-secondary mt-2 leading-[1.6]">
            This rule uses an {validation.reason}. Its detection logic is a threshold or a sequence
            measured across many events, and the in-process evaluator judges one event at a time, so
            the rule is not executed here and no fidelity score is produced. The rule itself is not
            faulty; this form of testing simply does not apply to it. Review the logic against
            the detection note and the playbook instead.
          </p>
        </div>
      )}

      {validation && validation.evaluable && (
        <>
          <div className="bg-surface-card border border-border rounded-card p-6 flex items-center gap-8 flex-wrap">
            <div>
              <div className="text-[2.8rem] font-[800] text-purple leading-none">{validation.fidelity}</div>
              <div className="font-mono text-[0.62rem] uppercase tracking-[1px] text-content-dim mt-1">Fidelity</div>
            </div>
            <div className="flex gap-3 flex-wrap">
              <MiniStat label="Positives hit" value={validation.summary?.positiveHit ?? '—'} />
              <MiniStat label="Benign quiet" value={validation.summary?.benignQuiet ?? '—'} />
              <MiniStat label="Evasion caught" value={validation.summary?.evasionCaught ?? '—'} />
            </div>
            <p className="text-[0.78rem] text-content-dim max-w-[280px] leading-[1.5]">
              Fidelity blends the three rates on AI-generated events. It measures rule logic, not production
              noise.
            </p>
          </div>

          <div className="bg-surface-card border border-border rounded-card p-6">
            <SectionLabel>Test Scenarios</SectionLabel>
            <div className="mt-3 flex flex-col gap-2">
              {validation.scenarios?.map((scenario, i) => <ScenarioRow key={i} scenario={scenario} />)}
            </div>
          </div>

          {validation.suggestions && validation.suggestions.length > 0 && (
            <div className="bg-surface-card border border-border rounded-card p-6">
              <div className="flex items-center gap-2">
                <SectionLabel>Suggested Improvements</SectionLabel>
                <AiBadge />
              </div>
              <ul className="mt-3 flex flex-col gap-2">
                {validation.suggestions.map((suggestion, i) => (
                  <li key={i} className="text-[0.83rem] text-content-secondary leading-[1.6] pl-4 relative">
                    <span className="absolute left-0 text-content-dim">&middot;</span>
                    {suggestion}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  )
}

/** One expandable synthetic test event with its verdict. */
function ScenarioRow({ scenario }: { scenario: ValidationScenario }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border border-border rounded-btn overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-3 px-3.5 py-2.5 text-left cursor-pointer">
        <span className="font-mono text-[0.6rem] uppercase tracking-[0.5px] px-2 py-0.5 rounded bg-[rgba(255,255,255,0.05)] text-content-dim">
          {scenario.label}
        </span>
        <span className="text-[0.8rem] text-content-secondary flex-1">{scenario.rationale}</span>
        <span className={`font-mono text-[0.7rem] font-semibold uppercase ${VERDICT_CLASS[scenario.verdict]}`}>
          {scenario.verdict}
        </span>
      </button>
      {open && (
        <div className="px-3.5 pb-3">
          <CodeBlock code={JSON.stringify(scenario.event, null, 2)} className="mt-1" />
          {scenario.firedSelections.length > 0 && (
            <div className="text-[0.72rem] text-content-dim mt-2 font-mono">
              fired: {scenario.firedSelections.join(', ')}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
