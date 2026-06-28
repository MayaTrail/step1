import type { ReactNode } from 'react'
import type { Emulation } from '@/types'
import { useDetections } from '@/hooks/usePlatformData'
import { Card } from '@/components/ui/Card'
import { MetricCard } from '@/components/ui/MetricCard'
import { Button } from '@/components/ui/Button'

/**
 * Overview tab — the landing surface for an emulation's detail page.
 *
 * Answers the pre-execution questions from the PRD ("what is this attack? who
 * uses it? what will it cost? what will happen?") using only data the MANIFEST
 * and the detections endpoint already provide. Sections render conditionally so
 * a sparse atomic emulation (1 technique, 0 resources) reads as intentional
 * rather than broken.
 *
 * Deliberately omitted this phase (no authored data source yet):
 *   - Detection Difficulty rating (deferred MANIFEST field)
 *   - Per-technique MITRE coverage gauge
 */

/** Phase accent colors, shared with the Attack Path kill-chain visualisation. */
const PHASE_COLORS = ['#f87171', '#ff6b35', '#fbbf24', '#00d4ff', '#a78bfa', '#10b981']

interface OverviewTabProps {
  emulation: Emulation
  platformLabel: string
  /** Opens the Run Emulation modal (owned by the parent detail page). */
  onRun: () => void
  /** Switches the parent's active tab to Attack Path. */
  onOpenAttackPath: () => void
  /** Switches the parent's active tab to References. */
  onOpenReferences: () => void
  /** Route to the emulation's playbook page. */
  playbookHref: string
}

export function OverviewTab({
  emulation: em,
  platformLabel,
  onRun,
  onOpenAttackPath,
  onOpenReferences,
  playbookHref,
}: OverviewTabProps) {
  // Detection rule count is per-emulation; cached SWR hook so it never blanks.
  const { data: detections } = useDetections(em.id)
  const detectionCount = detections?.totalCount

  const ttl = em.defaultTtlHours
  const costPerRun =
    em.estimatedCostPerHourUsd != null && ttl != null
      ? em.estimatedCostPerHourUsd * ttl
      : undefined

  return (
    <div className="flex flex-col gap-4 animate-fadeIn">
      {/* ── Executive Summary + Threat Intelligence ─────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-[1.4fr_1fr] gap-4">
        <Card className="p-6">
          <SectionTitle>Executive Summary</SectionTitle>
          <p className="text-[0.95rem] leading-relaxed text-content-secondary font-medium">
            {em.description || em.aliases}
          </p>
        </Card>

        <Card className="p-6">
          <SectionTitle>Threat Intelligence</SectionTitle>
          <div className="flex flex-col">
            <IntelRow label="Attribution" value={em.attribution} valueClass="text-danger" />
            <IntelRow label="Active Since" value={em.activeSince} />
            <IntelRow label="Primary Targets" value={em.targets} />
            {em.incidents.length > 0 && (
              <div className="py-2.5">
                <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-1.5">
                  Notable Incidents
                </div>
                <div className="flex flex-col gap-1">
                  {em.incidents.map((inc, i) => (
                    <div key={i} className="font-mono text-[11px] text-content-secondary leading-relaxed">
                      {inc}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* ── Key Metrics ─────────────────────────────────────────────── */}
      <Card className="p-6">
        <SectionTitle>Key Metrics</SectionTitle>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MetricCard accent="neutral" label="Platform" value={platformLabel} />
          <MetricCard
            accent="neutral"
            label="Est. Runtime"
            value={em.estimatedDurationMinutes != null ? `~${em.estimatedDurationMinutes}` : '—'}
            caption={em.estimatedDurationMinutes != null ? 'minutes' : undefined}
          />
          <MetricCard
            accent="neutral"
            label="Est. Cost"
            value={costPerRun != null ? (costPerRun > 0 ? `$${costPerRun.toFixed(2)}` : 'Free') : '—'}
            caption={costPerRun != null && costPerRun > 0 ? 'per run' : undefined}
          />
          <MetricCard accent="neutral" label="Attack Phases" value={em.phaseCount ?? em.attackPath.length} />
          <MetricCard accent="neutral" label="MITRE Techniques" value={em.techniqueCount} />
          <MetricCard accent="neutral" label="AWS Services" value={em.services?.length ?? 0} />
          {em.totalResources != null && (
            <MetricCard accent="neutral" label="Total Resources" value={em.totalResources} />
          )}
          {detectionCount != null && (
            <MetricCard accent="neutral" label="Detection Rules" value={detectionCount} />
          )}
        </div>
      </Card>

      {/* ── AWS Services Involved ───────────────────────────────────── */}
      {em.services && em.services.length > 0 && (
        <Card className="p-6">
          <SectionTitle>AWS Services Involved</SectionTitle>
          <div className="flex flex-wrap gap-2.5">
            {em.services.map((svc) => (
              <span
                key={svc}
                className="inline-flex items-center gap-2 bg-surface-base border border-border rounded-btn
                  px-3.5 py-2 text-[0.8rem] font-medium text-content-secondary"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-accent-blue" />
                {svc}
              </span>
            ))}
          </div>
        </Card>
      )}

      {/* ── Attack Summary timeline ─────────────────────────────────── */}
      {em.attackPath.length > 0 && (
        <Card className="p-6">
          <SectionTitle>
            Attack Summary
            <span className="ml-2 normal-case tracking-normal font-sans text-content-dim text-[11px]">
              select a phase to open the Attack Path
            </span>
          </SectionTitle>
          <div className="flex items-stretch gap-1 overflow-x-auto pb-1">
            {em.attackPath.map((phase, i) => {
              const color = PHASE_COLORS[i % PHASE_COLORS.length]
              const isLast = i === em.attackPath.length - 1
              return (
                <div key={phase.phase} className="flex items-center">
                  <button
                    onClick={onOpenAttackPath}
                    className="flex-1 min-w-[140px] text-left bg-surface-base border border-border rounded-[10px]
                      px-3.5 py-3 cursor-pointer transition-all hover:border-border-active hover:-translate-y-0.5"
                  >
                    <div className="font-mono text-[9px] tracking-label uppercase" style={{ color }}>
                      Phase {phase.phase}
                    </div>
                    <div className="text-[0.8rem] font-semibold text-content-primary mt-1.5">{phase.name}</div>
                    <div className="font-mono text-[10px] text-content-dim mt-1">
                      {phase.techniques.map((t) => t.id).join(' · ')}
                    </div>
                  </button>
                  {!isLast && <span className="text-content-dim px-1.5 shrink-0">{'→'}</span>}
                </div>
              )
            })}
          </div>
        </Card>
      )}

      {/* ── Expected Outcomes + Detection Readiness ─────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="p-6">
          <SectionTitle>Expected Outcomes</SectionTitle>
          <ul className="flex flex-col gap-2.5">
            {em.totalResources != null && em.totalResources > 0 && (
              <Outcome>Deploys temporary AWS infrastructure ({em.totalResources} resources)</Outcome>
            )}
            <Outcome>
              Executes {em.techniqueCount} ATT&amp;CK technique{em.techniqueCount === 1 ? '' : 's'} across{' '}
              {em.phaseCount ?? em.attackPath.length} phase{(em.phaseCount ?? em.attackPath.length) === 1 ? '' : 's'}
            </Outcome>
            <Outcome>Generates CloudTrail telemetry for detection validation</Outcome>
            <Outcome>Produces an execution report and IR findings</Outcome>
            {ttl != null && (
              <Outcome>Automatically destroys all resources after {ttl} hour{ttl === 1 ? '' : 's'}</Outcome>
            )}
          </ul>
        </Card>

        <Card className="p-6">
          <SectionTitle>Detection Readiness</SectionTitle>
          <div className="grid grid-cols-2 gap-3">
            <ReadinessCell
              value={detectionCount != null ? detectionCount : '—'}
              label="Detection Rules"
              caption={detections?.formats ?? 'SIGMA / KQL'}
              accent="text-safe"
            />
            <ReadinessCell value={em.techniqueCount} label="MITRE Techniques" caption={`${em.attackPath.length} tactics`} />
          </div>
          <a
            href={playbookHref}
            className="inline-flex items-center gap-2 mt-4 font-mono text-[11px] text-accent-blue no-underline hover:underline"
          >
            View the incident-response playbook {'↗'}
          </a>
        </Card>
      </div>

      {/* ── Prerequisites + Safety ──────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="p-6">
          <SectionTitle>Prerequisites</SectionTitle>
          <div className="flex flex-col">
            <PrereqRow label="Platform" value={platformLabel} />
            <PrereqRow label="IaC Engine" value="Pulumi" />
            {costPerRun != null && (
              <PrereqRow
                label="Estimated AWS Cost"
                value={costPerRun > 0 ? `$${em.estimatedCostPerHourUsd?.toFixed(2)} / hr` : 'Free tier'}
              />
            )}
            <PrereqRow label="Deploy Permissions" value="Scoped IAM connector role" />
            {ttl != null && (
              <PrereqRow label="Cleanup Behavior" value={`Auto-destroy after ${ttl} hour${ttl === 1 ? '' : 's'}`} />
            )}
          </div>
        </Card>

        <Card accent="blue" className="p-6 flex flex-col justify-center">
          <div className="font-mono text-2xs uppercase tracking-label text-accent-blue mb-3">
            Safety Information
          </div>
          <ul className="flex flex-col gap-2">
            <SafetyLine>This emulation only deploys resources inside your selected sandbox stack.</SafetyLine>
            <SafetyLine>No production data is read, modified, or exfiltrated outside the sandbox.</SafetyLine>
            {ttl != null && (
              <SafetyLine>
                All infrastructure is automatically destroyed after {ttl} hour{ttl === 1 ? '' : 's'} unless retained.
              </SafetyLine>
            )}
          </ul>
        </Card>
      </div>

      {/* ── Primary Actions ─────────────────────────────────────────── */}
      <Card className="p-5">
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="primary" size="lg" onClick={onRun}>
            Run Emulation
          </Button>
          <Button variant="secondary" onClick={onOpenAttackPath}>
            View Attack Path
          </Button>
          <a href={playbookHref}>
            <Button variant="secondary">View Playbook</Button>
          </a>
          <Button variant="secondary" onClick={onOpenReferences}>
            View References
          </Button>
        </div>
      </Card>
    </div>
  )
}

/* ── Local presentational helpers ──────────────────────────────────── */

function SectionTitle({ children }: { children: ReactNode }) {
  return (
    <div className="font-mono text-2xs tracking-label uppercase text-content-dim mb-4 flex items-center gap-2.5">
      {children}
      <div className="flex-1 h-px bg-border" />
    </div>
  )
}

/** One Threat-Intelligence row; renders nothing when the value is missing. */
function IntelRow({ label, value, valueClass = '' }: { label: string; value?: string; valueClass?: string }) {
  if (!value) return null
  return (
    <div className="flex justify-between gap-4 py-2.5 border-b border-border last:border-b-0">
      <div className="font-mono text-2xs uppercase tracking-label text-content-dim pt-0.5 shrink-0">{label}</div>
      <div className={`text-[13px] font-medium text-content-primary text-right ${valueClass}`}>{value}</div>
    </div>
  )
}

function Outcome({ children }: { children: ReactNode }) {
  return (
    <li className="flex items-start gap-2.5 text-[0.85rem] text-content-secondary font-medium">
      <span className="text-safe shrink-0 mt-0.5">{'✓'}</span>
      {children}
    </li>
  )
}

function ReadinessCell({
  value,
  label,
  caption,
  accent = 'text-content-primary',
}: {
  value: ReactNode
  label: string
  caption?: string
  accent?: string
}) {
  return (
    <div className="bg-surface-base border border-border rounded-[10px] p-4">
      <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-2">{label}</div>
      <div className={`font-display text-2xl font-bold leading-none tabular-nums ${accent}`}>{value}</div>
      {caption && <div className="text-[11px] text-content-dim mt-1">{caption}</div>}
    </div>
  )
}

function PrereqRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 py-2 border-b border-border last:border-b-0 text-[13px]">
      <span className="text-content-dim font-medium">{label}</span>
      <span className="text-content-primary font-medium text-right">{value}</span>
    </div>
  )
}

function SafetyLine({ children }: { children: ReactNode }) {
  return (
    <li className="text-[13px] text-content-secondary font-medium pl-4 relative before:content-['\2014'] before:absolute before:left-0 before:text-content-dim">
      {children}
    </li>
  )
}
