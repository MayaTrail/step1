import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import type {
  DetectionCheck,
  DetectionRuleOutcome,
  DetectionVerdict,
  EmulationRunRecord,
  PlatformId,
} from '@/types'
import { getEmulationRun } from '@/services/emulation.service'
import { useUiMode } from '@/context/UiModeContext'
import { Breadcrumb } from '@/components/ui/Breadcrumb'
import { DetectionExport } from '@/components/detections/DetectionExport'
import { CoverageTrend, RegressionBanner } from './CoverageHistory'
import { EmptyState } from '@/components/ui/EmptyState'
import { IconSearch } from '@/components/ui/Icons'

/** Verdicts in reading order: what worked, what to look at, what is not wired up. */
const VERDICT_ORDER: DetectionVerdict[] = ['fired', 'silent', 'no_logs']

/**
 * Two label sets for the same verdict. Technical is the SIEM vocabulary a
 * detection engineer expects; plain is what the verdict means in English, for
 * the Simple UI mode: a detection that "fired" caught the attack, one that
 * stayed "silent" missed it, and "no logs" means we had no data to judge it.
 */
const VERDICT_LABEL: Record<DetectionVerdict, string> = {
  fired: 'Fired',
  silent: 'Silent',
  no_logs: 'No logs',
}

const VERDICT_LABEL_PLAIN: Record<DetectionVerdict, string> = {
  fired: 'Caught',
  silent: 'Missed',
  no_logs: 'No data',
}

const verdictLabel = (verdict: DetectionVerdict, plain: boolean): string =>
  (plain ? VERDICT_LABEL_PLAIN : VERDICT_LABEL)[verdict]

/**
 * Colour carries meaning here, not decoration. Green is a working detection,
 * amber is a gap the user can close by fixing logging, and grey is the
 * informational middle case that needs a human to look at the rule.
 */
const VERDICT_CLASS: Record<DetectionVerdict, { chip: string; stripe: string; stat: string }> = {
  fired: {
    chip: 'text-safe bg-safe-dim',
    stripe: 'bg-safe',
    stat: 'text-safe',
  },
  silent: {
    chip: 'text-content-dim bg-[rgba(255,255,255,0.045)]',
    stripe: 'bg-[rgba(255,255,255,0.1)]',
    stat: 'text-content-secondary',
  },
  no_logs: {
    chip: 'text-warning bg-warning-dim',
    stripe: 'bg-warning',
    stat: 'text-warning',
  },
}

/**
 * Detection coverage for one emulation run.
 *
 * Opened from the "Check your logging" tile on the Live Emulation view. Replays
 * the emulation's Sigma rules over the detections archived while the attack was
 * running, and reports each rule as fired, silent, or lacking telemetry.
 *
 * The report is computed once by a Celery task after the run completes and
 * stored on the run, so this page is a read of one record, not a scan of S3.
 */
export function DetectionCoveragePage() {
  const { platformId, emulationId, runId } = useParams<{
    platformId: string
    emulationId: string
    runId: string
  }>()
  const pid = platformId as PlatformId
  const { plain } = useUiMode()

  const [run, setRun] = useState<EmulationRunRecord | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!runId) return
    let cancelled = false
    getEmulationRun(runId)
      .then((record) => !cancelled && setRun(record))
      .catch(() => !cancelled && setRun(null))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
  }, [runId])

  const back = `/${pid}/emulations/${emulationId}`

  if (loading) {
    return <div className="text-center py-16 text-content-dim font-mono text-sm">Loading coverage...</div>
  }

  const check = run?.detection_check ?? null

  return (
    <div>
      <Breadcrumb
        items={[
          { label: 'Home', to: '/' },
          { label: emulationId?.toUpperCase() ?? '', to: back },
          { label: 'Detection coverage' },
        ]}
      />

      <div className="flex items-start justify-between mb-6 gap-4">
        <div>
          <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
            {emulationId?.toUpperCase()}
          </div>
          <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
            Detection coverage
          </div>
          <div className="text-[0.9rem] text-content-secondary mt-1.5">
            {plain
              ? 'Which attacks in this run your defences caught, and which they missed'
              : "Which of this run's detections actually fired in your logs"}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {/* The report is this page's output, so it is reachable from here
              rather than only from the Reports list. */}
          {runId && (
            <Link
              to={`/reports/${runId}`}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer no-underline
                bg-accent-blue text-button-fg transition-opacity hover:opacity-80"
            >
              {plain ? 'Get the report' : 'Evidence report'}
            </Link>
          )}
          <Link
            to={back}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-btn font-body text-[0.9rem] font-medium cursor-pointer no-underline
              bg-transparent border border-border text-content-primary transition-opacity hover:opacity-60"
          >
            &#8592; Back to run
          </Link>
        </div>
      </div>

      {check === null || check.status !== 'ok' ? (
        <UnavailableState check={check} />
      ) : (
        <>
          <CoveragePanel check={check} plain={plain} />
          {runId && <RegressionBanner runId={runId} />}
          {emulationId && <CoverageTrend emulationType={emulationId} />}
          <SilentRuleExport check={check} runId={runId} plain={plain} />
        </>
      )}
    </div>
  )
}

/**
 * Turn the silent verdict into something deployable.
 *
 * A silent rule means the activity happened, the logs arrived, and the rule did
 * not match. That is the finding this whole page exists to produce - and on its
 * own it is just bad news. Compiling exactly those rules into the query
 * language the team's SIEM speaks is the part they can act on today.
 *
 * Only rendered when there is something to fix. Fired rules need nothing, and
 * no_logs is a telemetry gap that no query can close, so offering an export
 * there would send someone down the wrong path.
 */
function SilentRuleExport({
  check,
  runId,
  plain,
}: {
  check: DetectionCheck
  runId?: string
  plain: boolean
}) {
  const silent = check.counts?.silent ?? 0
  if (!runId || silent === 0) return null

  return (
    <div className="mt-5 bg-surface-card border border-border rounded-card shadow-ring p-5">
      <div className="mb-3">
        <div className="text-[0.85rem] font-semibold text-content-primary">
          Close the gap
        </div>
        <div className="text-[0.75rem] text-content-dim mt-0.5">
          {plain ? (
            <>{silent} attack{silent === 1 ? '' : 's'} slipped through undetected. Download{' '}
            {silent === 1 ? 'the detection' : 'these detections'} for your monitoring tool, turn{' '}
            {silent === 1 ? 'it' : 'them'} on, then run this test again to confirm{' '}
            {silent === 1 ? "it's caught" : "they're caught"}.</>
          ) : (
            <>{silent} rule{silent === 1 ? '' : 's'} stayed silent. Compile{' '}
            {silent === 1 ? 'it' : 'them'} for your SIEM, deploy, then re-run this
            emulation to confirm {silent === 1 ? 'it fires' : 'they fire'}.</>
          )}
        </div>
      </div>
      <DetectionExport scope="run" runId={runId} verdicts={['silent']} />
    </div>
  )
}

/**
 * What the page shows when there is no report to render.
 *
 * Each reason is named rather than collapsed into one message, because "the
 * archive is not configured" and "the check hit an error" call for different
 * responses from whoever is reading.
 */
function UnavailableState({ check }: { check: DetectionCheck | null }) {
  if (check === null) {
    return (
      <EmptyState
        icon={<IconSearch size={32} />}
        title="Coverage not available yet"
        body="The check runs about a minute after an attack completes. Reload once the run has finished."
      />
    )
  }
  if (check.status === 'not_configured') {
    return (
      <EmptyState
        icon={<IconSearch size={32} />}
        title="No detection archive configured"
        body="Set DETECTIONS_BUCKET on the worker to have MayaTrail replay this emulation's rules against your archived detections."
      />
    )
  }
  return (
    <EmptyState
      icon={<IconSearch size={32} />}
      title="Coverage check did not complete"
      body={check.detail ?? 'The check could not read the detection archive for this run.'}
    />
  )
}

/** The fixed-height shell: pinned tally, scrolling rule list, pinned footer. */
function CoveragePanel({ check, plain }: { check: DetectionCheck; plain: boolean }) {
  const rules = check.rules ?? []
  const counts = check.counts ?? { fired: 0, silent: 0, no_logs: 0 }

  return (
    <div className="bg-surface-card border border-border rounded-card shadow-ring overflow-hidden
      flex flex-col h-[calc(100vh-300px)] min-h-[520px]">
      <div className="flex flex-wrap items-start justify-between gap-4 px-5 py-4 border-b border-border shrink-0">
        <div>
          <div className="text-[0.85rem] font-semibold text-content-primary">
            {plain ? 'What we caught' : 'Detection coverage'}
          </div>
          <div className="text-[0.75rem] text-content-dim mt-0.5">
            {plain
              ? `We checked ${check.ruleCount ?? rules.length} detection${(check.ruleCount ?? rules.length) === 1 ? '' : 's'} against ${check.eventCount ?? 0} things this attack did`
              : `${check.ruleCount ?? rules.length} rules evaluated against ${check.eventCount ?? 0} events from this run`}
          </div>
        </div>
        <div className="flex gap-2 flex-wrap">
          {VERDICT_ORDER.map((verdict) => (
            <div key={verdict} className="border border-border rounded-btn px-3 py-1.5 min-w-[72px]">
              <div className={`font-mono text-[1.15rem] font-bold leading-none tabular-nums ${VERDICT_CLASS[verdict].stat}`}>
                {counts[verdict] ?? 0}
              </div>
              <div className="font-mono text-[0.55rem] uppercase tracking-[1px] text-content-dim mt-1.5">
                {verdictLabel(verdict, plain)}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* min-h-0 is what lets this scroll rather than stretching the shell. */}
      <div className="flex-1 min-h-0 overflow-y-auto">
        {rules.length === 0 ? (
          <div className="text-center py-12 text-content-dim font-mono text-sm">
            This emulation ships no Sigma rules to evaluate.
          </div>
        ) : (
          rules.map((rule) => <RuleRow key={rule.ruleId} rule={rule} plain={plain} />)
        )}
      </div>

      <div className="flex flex-wrap gap-x-5 gap-y-1 px-5 py-3 border-t border-border shrink-0
        font-mono text-[0.62rem] text-content-dim">
        {check.window?.start && check.window?.end && (
          <span>
            Window {formatTime(check.window.start)} to {formatTime(check.window.end)}
          </span>
        )}
        {(check.coveredSources?.length ?? 0) > 0 && (
          <span>Sources carried: {check.coveredSources?.join(', ')}</span>
        )}
      </div>
    </div>
  )
}

/** One rule: verdict stripe, identity, why it landed there, and evidence if it fired. */
function RuleRow({ rule, plain }: { rule: DetectionRuleOutcome; plain: boolean }) {
  const style = VERDICT_CLASS[rule.verdict]

  return (
    <div className="grid grid-cols-[3px_1fr_auto] gap-x-3.5 items-start pr-5 py-3 border-b border-border last:border-b-0">
      <div className={`w-[3px] self-stretch rounded-r-sm ${style.stripe}`} />
      <div>
        <div className="font-mono text-[0.7rem] text-accent-blue font-semibold uppercase">
          {rule.ruleId}
        </div>
        <div className="text-[0.8rem] text-content-primary font-semibold mt-0.5 leading-snug">
          {rule.title || rule.technique?.name || rule.ruleId}
        </div>
        <div className="font-mono text-[0.65rem] text-content-dim mt-1">
          {ruleReason(rule, plain)}
        </div>
        {rule.evidence && (
          <div className="mt-2 px-3 py-2 rounded-btn border border-safe/25 bg-safe-dim
            font-mono text-[0.65rem] text-content-secondary leading-relaxed overflow-x-auto">
            <div>
              <span className="text-content-dim">eventTime</span> {rule.evidence.eventTime}
              {'  '}
              <span className="text-content-dim">eventName</span> {rule.evidence.eventName}
            </div>
            <div>
              <span className="text-content-dim">actor</span> {rule.evidence.actor}
            </div>
            <div>
              <span className="text-content-dim">sourceIP</span> {rule.evidence.sourceIPAddress}
              {'  '}
              <span className="text-content-dim">is_emulation</span>{' '}
              <span className={rule.evidence.isEmulation ? '' : 'text-warning'}>
                {String(rule.evidence.isEmulation)}
              </span>
            </div>
          </div>
        )}
      </div>
      <div className={`font-mono text-[0.58rem] font-bold tracking-[1px] uppercase px-2 py-1 rounded whitespace-nowrap mt-0.5 ${style.chip}`}>
        {verdictLabel(rule.verdict, plain)}
      </div>
    </div>
  )
}

/**
 * The one-line explanation under a rule.
 *
 * Says why the rule landed on its verdict rather than restating the verdict, so
 * a reader can act without opening the rule.
 */
function ruleReason(rule: DetectionRuleOutcome, plain = false): string {
  const sources = rule.requiredSources.join(', ')
  if (rule.verdict === 'fired') {
    const n = rule.matchCount
    return plain
      ? `caught the attack (${n} matching event${n === 1 ? '' : 's'})`
      : `${n} matching event${n === 1 ? '' : 's'}`
  }
  if (rule.verdict === 'no_logs') {
    return plain
      ? `couldn't judge it — no ${sources || 'relevant'} logs came through`
      : `needs ${sources || 'an unlisted source'}, none reached the archive`
  }
  return plain
    ? `missed it — the activity was logged but nothing matched`
    : sources
      ? `${sources} arrived, no match`
      : 'no declared source, no match'
}

/** Render an ISO timestamp as HH:MM:SS UTC, which is all the footer needs. */
function formatTime(iso: string): string {
  const parsed = new Date(iso)
  return Number.isNaN(parsed.getTime()) ? iso : parsed.toISOString().slice(11, 19)
}
