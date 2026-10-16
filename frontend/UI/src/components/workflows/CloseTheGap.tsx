import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { DetectionExportBundle, DetectionTarget } from '@/types'
import type { AttackPhase } from '@/types/platform'
import type { RuleOutcome, WorkflowRunDetail } from '@/types/workflow'
import { exportWorkflowGap, listDetectionTargets } from '@/services/detectionExport.service'
import { rulesForPhase } from './phaseMeta'

/**
 * The detections this run's SIEM missed, compiled for that SIEM.
 *
 * Where the validation loop closes. A workflow ends by saying which expected
 * detections never reported; on its own that is a finding with no action
 * attached. This hands each one back as queries the customer can deploy, so
 * the next run can prove the gap is shut.
 *
 * Laid out as three steps: pick a missed detection, pick your SIEM, copy what
 * to deploy. The queries compile as soon as a SIEM is chosen, because the
 * conversion is deterministic and fast, so a separate compile button only
 * added a click. Each SIEM and format is compiled once and kept, so switching
 * back is instant.
 *
 * Rendered only when something was actually silent. A run where everything
 * fired has nothing to fix, and a run with no alert endpoint measured nothing.
 */

/** Short names for the SIEMs, in place of the backend's longer labels. */
const SIEM_NAME: Record<string, string> = {
  splunk: 'Splunk',
  opensearch: 'OpenSearch / Wazuh',
}

/** Each output format in plain words, and where its output goes. */
const FORMAT_TEXT: Record<string, Record<string, { label: string; hint: string }>> = {
  splunk: {
    default: { label: 'Search query', hint: 'Paste into Search, then save it as an alert.' },
    savedsearches: {
      label: 'savedsearches.conf',
      hint: 'Drop into an app on your search head. One stanza per detection.',
    },
  },
  opensearch: {
    default: { label: 'Lucene query', hint: "Paste into Discover, or into a monitor's query." },
    dsl_lucene: { label: 'Query DSL', hint: 'Use as the query of a monitor or a _search request.' },
  },
}

const SEGMENTS = 'inline-flex gap-0.5 rounded-btn bg-surface-elevated p-0.5'
const BUTTON = 'px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn transition-opacity hover:opacity-60'

/** One segment of a segmented control. */
function segment(active: boolean): string {
  return `rounded-md px-3 py-1.5 text-xs tracking-body transition-opacity hover:opacity-60 ${
    active ? 'bg-white/[0.08] text-content-primary' : 'text-content-dim'
  }`
}

/** A rule title without the emulation prefix every shipped rule carries. */
function shortTitle(title: string): string {
  return title.replace(/^[^-]+ - /, '')
}

/**
 * Explain a failed conversion in a sentence.
 *
 * The backend reports the converter's own message, which is accurate and
 * unreadable. The one failure that recurs is a correlation (a count of events
 * over a time window) that a backend cannot express, so that case is named;
 * anything else is described generally, with the raw message one click away.
 */
function plainReason(reasons: string[], siem: string): string {
  if (reasons.some((reason) => /correlation/i.test(reason))) {
    return `It counts events over a time window, and the ${siem} converter cannot write that as a single query.`
  }
  return `The ${siem} converter could not express this rule.`
}

/**
 * Flatten a bundle into the text the copy-all button puts on the clipboard.
 *
 * @param bundle - The compiled bundle.
 * @returns One titled block per query, in the order they were compiled.
 */
function bundleText(bundle: DetectionExportBundle): string {
  const header = [
    `# MayaTrail detection export`,
    `# Emulation: ${bundle.emulationType}`,
    `# Target: ${bundle.target} / ${bundle.format}`,
    bundle.note ? `# ${bundle.note}` : '',
    '',
  ].filter(Boolean)
  const body = bundle.queries.map((entry) => `# ${entry.title}\n${entry.query}`)
  return [...header, ...body].join('\n\n')
}

interface CloseTheGapProps {
  run: WorkflowRunDetail
  /** The emulation's attack phases, to say where each missed detection sits. Empty until loaded. */
  phases: AttackPhase[]
}

export function CloseTheGap({ run, phases }: CloseTheGapProps) {
  const navigate = useNavigate()
  const [targets, setTargets] = useState<DetectionTarget[] | null>(null)
  const [target, setTarget] = useState('')
  const [format, setFormat] = useState('')
  const [bundles, setBundles] = useState<Record<string, DetectionExportBundle>>({})
  const [error, setError] = useState<string | null>(null)
  const [chosen, setChosen] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)

  const listRef = useRef<HTMLUListElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const [notchTop, setNotchTop] = useState<number | null>(null)

  const phaseOf = (rule: RuleOutcome) => phases.find((phase) => rulesForPhase(phase, [rule]).length > 0)
  const silent = (run.score?.rules ?? [])
    .filter((rule) => rule.verdict === 'silent')
    .sort((a, b) => (phaseOf(a)?.phase ?? 99) - (phaseOf(b)?.phase ?? 99))
  const selected = silent.find((rule) => rule.ruleId === chosen) ?? silent[0] ?? null

  const key = `${target}/${format}`
  const bundle = bundles[key] ?? null

  useEffect(() => {
    let live = true
    listDetectionTargets()
      .then((rows) => {
        if (!live) return
        setTargets(rows)
        const first = rows.find((row) => row.installed)
        if (first) {
          setTarget(first.name)
          setFormat(first.formats[0] ?? 'default')
        }
      })
      .catch(() => live && setTargets([]))
    return () => {
      live = false
    }
  }, [])

  // Compile on choosing a SIEM or format, once per pair.
  useEffect(() => {
    setError(null)
    if (!target || !format || bundles[key]) return undefined
    let live = true
    exportWorkflowGap(run.id, target, format)
      .then((result) => {
        if (!live) return
        if (result) setBundles((current) => ({ ...current, [key]: result }))
        else setError('Nothing to compile: every expected detection fired in this run.')
      })
      .catch((caught) => {
        if (!live) return
        const detail = (caught as { response?: { data?: { detail?: string } } }).response?.data?.detail
        setError(detail ?? 'Could not compile these rules.')
      })
    return () => {
      live = false
    }
  }, [run.id, target, format, key, bundles])

  /*
   * The panel points at the detection it shows. The notch is placed level
   * with the selected row, measured after layout, and again on resize because
   * the list reflows. Below the lg breakpoint the panel sits under the list
   * and the notch is hidden.
   */
  useLayoutEffect(() => {
    function place() {
      const row = listRef.current?.querySelector(`[data-rule="${selected?.ruleId}"]`)
      const panel = panelRef.current
      if (!row || !panel) return
      const rowBox = row.getBoundingClientRect()
      const middle = rowBox.top + rowBox.height / 2 - panel.getBoundingClientRect().top - 6
      setNotchTop(Math.max(14, Math.min(middle, panel.offsetHeight - 18)))
    }
    place()
    window.addEventListener('resize', place)
    return () => window.removeEventListener('resize', place)
  }, [selected?.ruleId, bundle])

  if (silent.length === 0 || !selected) return null

  const siem = SIEM_NAME[target] ?? targets?.find((row) => row.name === target)?.label ?? target
  const formats = targets?.find((row) => row.name === target)?.formats ?? []
  const formatText = FORMAT_TEXT[target]?.[format]
  const total = run.score?.ruleCount ?? silent.length
  const many = silent.length > 1

  const queriesFor = (rule: RuleOutcome) => bundle?.queries.filter((q) => q.ruleId === rule.ruleId) ?? []
  const reasonsFor = (rule: RuleOutcome) => [
    ...(bundle?.skipped.filter((s) => s.ruleId === rule.ruleId).map((s) => s.reason) ?? []),
    ...(bundle?.missing.includes(rule.ruleId) ? ['No Sigma rule ships for this detection.'] : []),
  ]
  const unconvertible = (rule: RuleOutcome) => Boolean(bundle) && queriesFor(rule).length === 0

  function copy(id: string, text: string) {
    navigator.clipboard?.writeText(text)
    setCopied(id)
    window.setTimeout(() => setCopied((current) => (current === id ? null : current)), 1500)
  }

  const queries = queriesFor(selected)
  const reasons = reasonsFor(selected)
  const phase = phaseOf(selected)

  return (
    <section>
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h3 className="font-mono text-2xs uppercase tracking-label text-content-dim">Close the gap</h3>
        <span className="font-mono text-2xs text-content-dim">
          {silent.length} of {total} expected detections stayed silent
        </span>
      </div>
      <p className="text-sm text-content-secondary tracking-body leading-relaxed mt-2">
        Your SIEM did not report {many ? 'these detections' : 'this detection'} during the run. Deploy
        the {many ? 'queries' : 'query'}, then run this workflow again to confirm {many ? 'they fire' : 'it fires'}.
      </p>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mt-5">
        <div className="lg:col-span-5 flex flex-col gap-6">
          <div>
            <StepHead number={1}>What stayed silent</StepHead>
            <ul ref={listRef} className="divide-y divide-border border-y border-border">
              {silent.map((rule) => {
                const on = rule.ruleId === selected.ruleId
                const rulePhase = phaseOf(rule)
                return (
                  <li key={rule.ruleId}>
                    <button
                      type="button"
                      data-rule={rule.ruleId}
                      aria-pressed={on}
                      onClick={() => setChosen(rule.ruleId)}
                      className="w-full min-w-0 bg-transparent text-left py-3 transition-opacity hover:opacity-60"
                    >
                      <span className={`block truncate text-sm ${on ? 'text-accent-blue' : 'text-content-primary'}`}>
                        {shortTitle(rule.title)}
                      </span>
                      <span className="block truncate font-mono text-2xs text-content-dim mt-1">
                        {[rulePhase ? `Phase ${rulePhase.phase}` : '', rule.technique, rule.severity]
                          .filter(Boolean)
                          .join(' · ')}
                      </span>
                      {unconvertible(rule) && (
                        <span className="block text-xs text-warning mt-1">{siem} cannot express this one</span>
                      )}
                    </button>
                  </li>
                )
              })}
            </ul>
          </div>

          <div>
            <StepHead number={2}>Your SIEM</StepHead>
            {targets === null ? (
              <p className="font-mono text-2xs text-content-muted">Loading…</p>
            ) : targets.every((row) => !row.installed) ? (
              <p className="text-xs text-content-dim">No SIEM converters are installed on this server.</p>
            ) : (
              <>
                <div className="flex flex-col items-start gap-2">
                  <div className={SEGMENTS}>
                    {targets.filter((row) => row.installed).map((row) => (
                      <button
                        key={row.name}
                        type="button"
                        onClick={() => {
                          setTarget(row.name)
                          setFormat(row.formats[0] ?? 'default')
                        }}
                        className={segment(row.name === target)}
                      >
                        {SIEM_NAME[row.name] ?? row.label}
                      </button>
                    ))}
                  </div>
                  {formats.length > 1 && (
                    <div className={SEGMENTS}>
                      {formats.map((name) => (
                        <button key={name} type="button" onClick={() => setFormat(name)} className={segment(name === format)}>
                          {FORMAT_TEXT[target]?.[name]?.label ?? name}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                {formatText && <p className="text-2xs text-content-muted mt-2">{formatText.hint}</p>}
              </>
            )}
          </div>
        </div>

        <div className="lg:col-span-7">
          <StepHead number={3}>Deploy, then run again</StepHead>
          <div ref={panelRef} className="relative rounded-xl border border-border bg-surface-base">
            {notchTop !== null && (
              <span
                aria-hidden="true"
                style={{ top: notchTop }}
                className="hidden lg:block absolute -left-1.5 w-3 h-3 rotate-45 bg-surface-base
                  border-l border-b border-border transition-all duration-200"
              />
            )}

            <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border">
              <span className="min-w-0">
                <span className="block truncate text-sm text-content-primary">{shortTitle(selected.title)}</span>
                <span className="block truncate font-mono text-2xs text-content-dim mt-0.5">
                  {[
                    phase?.name ?? '',
                    !bundle ? '' : queries.length ? `${queries.length} quer${queries.length === 1 ? 'y' : 'ies'}` : 'not converted',
                    siem,
                  ]
                    .filter(Boolean)
                    .join(' · ')}
                </span>
              </span>
              {bundle && bundle.queries.length > 0 && (
                <button
                  type="button"
                  onClick={() => copy('all', bundleText(bundle))}
                  className={`${BUTTON} shrink-0 border border-white/10 ${copied === 'all' ? 'text-safe' : 'text-content-primary'}`}
                >
                  {copied === 'all' ? 'Copied' : many ? `Copy all ${silent.length} detections` : 'Copy all'}
                </button>
              )}
            </div>

            {error ? (
              <p className="px-4 py-3 text-xs text-danger leading-relaxed">{error}</p>
            ) : !bundle ? (
              <p className="px-4 py-3 font-mono text-2xs text-content-muted">Compiling for {siem}…</p>
            ) : queries.length === 0 ? (
              <div className="p-4">
                <p className="text-sm text-content-primary">{siem} cannot express this detection</p>
                <p className="text-xs text-content-dim leading-relaxed mt-1.5">
                  {plainReason(reasons, siem)} Try another SIEM if you run one, or build it by hand from the rule.
                </p>
                <TechnicalDetail reasons={reasons} />
              </div>
            ) : (
              <>
                {queries.map((query, index) => {
                  const id = `${selected.ruleId}-${index}`
                  return (
                    <div key={`${query.sigmaId}-${index}`} className={`px-4 py-3 ${index ? 'border-t border-border' : ''}`}>
                      <div className="flex items-center justify-between gap-3 mb-2">
                        <span className="truncate text-xs text-content-secondary">
                          {shortTitle(query.title || selected.title)}
                        </span>
                        <button
                          type="button"
                          onClick={() => copy(id, query.query)}
                          className={`shrink-0 font-mono text-2xs transition-opacity hover:opacity-60 ${
                            copied === id ? 'text-safe' : 'text-content-dim'
                          }`}
                        >
                          {copied === id ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                      <pre className="font-mono text-2xs leading-relaxed text-content-secondary whitespace-pre-wrap break-words max-h-56 overflow-auto">
                        {query.query}
                      </pre>
                    </div>
                  )
                })}
                {/* A rule can convert in part: its base query compiles while a
                    correlation beside it cannot. Saying so keeps an engineer
                    from believing the deployed query is the whole detection. */}
                {reasons.length > 0 && (
                  <div className="px-4 py-3 border-t border-border">
                    <p className="text-xs text-warning">Part of this detection could not be converted</p>
                    <p className="text-xs text-content-dim leading-relaxed mt-1">{plainReason(reasons, siem)}</p>
                    <TechnicalDetail reasons={reasons} />
                  </div>
                )}
              </>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 mt-4">
            <span className="text-xs text-content-dim tracking-body">
              Once deployed, a new run shows whether {many ? 'they fire' : 'it fires'}.
            </span>
            {/* Opens the start form with this emulation chosen rather than
                starting a run: a run deploys real infrastructure in the
                customer's account, which one click here should not do. */}
            <button
              type="button"
              onClick={() => navigate(`/workflows?start=${encodeURIComponent(run.emulationType)}`)}
              className={`${BUTTON} border border-white/15 text-content-primary`}
            >
              Run this workflow again
            </button>
          </div>
        </div>
      </div>
    </section>
  )
}

/** A numbered step heading. */
function StepHead({ number, children }: { number: number; children: string }) {
  return (
    <div className="flex items-center gap-2.5 mb-3">
      <span className="w-5 h-5 rounded-full border border-border flex items-center justify-center font-mono text-2xs text-content-secondary">
        {number}
      </span>
      <span className="text-xs font-medium tracking-body text-content-primary">{children}</span>
    </div>
  )
}

/** The converter's own messages, folded away for whoever needs them. */
function TechnicalDetail({ reasons }: { reasons: string[] }) {
  if (reasons.length === 0) return null
  return (
    <details className="mt-3">
      <summary className="text-xs text-content-secondary cursor-pointer transition-opacity hover:opacity-60">
        Technical detail
      </summary>
      <pre className="mt-2 font-mono text-2xs text-content-dim whitespace-pre-wrap break-words">{reasons.join('\n')}</pre>
    </details>
  )
}
