import { useEffect, useState } from 'react'
import type { DetectionExportBundle, DetectionTarget } from '@/types'
import { exportWorkflowGap, listDetectionTargets } from '@/services/detectionExport.service'

/**
 * The detections this run's SIEM missed, compiled for that SIEM.
 *
 * Where the validation loop closes. A workflow ends by saying two expected
 * detections never reported; on its own that is a finding with no action
 * attached. This hands back those two as queries the customer can deploy, so
 * the next run can prove the gap is shut.
 *
 * Rendered only when something was actually silent. A run where everything
 * fired has nothing to fix, and a run with no alert endpoint measured nothing,
 * so offering a download in either case would invent work.
 */

interface CloseTheGapProps {
  workflowId: string
  /** How many rules the run judged silent, from the score. */
  silentCount: number
}

/**
 * Flatten a bundle into the text the copy button puts on the clipboard.
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

export function CloseTheGap({ workflowId, silentCount }: CloseTheGapProps) {
  const [targets, setTargets] = useState<DetectionTarget[] | null>(null)
  const [target, setTarget] = useState<string>('')
  const [format, setFormat] = useState<string>('')
  const [bundle, setBundle] = useState<DetectionExportBundle | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

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

  async function compile() {
    if (!target || loading) return
    setLoading(true)
    setError(null)
    try {
      setBundle(await exportWorkflowGap(workflowId, target, format))
    } catch (caught) {
      const detail = (caught as { response?: { data?: { detail?: string } } })
        .response?.data?.detail
      setError(detail ?? 'Could not compile these rules.')
    } finally {
      setLoading(false)
    }
  }

  if (silentCount === 0) return null

  const active = targets?.find((row) => row.name === target)

  return (
    <section>
      <h3 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-2.5">
        Close the gap
      </h3>

      <p className="text-xs text-content-secondary leading-relaxed mb-3">
        {silentCount} expected detection{silentCount === 1 ? '' : 's'} stayed silent during this
        run. Compile {silentCount === 1 ? 'it' : 'them'} for your SIEM, deploy, then run this
        workflow again to confirm.
      </p>

      {targets === null ? (
        <p className="font-mono text-2xs text-content-muted">Loading targets…</p>
      ) : targets.length === 0 ? (
        <p className="text-xs text-content-dim">No conversion targets are available.</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-1.5 mb-2.5">
            {targets.map((row) => (
              <button
                key={row.name}
                type="button"
                disabled={!row.installed}
                title={row.installed ? undefined : `Backend not installed: ${row.install}`}
                onClick={() => {
                  setTarget(row.name)
                  setFormat(row.formats[0] ?? 'default')
                  setBundle(null)
                }}
                className={`px-2.5 py-1 rounded-btn font-mono text-2xs border transition-opacity
                  hover:opacity-60 disabled:opacity-30 disabled:cursor-not-allowed
                  ${row.name === target
                    ? 'border-accent-blue text-accent-blue bg-accent-blue/[0.08]'
                    : 'border-border text-content-secondary'}`}
              >
                {row.label}
              </button>
            ))}
          </div>

          {active && active.formats.length > 1 && (
            <div className="flex flex-wrap items-center gap-1.5 mb-2.5">
              {active.formats.map((name) => (
                <button
                  key={name}
                  type="button"
                  onClick={() => {
                    setFormat(name)
                    setBundle(null)
                  }}
                  className={`px-2.5 py-1 rounded-btn font-mono text-2xs border transition-opacity
                    hover:opacity-60
                    ${name === format
                      ? 'border-border-active text-content-primary'
                      : 'border-border text-content-muted'}`}
                >
                  {name}
                </button>
              ))}
            </div>
          )}

          <button
            type="button"
            onClick={compile}
            disabled={loading || !target}
            className="px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn border border-border
              text-content-primary shadow-button transition-opacity hover:opacity-60
              disabled:opacity-30 disabled:cursor-not-allowed"
          >
            {loading ? 'Compiling…' : bundle ? 'Recompile' : 'Compile for my SIEM'}
          </button>
        </>
      )}

      {error && <p className="text-xs text-danger mt-2.5 leading-relaxed">{error}</p>}

      {bundle && (
        <div className="mt-3">
          <div className="flex items-center gap-2 mb-1.5">
            <span className="font-mono text-2xs text-content-muted">
              {bundle.queries.length} compiled
              {bundle.skipped.length > 0 ? `, ${bundle.skipped.length} skipped` : ''}
            </span>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard?.writeText(bundleText(bundle))
                setCopied(true)
                window.setTimeout(() => setCopied(false), 1500)
              }}
              className={`ml-auto px-2.5 py-1 rounded-btn font-mono text-2xs border border-border
                transition-opacity hover:opacity-60
                ${copied ? 'text-safe' : 'text-content-secondary'}`}
            >
              {copied ? 'copied' : 'copy'}
            </button>
          </div>

          {/* One block per rule, titled. A single blob would be shorter to
              render and useless to read: the engineer has to know which query
              closes which gap. */}
          <div className="flex flex-col gap-2 max-h-72 overflow-y-auto">
            {bundle.queries.map((entry) => (
              <div key={`${entry.ruleId}-${entry.sigmaId}`}>
                <span className="block text-xs text-content-secondary mb-1">{entry.title}</span>
                <pre
                  className="bg-surface-deep border border-border rounded-btn p-2.5 font-mono
                    text-2xs leading-relaxed text-content-secondary overflow-x-auto
                    whitespace-pre-wrap break-words"
                >
                  {entry.query}
                </pre>
              </div>
            ))}
          </div>

          {bundle.skipped.length > 0 && (
            /* Reported, never dropped. A bundle that silently swallowed a rule
               would leave a detection engineer believing they have coverage
               they do not have. */
            <div className="mt-2.5 border border-warning/25 bg-warning/[0.05] rounded-btn p-3">
              <p className="font-mono text-2xs uppercase tracking-label text-warning mb-2">
                {bundle.skipped.length} could not be converted
              </p>
              {bundle.skipped.map((row) => (
                <div key={row.ruleId} className="mb-1.5 last:mb-0">
                  <span className="block font-mono text-2xs text-content-secondary">
                    {row.ruleId}
                  </span>
                  <span className="block text-xs text-content-dim leading-relaxed">
                    {row.reason}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  )
}
