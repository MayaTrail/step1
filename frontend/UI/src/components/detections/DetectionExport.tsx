import { useEffect, useState } from 'react'

import {
  downloadEmulationDetections,
  downloadRunDetections,
  exportEmulationDetections,
  exportRunDetections,
  listDetectionTargets,
  type ExportVerdict,
} from '@/services/detectionExport.service'
import type { DetectionExportBundle, DetectionTarget } from '@/types'

/**
 * Compile detection rules into a SIEM dialect and download them.
 *
 * Two modes, one component:
 *   scope="emulation"  every Sigma rule the emulation ships (or a subset)
 *   scope="run"        only the rules a run judged with the given verdicts
 *
 * The run mode is the one that earns its place. A run says "three rules stayed
 * silent"; that is a finding with no action attached. Handing back exactly
 * those three, in the language the customer's SIEM speaks, is the action.
 *
 * The result always reports what did NOT convert. A bundle that quietly
 * omitted rules would be worse than no bundle: the engineer deploys it
 * believing they have coverage they do not have.
 */

interface Common {
  /** Bold header shown above the control, so it reads as a capability. */
  heading?: string
  /** One line under the heading explaining what it does. */
  blurb?: string
}

type Props = Common &
  (
    | {
        scope: 'emulation'
        emulationType: string
        ruleIds?: string[]
        runId?: never
        verdicts?: never
      }
    | {
        scope: 'run'
        runId: string
        verdicts?: ExportVerdict[]
        emulationType?: never
        ruleIds?: never
      }
  )

export function DetectionExport(props: Props) {
  const [targets, setTargets] = useState<DetectionTarget[] | null>(null)
  const [target, setTarget] = useState<string>('')
  const [bundle, setBundle] = useState<DetectionExportBundle | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    listDetectionTargets()
      .then((rows) => {
        if (cancelled) return
        setTargets(rows)
        // Default to the first target that can actually compile here.
        setTarget(rows.find((t) => t.installed)?.name ?? rows[0]?.name ?? '')
      })
      .catch(() => {
        if (!cancelled) setTargets([])
      })
    return () => {
      cancelled = true
    }
  }, [])

  const selected = targets?.find((t) => t.name === target)

  function describeError(err: unknown): string {
    const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data
      ?.detail
    return detail || (err instanceof Error ? err.message : 'Export failed.')
  }

  async function preview() {
    setBusy(true)
    setError(null)
    setBundle(null)
    try {
      const result =
        props.scope === 'run'
          ? await exportRunDetections(props.runId, target, props.verdicts ?? ['silent'])
          : await exportEmulationDetections(props.emulationType, target, props.ruleIds)
      setBundle(result)
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }

  async function save() {
    setBusy(true)
    setError(null)
    try {
      if (props.scope === 'run') {
        await downloadRunDetections(props.runId, target, props.verdicts ?? ['silent'])
      } else {
        await downloadEmulationDetections(props.emulationType, target, props.ruleIds)
      }
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }

  if (targets === null) {
    return (
      <div className="font-mono text-2xs text-content-dim">Loading export targets...</div>
    )
  }
  if (targets.length === 0) {
    return null
  }

  return (
    <div className="flex flex-col gap-3">
      {(props.heading || props.blurb) && (
        <div>
          {props.heading && (
            <div className="text-[0.9rem] font-semibold text-content-primary">
              {props.heading}
            </div>
          )}
          {props.blurb && (
            <div className="text-[0.8rem] text-content-secondary mt-0.5">{props.blurb}</div>
          )}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
          Export for
        </span>
        <select
          value={target}
          onChange={(e) => {
            setTarget(e.target.value)
            setBundle(null)
            setError(null)
          }}
          className="bg-surface-base border border-border rounded-btn px-2.5 py-1.5 text-[0.82rem] text-content-primary focus:outline-none focus:border-accent-blue"
        >
          {targets.map((t) => (
            <option key={t.name} value={t.name}>
              {t.label}
              {t.installed ? '' : ' (unavailable)'}
            </option>
          ))}
        </select>

        <button
          type="button"
          onClick={() => void preview()}
          disabled={busy || !selected?.installed}
          className="border border-border text-content-secondary hover:text-content-primary rounded-btn px-3 py-1.5 text-[0.82rem] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {busy ? 'Compiling...' : 'Preview'}
        </button>
        <button
          type="button"
          onClick={() => void save()}
          disabled={busy || !selected?.installed}
          className="border border-border text-content-primary shadow-button rounded-btn px-3 py-1.5 text-[0.82rem] font-medium tracking-btn transition-opacity hover:opacity-60 disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Download
        </button>
      </div>

      {selected && !selected.installed && (
        <div className="text-[0.8rem] text-content-dim">
          This server cannot compile {selected.label} &mdash;{' '}
          <code className="font-mono text-[0.78rem] text-content-secondary">
            {selected.install}
          </code>{' '}
          is not installed. Every other target still works.
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="border border-danger/40 bg-danger/10 text-danger rounded-btn px-3 py-2 text-[0.82rem]"
        >
          {error}
        </div>
      )}

      {bundle && (
        <div className="border border-border rounded-card bg-surface-card overflow-hidden">
          <div className="flex flex-wrap items-center gap-3 px-4 py-2.5 border-b border-border bg-surface-deep">
            <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
              {bundle.label}
            </span>
            <span className="font-mono text-[0.78rem] text-safe">
              {bundle.counts.converted} converted
            </span>
            {bundle.counts.skipped > 0 && (
              <span className="font-mono text-[0.78rem] text-warning">
                {bundle.counts.skipped} not expressible
              </span>
            )}
            {bundle.counts.missing > 0 && (
              <span className="font-mono text-[0.78rem] text-content-dim">
                {bundle.counts.missing} not in catalogue
              </span>
            )}
          </div>

          {bundle.note && (
            <div className="px-4 py-2 text-[0.8rem] text-content-secondary border-b border-border">
              {bundle.note}
            </div>
          )}

          {(bundle.skipped.length > 0 || bundle.missing.length > 0) && (
            <div className="px-4 py-3 border-b border-border bg-warning/5">
              <div className="font-mono text-2xs uppercase tracking-label text-warning mb-1.5">
                Not in this file
              </div>
              <ul className="text-[0.8rem] text-content-secondary flex flex-col gap-1">
                {bundle.skipped.map((s) => (
                  <li key={`${s.ruleId}-${s.sigmaId}`}>
                    <code className="font-mono text-[0.78rem]">{s.ruleId}</code> &mdash;{' '}
                    {s.reason}
                  </li>
                ))}
                {bundle.missing.map((m) => (
                  <li key={m}>
                    <code className="font-mono text-[0.78rem]">{m}</code> &mdash; the
                    catalogue ships no Sigma rule for this.
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="max-h-[22rem] overflow-y-auto divide-y divide-border">
            {bundle.queries.map((q) => (
              <div key={`${q.ruleId}-${q.sigmaId}`} className="px-4 py-3">
                <div className="flex items-baseline gap-2 mb-1.5">
                  <span className="text-[0.85rem] font-medium text-content-primary">
                    {q.title}
                  </span>
                  <code className="font-mono text-2xs text-content-dim">{q.ruleId}</code>
                </div>
                <pre className="bg-surface-deep border border-border rounded-btn p-2.5 overflow-x-auto text-[0.75rem] text-content-secondary whitespace-pre-wrap break-all">
                  {q.query}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
