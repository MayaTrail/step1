/**
 * The Attack Graph page.
 *
 * Five states, and the distinction between two of them is the reason this
 * feature exists:
 *
 *   queued/running — the scan is waiting for a worker, or reading IAM. The
 *              enterprise queue runs two tasks at a time alongside Pulumi
 *              deploys, so "queued" is a real state, not a flicker.
 *   findings — ranked privilege-escalation chains, drawn.
 *   clean    — a full account scan that found none. Good news, said plainly.
 *   partial  — the scan did not demonstrably see the whole account, so it
 *              found nothing because it could not look. Never worded as good
 *              news. The *reason* branches on envelope.mode: "self" is a
 *              diagnosis Scout reported and the page gives the fix; anything
 *              else is only an absence of information and the page says so
 *              without inventing a cause.
 *   failed   — the scan did not run; the error is shown verbatim.
 *
 * The state is read from envelope.state, which the backend computes. It is
 * not re-derived here.
 */

import { lazy, Suspense, useCallback, useState } from 'react'

import { ConnectPrompt, useScoutConnection } from '@/components/common/ConnectGate'
import { ComingSoon } from '@/components/common/ComingSoon'
import { IconBroadcast } from '@/components/ui/Icons'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import { useCachedResource } from '@/hooks/useCachedResource'
import * as attackGraph from '@/services/attackGraph.service'
import type { ScanDetail, ScanEnvelope, ScanState, ScanStatus, ScanSummary } from '@/types/attackGraph'
import { isTooNewToRender } from '@/types/attackGraph'

const AttackChainGraph = lazy(() => import('./AttackChainGraph'))

// A GAAD collection is minutes, and the enterprise worker runs two tasks at a
// time alongside Pulumi deploys, so a scan can legitimately sit queued. Three
// seconds is responsive without hammering a request per second for ten minutes.
const POLL_MS = 3000

// The history strip refreshes more slowly than the live scan does. It only
// has to notice that a scan finished, or that one was started in another tab.
const HISTORY_POLL_MS = 10000

const UNFINISHED: ScanStatus[] = ['pending', 'running']

const STATUS_LABEL: Record<ScanStatus, string> = {
  pending: 'Queued',
  running: 'Scanning',
  completed: 'Completed',
  failed: 'Failed',
}

// Small colored dots for the history strip's status marker — the strip is a
// row of past *scans*, not a set of status filters, so status is secondary
// information here even though it is the headline everywhere else on the page.
const STATUS_DOT: Record<ScanStatus, string> = {
  pending: 'bg-content-dim',
  running: 'bg-accent-blue',
  completed: 'bg-safe',
  failed: 'bg-danger',
}

// What a completed scan's history pill says in place of the status label —
// the outcome, not just that it finished. A row of four "Completed" pills is
// what reads as duplicate tabs; "5 findings" / "Clean" / "Partial" makes each
// one a different scan again.
const STATE_SUMMARY: Record<ScanState, string> = {
  findings: 'Findings',
  clean: 'Clean',
  partial: 'Partial',
}

// Chains are evaluated without AWS Organizations policies applied, so a path
// shown here may in fact be blocked by an SCP the scan never fetched. Shown
// above both the graph and the clean state — it qualifies what "no findings"
// or "these findings" actually mean.
const SCP_CAVEAT = 'Evaluated without AWS Organizations service control policies applied — a path shown here may be blocked by an SCP this scan did not fetch.'

export function AttackGraphHub() {
  const { connected } = useScoutConnection()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)

  // Both reads go through useCachedResource, the hook Active Runs already
  // polls with. It owns the interval, cancels in-flight requests on unmount,
  // swallows a failed poll instead of raising an unhandled rejection, and
  // never blanks what is on screen to re-fetch it. A bespoke
  // useEffect+setInterval here would have to get all four right again.
  const { data: scans } = useCachedResource<ScanSummary[]>(
    connected ? 'attack-graph:scans' : null,
    attackGraph.listScans,
    { pollMs: HISTORY_POLL_MS },
  )

  // Default to the newest scan; the history strip overrides it.
  const viewingId = selectedId ?? scans?.[0]?.id ?? null

  // Whether to poll the detail is read from the *list*, not from the detail
  // itself — a hook cannot key its own options on its own output. The list
  // is the cheaper query (no `result` field) and it is already refreshing.
  // A scan selected but not yet in the list is one Run Scan just created —
  // poll it immediately rather than waiting up to HISTORY_POLL_MS for the
  // list to catch up and admit it exists.
  const viewing = scans?.find((scan) => scan.id === viewingId)
  const live = viewingId !== null && (!viewing || UNFINISHED.includes(viewing.status))

  const { data: current } = useCachedResource<ScanDetail>(
    viewingId ? `attack-graph:scan:${viewingId}` : null,
    () => attackGraph.getScan(viewingId as string),
    // pollMs is a dependency of the hook's effect, so passing undefined
    // clears the interval the moment the scan reaches a terminal status.
    // A completed scan never changes again; polling it is pure waste, and
    // its `result` envelope is the largest response on the page.
    { pollMs: live ? POLL_MS : undefined },
  )

  const runScan = useCallback(async () => {
    setStarting(true)
    setError(null)
    try {
      const { scanId } = await attackGraph.triggerScan()
      setSelectedId(scanId)
    } catch (err: any) {
      // A 409 names the scan already in flight; select it so the user sees
      // what is running rather than a generic failure.
      const inFlight = err?.response?.data?.scanId
      if (inFlight) setSelectedId(inFlight)
      else setError(err?.response?.data?.detail ?? 'Could not start the scan.')
    } finally {
      setStarting(false)
    }
  }, [])

  if (!connected) {
    return (
      <ConnectPrompt
        title="Connect a Scout audit role"
        body={
          'The attack graph reads your account’s IAM configuration through a ' +
          'separate read-only role, so granting it does not widen what emulations can do. ' +
          'Connect one from your profile to run a scan.'
        }
        cta="Connect a Scout audit role"
      />
    )
  }

  const runDisabled = starting || live

  return (
    <div>
      {/* Page header */}
      <div className="mb-6 flex items-start justify-between flex-wrap gap-3">
        <div>
          <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
            Security Content
          </div>
          <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
            Attack Graph
          </div>
          <div className="text-[0.9rem] text-content-secondary mt-1.5">
            Ranked IAM privilege-escalation chains, from a read-only scan of your account
          </div>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          <button
            onClick={runScan}
            disabled={runDisabled}
            className="rounded-btn bg-accent-blue px-4 py-2 text-[13px] font-semibold text-white
              transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {live ? 'Scan Running…' : starting ? 'Starting…' : 'Run Scan'}
          </button>
          {error && <div className="text-[11px] text-danger max-w-xs text-right">{error}</div>}
        </div>
      </div>

      {/* History strip — a row of past scans to click through, not a set of
          status filters. Each pill leads with when it ran (what makes one
          scan a different pill from another); status is a small dot, and a
          completed scan says what it found rather than just that it
          finished — four "Completed" pills in a row is what reads as
          duplicate tabs. */}
      {scans && scans.length > 0 && (
        <div className="flex items-center gap-2 overflow-x-auto pb-2 mb-4">
          {scans.map((scan) => {
            const unfinished = UNFINISHED.includes(scan.status)
            const outcome =
              scan.status === 'completed' && scan.state
                ? STATE_SUMMARY[scan.state]
                : STATUS_LABEL[scan.status]
            return (
              <button
                key={scan.id}
                onClick={() => setSelectedId(scan.id)}
                className={`flex flex-col items-start gap-1 shrink-0 rounded-btn border px-3 py-2 cursor-pointer
                  bg-surface-card transition-colors hover:border-accent-blue/40
                  ${scan.id === viewingId ? 'border-accent-blue' : 'border-border'}`}
              >
                <span className="font-mono text-[11px] text-content-primary font-semibold">
                  {formatWhen(scan.created_at)}
                </span>
                <span className="flex items-center gap-1.5">
                  <span className={`w-1.5 h-1.5 rounded-full ${STATUS_DOT[scan.status]} ${unfinished ? 'animate-pulse' : ''}`} />
                  <span className="font-mono text-[9.5px] text-content-dim uppercase tracking-[0.5px]">
                    {outcome}
                  </span>
                </span>
              </button>
            )
          })}
        </div>
      )}

      {/* Result region */}
      <ResultRegion current={current} hasHistory={Boolean(scans?.length)} />
    </div>
  )
}

function ResultRegion({ current, hasHistory }: { current: ScanDetail | undefined; hasHistory: boolean }) {
  if (!current && !hasHistory) {
    return (
      <ComingSoon
        icon={<IconBroadcast size={28} />}
        title="No scans yet"
        body="Run a scan to see ranked IAM privilege-escalation chains for this account."
      />
    )
  }

  if (!current) return null

  if (current.status === 'pending') {
    return (
      <StateBanner
        tone="neutral"
        title="Queued — waiting for a worker"
        body="The enterprise queue runs two tasks at a time alongside infrastructure deploys, so a scan can sit queued for a moment before it starts."
      />
    )
  }

  if (current.status === 'running') {
    return <StateBanner tone="blue" title="Scanning your account's IAM configuration" body="A full account read can take several minutes." />
  }

  if (current.status === 'failed') {
    return <StateBanner tone="red" title="Scan failed" body={current.error_message || 'The scan failed with no further detail.'} />
  }

  // status === 'completed'
  const result = current.result
  if (!result) {
    // A scan cannot be complete and have nothing to show; if this renders,
    // the task reached "completed" without writing its envelope and the row
    // is lying.
    return <StateBanner tone="red" title="Scan result missing" body="This scan completed but recorded no result. Contact support." />
  }

  if (isTooNewToRender(result)) {
    return (
      <StateBanner
        tone="neutral"
        title="This scan was produced by a newer version of MayaTrail"
        body="Update the app to view it."
      />
    )
  }

  return <CompletedResult result={result} scanId={current.id} />
}

function CompletedResult({ result, scanId }: { result: ScanEnvelope; scanId: string }) {
  const accountLine = (
    <div className="font-mono text-[10px] text-content-dim mb-2">Account {result.account_id}</div>
  )
  // Only relevant when the scan actually reached a verdict — 'partial' already
  // explains its own incompleteness and a second, differently-worded caveat
  // here would muddy that message rather than add to it.
  const regions = result.regions ?? []
  const regionsLine = (
    <div className="font-mono text-[10px] text-content-dim mb-2">
      {regions.length > 0
        ? `Regions scanned: ${regions.join(', ')}`
        : 'IAM only — no regions were scanned, so a path through an actual resource could not be found.'}
    </div>
  )

  if (result.state === 'findings') {
    return (
      <div>
        {accountLine}
        {regionsLine}
        <div className="font-mono text-[10px] text-content-dim mb-3">{SCP_CAVEAT}</div>
        <Suspense fallback={<div className="text-[0.9rem] text-content-secondary">Loading graph…</div>}>
          <AttackChainGraph envelope={result} scanId={scanId} />
        </Suspense>
      </div>
    )
  }

  if (result.state === 'clean') {
    return (
      <div>
        {accountLine}
        {regionsLine}
        <StateBanner
          tone="green"
          title="No privilege-escalation paths found in this account"
          body={SCP_CAVEAT}
        />
      </div>
    )
  }

  // result.state === 'partial' — never the clean copy, never styled as success.
  const selfScoped = result.mode === 'self'
  return (
    <div>
      {accountLine}
      <StateBanner
        tone="yellow"
        title="Partial scan — this result does not cover your whole account"
        body={
          selfScoped
            ? "Scout could only enumerate the role it assumed. Its policy no longer grants iam:GetAccountAuthorizationDetails — reconnect the Scout audit role from your profile after fixing its permissions."
            : 'Scout did not report how much of the account it was able to read, so this result is not treated as complete.'
        }
      />
    </div>
  )
}

function StateBanner({
  tone, title, body,
}: { tone: 'neutral' | 'blue' | 'green' | 'red' | 'yellow'; title: string; body: string }) {
  const border: Record<typeof tone, string> = {
    neutral: 'border-border',
    blue: 'border-accent-blue/30',
    green: 'border-safe/30',
    red: 'border-danger/30',
    yellow: 'border-warning/30',
  }
  return (
    <div className={`rounded-card border ${border[tone]} bg-surface-card px-5 py-8 text-center`}>
      <div className="font-display text-base font-semibold text-content-primary mb-1.5">{title}</div>
      <div className="text-[0.85rem] text-content-secondary leading-relaxed max-w-lg mx-auto">{body}</div>
    </div>
  )
}
