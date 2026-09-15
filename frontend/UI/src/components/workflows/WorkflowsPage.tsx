import { useMemo, useState } from 'react'
import { useEmulations } from '@/hooks/usePlatformData'
import { useAlertEndpoints, useWorkflowRuns } from '@/hooks/useWorkflows'
import { startWorkflowRun } from '@/services/workflow.service'
import { Card } from '@/components/ui/Card'
import { Combobox, type ComboboxOption } from '@/components/ui/Combobox'
import { severityColorClass } from '@/components/ui/SeverityBadge'
import type { Emulation } from '@/types'
import { EndpointsSection } from './EndpointsSection'
import { RunsSection } from './RunsSection'

/**
 * Workflows, the detection-validation pipeline.
 *
 * A workflow runs an emulation in the customer's account and reports which of
 * that emulation's expected detections their own SIEM actually caught. Running
 * the attack alone tells them nothing; their SIEM's response to it is the
 * finding.
 *
 * Split into two tabs because the surfaces have different lifetimes. Endpoints
 * are configuration, set once and rarely revisited; runs are the working
 * history. Sharing one scroll meant a team with several SIEMs pushed their own
 * results off the page.
 */

/** Refresh cadence while at least one run is still moving. */
const LIST_POLL_MS = 20_000

/*
 * Catalogue headings, most consequential first. A campaign deploys a multi
 * stage attack and is the run a detection engineer wants; the forty atomic
 * techniques are one API call each and would otherwise bury the four campaigns
 * in an alphabetical list. The values are the MANIFEST origin_label verbatim,
 * so an emulation whose label is not listed here simply sorts to the end
 * rather than disappearing.
 */
const GROUP_LABELS: Record<string, string> = {
  'APT EMULATION': 'Campaign emulations',
  'RESEARCH POC': 'Research proof of concept',
  'K8S EMULATION': 'Kubernetes emulations',
  'ATOMIC TECHNIQUE': 'Atomic techniques',
}

const GROUP_ORDER = Object.values(GROUP_LABELS)

/**
 * The current local time, formatted for a datetime-local input's `min`.
 *
 * The input takes and returns wall-clock time with no zone, so the bound has to
 * be built from the reader's own clock rather than from an ISO string.
 *
 * @returns A value such as "2026-09-15T13:45".
 */
function localNow(): string {
  const now = new Date()
  const offset = now.getTimezoneOffset() * 60_000
  return new Date(now.getTime() - offset).toISOString().slice(0, 16)
}

/** Services listed in full would wrap the row; AMBERSQUID names twelve. */
const MAX_SERVICES_SHOWN = 3

/**
 * Describe one emulation as a row in the search dropdown.
 *
 * Everything here is already on the catalogue response, so the richer row costs
 * no extra request. The facts chosen are the ones that separate rows a reader
 * cannot otherwise tell apart: six emulations are named some variant of
 * "Backdoor IAM ...", and only the severity and technique count say which is
 * worth a run.
 *
 * @param emulation - A catalogue entry from GET /api/emulations/.
 * @returns The option, grouped by its origin label.
 */
function toOption(emulation: Emulation): ComboboxOption {
  const services = emulation.services ?? []
  const shown = services.slice(0, MAX_SERVICES_SHOWN).join(' ')
  const hidden = services.length - MAX_SERVICES_SHOWN

  const meta: string[] = []
  if (emulation.tags[0]) meta.push(emulation.tags[0])
  if (shown) meta.push(hidden > 0 ? `${shown} +${hidden}` : shown)
  meta.push(emulation.techniqueCount === 1 ? '1 technique' : `${emulation.techniqueCount} techniques`)

  return {
    value: emulation.id,
    label: emulation.name,
    hint: emulation.id,
    group: GROUP_LABELS[emulation.originLabel] ?? emulation.originLabel,
    meta,
    // An emulation whose MANIFEST omits a severity serialises as an empty
    // string, and an empty chip reads as a missing value rather than a low one.
    badge: emulation.severity ? (
      <span
        className={`font-mono text-2xs uppercase tracking-caps ${severityColorClass(emulation.severity)}`}
      >
        {emulation.severity}
      </span>
    ) : undefined,
  }
}

type Tab = 'runs' | 'endpoints'

export function WorkflowsPage() {
  const [tab, setTab] = useState<Tab>('runs')
  // Bumped after a mutation. It forms part of each hook's cache key, so the
  // data refetches without remounting anything, which is what an earlier
  // version did and why a newly created secret vanished before it rendered.
  const [version, setVersion] = useState(0)

  const { data: runs, loading } = useWorkflowRuns(LIST_POLL_MS, version)
  const { data: endpoints, loading: endpointsLoading } = useAlertEndpoints(version)
  const { data: emulations } = useEmulations('aws')

  const [selected, setSelected] = useState('')
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Empty means start now. A datetime-local value carries no timezone, so it is
  // read as the reader's own clock and converted on submit.
  const [scheduledFor, setScheduledFor] = useState('')
  const [scheduling, setScheduling] = useState(false)

  const list = useMemo(() => runs ?? [], [runs])
  const hasEndpoint = (endpoints?.length ?? 0) > 0

  async function start() {
    if (!selected || starting) return
    if (scheduling && !scheduledFor) {
      setError('Choose a date and time, or switch back to starting now.')
      return
    }
    setStarting(true)
    setError(null)
    try {
      // new Date() on a datetime-local string reads it in the reader's timezone,
      // and toISOString converts to UTC, which is what the API stores.
      const when = scheduling && scheduledFor
        ? new Date(scheduledFor).toISOString()
        : undefined
      await startWorkflowRun(selected, when)
      setScheduledFor('')
      setScheduling(false)
      setVersion((current) => current + 1)
    } catch (caught) {
      const detail = (caught as { response?: { data?: { detail?: string } } })
        .response?.data?.detail
      setError(detail ?? 'Could not start the workflow.')
    } finally {
      setStarting(false)
    }
  }

  return (
    <div className="animate-fadeIn flex flex-col gap-5">
      <div>
        <div className="font-mono text-2xs uppercase tracking-label text-accent-blue font-medium mb-2">
          Operations
        </div>
        <h1 className="font-display text-2xl font-semibold text-content-primary leading-tight">
          Workflows
        </h1>
        <p className="text-sm text-content-dim mt-1">
          Run an emulation and find out which of its expected detections your SIEM caught
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2" role="tablist" aria-label="Workflows view">
        <TabButton id="runs" active={tab} count={list.length} onSelect={setTab}>
          Runs
        </TabButton>
        <TabButton
          id="endpoints"
          active={tab}
          count={endpoints?.length ?? 0}
          onSelect={setTab}
        >
          Endpoints
        </TabButton>
      </div>

      {tab === 'runs' ? (
        <>
          <Card className="p-5">
            <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-3">
              Start a workflow
            </h2>
            <div className="flex flex-wrap items-center gap-2">
              {/* Fifty emulations is too many to recognise in a dropdown, so
                  this filters as you type. The registry id distinguishes the
                  several near-identical IAM techniques from one another, and
                  the severity and technique count say which of them is worth
                  the run. All of it is already on the catalogue response. */}
              <Combobox
                options={(emulations ?? []).map(toOption)}
                value={selected}
                onChange={setSelected}
                placeholder="Search emulations…"
                ariaLabel="Choose an emulation to validate"
                groupOrder={GROUP_ORDER}
                noun="emulations"
                emptyHint="Names and registry ids are searched, not services or tactics."
              />
              {scheduling && (
                <input
                  type="datetime-local"
                  value={scheduledFor}
                  min={localNow()}
                  onChange={(event) => setScheduledFor(event.target.value)}
                  aria-label="Date and time to start the workflow"
                  className="bg-surface-base border border-border rounded-btn px-3 py-2
                    text-sm text-content-primary outline-none transition-colors
                    focus:border-border-active"
                />
              )}

              <button
                type="button"
                onClick={start}
                disabled={!selected || starting}
                className="px-4 py-2 rounded-btn text-sm font-medium tracking-btn border border-border
                  text-content-primary shadow-button transition-opacity hover:opacity-60
                  disabled:opacity-30 disabled:cursor-not-allowed"
              >
                {starting
                  ? 'Starting…'
                  : scheduling
                    ? 'Schedule workflow'
                    : 'Start workflow'}
              </button>

              {/* A secondary action, so it reads as the alternative to the
                  primary button rather than competing with it. */}
              <button
                type="button"
                onClick={() => {
                  setScheduling((current) => !current)
                  setScheduledFor('')
                  setError(null)
                }}
                className="px-3 py-2 rounded-btn text-xs tracking-btn text-content-dim
                  transition-opacity hover:opacity-60"
              >
                {scheduling ? 'Start now instead' : 'Schedule for later'}
              </button>
            </div>
            {/* Said before the run, not after it reports nothing. */}
            {!endpointsLoading && !hasEndpoint && (
              <p className="text-xs text-warning mt-2">
                No alert endpoint is configured yet. A workflow will still run, but it cannot
                report which detections your SIEM caught until one exists.
              </p>
            )}
            <p className="text-xs text-content-dim mt-2">
              This deploys real infrastructure into your connected account and runs a real attack
              against it.
            </p>
            {error && <p className="text-xs text-danger mt-2">{error}</p>}
          </Card>

          <RunsSection
            runs={list}
            loading={loading}
            onChanged={() => setVersion((current) => current + 1)}
          />
        </>
      ) : (
        <EndpointsSection
          endpoints={endpoints}
          loading={endpointsLoading}
          onCreated={() => setVersion((current) => current + 1)}
        />
      )}
    </div>
  )
}

interface TabButtonProps {
  id: Tab
  active: Tab
  count: number
  onSelect: (tab: Tab) => void
  children: React.ReactNode
}

function TabButton({ id, active, count, onSelect, children }: TabButtonProps) {
  const selected = active === id
  return (
    <button
      type="button"
      role="tab"
      aria-selected={selected}
      onClick={() => onSelect(id)}
      className={`px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn border
        transition-opacity hover:opacity-60
        ${selected
          ? 'border-border-active bg-surface-card text-content-primary'
          : 'border-border bg-transparent text-content-secondary'}`}
    >
      {children}
      <span className="ml-1.5 font-mono text-content-dim">{count}</span>
    </button>
  )
}
