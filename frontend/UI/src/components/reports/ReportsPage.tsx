import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import type { WorkflowRun } from '@/types/workflow'
import { useWorkflowRuns } from '@/hooks/useWorkflows'
import { Card } from '@/components/ui/Card'
import { IconChevron } from '@/components/ui/Icons'
import { formatCoverage } from '@/components/workflows/workflowMeta'
import { formatWhen } from '@/components/threatfeed/feedMeta'

/**
 * Every run that produced an evidence packet.
 *
 * Lists settled workflow runs only. A run still collecting alerts has nothing
 * to report, and offering it here would hand a reader a document that says
 * "nothing has been measured yet" over a link that promised a report.
 *
 * Replaces a ComingSoon stub that stood here while the product promised a
 * signed evidence packet as the deliverable of every run.
 */

/** Refresh cadence. Reports change only when a run settles, so this is slow. */
const POLL_MS = 60_000

export function ReportsPage() {
  const { data: runs, loading } = useWorkflowRuns(POLL_MS, 0)

  // Only a settled run has verdicts. Failed runs are listed too: "it failed at
  // the attack step" is itself a finding somebody may need to evidence.
  const reportable = useMemo(
    () => (runs ?? []).filter((run) => run.status === 'completed' || run.status === 'failed'),
    [runs],
  )

  return (
    <div className="animate-fadeIn">
      <div className="mb-6">
        <div className="font-mono text-2xs uppercase tracking-label text-accent-blue mb-2">
          Administration
        </div>
        <h1 className="font-display text-2xl font-semibold text-content-primary leading-tight">
          Reports
        </h1>
        <p className="text-sm text-content-dim mt-1.5">
          The evidence packet from each validation run: per-rule verdicts, the alert behind every
          one, and the techniques nothing is watching
        </p>
      </div>

      <Card className="p-5">
        {loading && reportable.length === 0 ? (
          <div className="py-10 text-center font-mono text-xs text-content-dim">Loading…</div>
        ) : reportable.length === 0 ? (
          <div className="py-10 text-center">
            <p className="text-sm text-content-secondary">No run has produced a report yet.</p>
            <p className="text-xs text-content-dim mt-1.5 leading-relaxed max-w-[52ch] mx-auto">
              A report is written when a workflow settles, once its alert window has closed.
            </p>
            <Link
              to="/workflows"
              className="inline-block mt-4 px-3 py-1.5 rounded-btn font-mono text-2xs uppercase
                tracking-label border border-border-active text-content-primary no-underline
                transition-opacity hover:opacity-60"
            >
              Start a workflow
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[680px]">
              <thead>
                <tr className="font-mono text-2xs uppercase tracking-caps text-content-dim">
                  <th className="font-normal pb-2 pr-3">Emulation</th>
                  <th className="font-normal pb-2 pr-3">Result</th>
                  <th className="font-normal pb-2 pr-3 text-right">Coverage</th>
                  <th className="font-normal pb-2 pr-3 text-right">Reported</th>
                  <th className="font-normal pb-2 text-right">When</th>
                </tr>
              </thead>
              <tbody>
                {reportable.map((run) => <ReportRow key={run.id} run={run} />)}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

/** One run, linking to its packet. */
function ReportRow({ run }: { run: WorkflowRun }) {
  const fired = run.score?.counts.fired ?? 0
  const total = run.score?.ruleCount ?? 0

  return (
    <tr className="group border-t border-border align-middle">
      <td className="py-3 pr-3">
        <Link
          to={`/reports/${run.id}`}
          className="flex items-center gap-1.5 no-underline transition-opacity hover:opacity-75"
        >
          <span className="text-xs font-medium tracking-body text-content-primary
            transition-colors group-hover:text-accent-blue">
            {run.emulationType}
          </span>
          <span className="text-accent-blue opacity-0 transition-opacity group-hover:opacity-100">
            <IconChevron size={12} />
          </span>
        </Link>
      </td>
      <td className="py-3 pr-3 text-xs text-content-secondary leading-relaxed max-w-[320px]">
        {run.summary || run.detail || '—'}
      </td>
      <td className="py-3 pr-3 text-right font-mono text-xs text-content-secondary whitespace-nowrap">
        {run.score ? formatCoverage(run.score.detectionCoverage) : '—'}
      </td>
      <td className="py-3 pr-3 text-right font-mono text-xs text-content-secondary whitespace-nowrap">
        {total ? `${fired} of ${total}` : '—'}
      </td>
      <td className="py-3 text-right font-mono text-2xs text-content-muted whitespace-nowrap">
        {formatWhen(run.completedAt ?? run.createdAt)}
      </td>
    </tr>
  )
}
