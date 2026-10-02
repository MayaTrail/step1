import { useState } from 'react'
import type { WorkflowRunDetail } from '@/types/workflow'
import { Card } from '@/components/ui/Card'
import { formatWhen } from '@/components/threatfeed/feedMeta'

/** Rows shown before the list collapses behind a control. */
const UNATTRIBUTED_PREVIEW = 5

/**
 * Alerts that arrived in the window but map to no expected detection.
 *
 * A busy SIEM can raise hundreds of these during a thirty minute window, which
 * would bury the verdicts above them, so only a few are shown and the rest are
 * behind a control. The count is always the true total, even when the report
 * stores fewer: a trimmed list must never read as a smaller number.
 */
export function UnattributedAlerts({ score }: { score: NonNullable<WorkflowRunDetail['score']> }) {
  const [expanded, setExpanded] = useState(false)
  const stored = score.unattributed
  const shown = expanded ? stored : stored.slice(0, UNATTRIBUTED_PREVIEW)
  const hidden = score.unattributedCount - shown.length

  return (
    <Card className="p-5">
      <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-1">
        Other alerts during this run
        <span className="ml-2 text-content-muted">{score.unattributedCount}</span>
      </h2>
      {/* Shown so a reader can judge them, never counted. They may be the
          customer's own coverage of something we did not expect, or noise from
          real activity that happened to overlap the window. */}
      <p className="text-xs text-content-dim leading-relaxed mb-3">
        Your SIEM sent these while the emulation was running, but they do not map to any
        detection this emulation expects. They are not counted in the score.
      </p>

      <div className="flex flex-col divide-y divide-border">
        {shown.map((alert) => (
          <div key={alert.alertId} className="py-2">
            <span className="block text-xs text-content-secondary tracking-body">
              {alert.ruleName || alert.ruleId || 'Unnamed alert'}
            </span>
            <span className="block font-mono text-2xs text-content-muted mt-0.5">
              {alert.technique || 'no technique'}
              {alert.receivedAt ? ` · ${formatWhen(alert.receivedAt)}` : ''}
            </span>
          </div>
        ))}
      </div>

      {stored.length > UNATTRIBUTED_PREVIEW && (
        <button
          type="button"
          onClick={() => setExpanded((open) => !open)}
          className="mt-3 text-xs font-medium tracking-btn text-accent-blue
            transition-opacity hover:opacity-60"
        >
          {expanded ? 'Show fewer' : `Show all ${stored.length}`}
        </button>
      )}

      {/* The report keeps a sample, not the whole flood. Saying so is the
          difference between a trimmed list and a wrong one. */}
      {score.unattributedTruncated && expanded && (
        <p className="text-xs text-content-dim leading-relaxed mt-3">
          {hidden > 0 ? `${hidden} further alerts arrived and are not listed here. ` : ''}
          This run stored a sample rather than every alert. The count above is the true total.
        </p>
      )}
    </Card>
  )
}
