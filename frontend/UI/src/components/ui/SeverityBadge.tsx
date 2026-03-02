import type { Severity } from '@/types'

const severityColors: Record<Severity, string> = {
  CRITICAL: 'text-danger',
  HIGH: 'text-orange',
  MEDIUM: 'text-content-secondary',
  LOW: 'text-content-dim',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`font-mono text-xs font-bold ${severityColors[severity]}`}>
      {severity}
    </span>
  )
}

export function severityColorClass(severity: Severity): string {
  return severityColors[severity]
}
