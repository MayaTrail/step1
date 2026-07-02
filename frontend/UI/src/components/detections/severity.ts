/**
 * Sigma severity level to semantic color classes, consistent with LibraryCard's
 * per-severity accents. Class strings are kept literal so Tailwind's content
 * scanner does not purge them.
 */
const TEXT_CLASS: Record<string, string> = {
  CRITICAL: 'text-danger',
  HIGH: 'text-warning',
  MEDIUM: 'text-accent-blue',
  LOW: 'text-content-dim',
  INFORMATIONAL: 'text-content-dim',
}

const DOT_CLASS: Record<string, string> = {
  CRITICAL: 'bg-danger',
  HIGH: 'bg-warning',
  MEDIUM: 'bg-accent-blue',
  LOW: 'bg-content-dim',
  INFORMATIONAL: 'bg-content-dim',
}

export function severityTextClass(level: string): string {
  return TEXT_CLASS[level.toUpperCase()] ?? 'text-content-secondary'
}

export function severityDotClass(level: string): string {
  return DOT_CLASS[level.toUpperCase()] ?? 'bg-content-dim'
}
