import type { LogEntry, LogEvent } from '@/types/log'

/**
 * Presentation logic for the activity trail, kept out of the panel.
 *
 * Every event the backend emits has to answer two questions here: what does it
 * look like, and where does clicking it take the reader. An unrecognised event
 * still renders, because the type is deliberately open and a new backend event
 * should degrade to a plain row rather than crash the panel.
 */

export type ActivityTone = 'neutral' | 'blue' | 'green' | 'red' | 'amber'

interface EventMeta {
  /** Short label above the message, naming the kind of thing that happened. */
  label: string
  tone: ActivityTone
}

const EVENT_META: Record<string, EventMeta> = {
  'stack.deployed': { label: 'Stack ready', tone: 'green' },
  'stack.destroyed': { label: 'Stack destroyed', tone: 'neutral' },
  'stack.failed': { label: 'Stack failed', tone: 'red' },
  'emulation.started': { label: 'Emulation started', tone: 'blue' },
  'emulation.completed': { label: 'Emulation finished', tone: 'green' },
  'emulation.failed': { label: 'Emulation failed', tone: 'red' },
  'workflow.started': { label: 'Workflow started', tone: 'blue' },
  'workflow.completed': { label: 'Workflow finished', tone: 'green' },
  'workflow.failed': { label: 'Workflow failed', tone: 'red' },
  'playbook.command': { label: 'Playbook command', tone: 'neutral' },
}

/**
 * Describe one event for the panel.
 *
 * @param event - The event name from the API.
 * @param level - The entry's severity, used when the event is unrecognised.
 * @returns A label and a tone. An unknown event falls back to its own name,
 *   which is more use to a reader than a generic "Activity".
 */
export function eventMeta(event: LogEvent, level: string): EventMeta {
  const known = EVENT_META[event]
  if (known) return known
  return {
    label: event.replace(/[._]/g, ' '),
    tone: level === 'error' ? 'red' : level === 'warning' ? 'amber' : 'neutral',
  }
}

/** Text colour per tone, used for the label and the leading dot. */
export const TONE_CLASS: Record<ActivityTone, string> = {
  neutral: 'text-content-dim',
  blue: 'text-accent-blue',
  green: 'text-safe',
  red: 'text-danger',
  amber: 'text-warning',
}

/**
 * Where a row should take the reader.
 *
 * A stack is the most specific target available, and the stacks page opens the
 * matching panel from `?stack=`. Everything else lands on the section that owns
 * the event. `LogEntry` carries no target id of its own, and adding one would
 * mean a schema change to an app whose migrations are regenerated at container
 * boot, so section-level links are the honest ceiling here.
 *
 * @param entry - The activity entry.
 * @returns A router path.
 */
export function activityHref(entry: LogEntry): string {
  if (entry.stack) return `/stacks?stack=${entry.stack}`
  if (entry.event.startsWith('workflow.')) return '/workflows'
  if (entry.event.startsWith('emulation.')) return '/runs'
  if (entry.event.startsWith('playbook.')) return '/playbooks'
  return '/stacks'
}

/**
 * Count entries the reader has not seen.
 *
 * @param entries - Activity newest-first.
 * @param lastSeen - ISO timestamp of the last time the panel was opened.
 * @returns How many arrived since. Everything counts on a first visit, which
 *   is why the marker is written when the panel is first opened rather than on
 *   mount: a new user should see that the platform has a history.
 */
export function unseenCount(entries: LogEntry[], lastSeen: string | null): number {
  if (!lastSeen) return entries.length
  const marker = new Date(lastSeen).getTime()
  if (Number.isNaN(marker)) return entries.length
  return entries.filter((entry) => new Date(entry.timestamp).getTime() > marker).length
}
