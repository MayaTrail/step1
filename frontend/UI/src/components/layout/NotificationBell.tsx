import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useCachedResource } from '@/hooks/useCachedResource'
import { listLogs } from '@/services/log.service'
import type { LogEntry } from '@/types/log'
import { IconBell } from '@/components/ui/Icons'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import { activityHref, eventMeta, TONE_CLASS, unseenCount } from './activityMeta'

/**
 * Activity notifications: what the platform did, and what it is doing.
 *
 * Replaces a bell that reported only the threat feed. Feed updates are content
 * the platform fetched; stack, emulation and workflow events are the reader's
 * own work finishing or failing while they were on another page. They are
 * different questions, so the feed count moved to its own sidebar entry and
 * this carries activity alone.
 *
 * No backend work beyond writing the events. `LogEntry` has always declared
 * stack and emulation transitions in its Event enum and has always been served
 * owner-scoped at /api/logs/; it simply had one write site. This reads what
 * that trail now records.
 */

/** Where the last-seen marker lives. Per browser, never sent anywhere. */
const LAST_SEEN_KEY = 'mayatrail.activity.lastSeenAt'

/** Entries pulled for the panel. Enough to count against, few enough to be cheap. */
const FETCH_LIMIT = 40

/** Rows listed inside the panel before the reader is sent to the full page. */
const PREVIEW_COUNT = 6

/** How often the trail is refetched while a page is open. */
const POLL_MS = 30_000

/**
 * Read the last-seen marker.
 *
 * Storage can throw outright in a private window or when site data is blocked,
 * so every access is guarded and a failure degrades to "never looked".
 */
function readLastSeen(): string | null {
  try {
    return window.localStorage.getItem(LAST_SEEN_KEY)
  } catch {
    return null
  }
}

/** Write the last-seen marker, ignoring storage failures. */
function writeLastSeen(value: string): void {
  try {
    window.localStorage.setItem(LAST_SEEN_KEY, value)
  } catch {
    // A reader who cannot persist the marker simply sees no unread count.
  }
}

export function NotificationBell() {
  const [open, setOpen] = useState(false)
  const [lastSeen, setLastSeen] = useState<string | null>(readLastSeen)
  const rootRef = useRef<HTMLDivElement>(null)

  const { data } = useCachedResource<LogEntry[]>(
    'activity-bell',
    () => listLogs(FETCH_LIMIT),
    { pollMs: POLL_MS },
  )

  const entries = useMemo(() => data ?? [], [data])

  /*
   * Returns 0 while the trail is loading rather than a guess. An earlier bell
   * counted an absent response as "stale" and flashed a red dot on every page
   * load for a condition that was never true.
   */
  const unseen = data ? unseenCount(entries, lastSeen) : 0

  useEffect(() => {
    if (!open) return
    function onPointerDown(event: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false)
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  function toggle() {
    const next = !open
    setOpen(next)
    // Marked read on open, not on mount, so arriving on a page does not silently
    // clear a count the reader never looked at.
    if (next) {
      const now = new Date().toISOString()
      setLastSeen(now)
      writeLastSeen(now)
    }
  }

  const preview = entries.slice(0, PREVIEW_COUNT)

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={toggle}
        aria-label={unseen > 0 ? `Activity, ${unseen} new` : 'Activity'}
        aria-expanded={open}
        className={`relative flex items-center justify-center w-8 h-8 rounded-btn bg-transparent
          border-none cursor-pointer transition-opacity hover:opacity-60
          ${open ? 'text-content-primary' : 'text-content-dim'}`}
      >
        <IconBell size={17} />
        {unseen > 0 && (
          /* A count, not a dot. "Three things finished" and "something
             happened" are different messages, and the first is the one worth
             interrupting a reader for. */
          <span
            className="absolute -top-0.5 -right-0.5 min-w-[15px] h-[15px] px-1 rounded-pill
              bg-accent-blue text-button-fg font-mono text-[9px] font-bold leading-[15px]
              text-center"
          >
            {unseen > 9 ? '9+' : unseen}
          </span>
        )}
      </button>

      {open && (
        <div
          className="absolute top-[calc(100%+8px)] right-0 w-[380px] max-w-[92vw] z-[300]
            bg-surface-card border border-border rounded-card shadow-float overflow-hidden
            animate-fadeIn"
        >
          <div className="flex items-baseline gap-2 px-4 pt-3.5 pb-2.5 border-b border-border">
            <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
              Activity
            </span>
            {entries.length > 0 && (
              <span className="ml-auto font-mono text-2xs text-content-muted">
                {entries.length} recent
              </span>
            )}
          </div>

          {preview.length === 0 ? (
            <div className="px-4 py-8 text-center">
              <p className="text-xs text-content-dim">Nothing has happened yet.</p>
              <p className="text-2xs text-content-muted mt-1.5 leading-relaxed">
                Deploys, emulation runs and workflow results appear here as they finish.
              </p>
            </div>
          ) : (
            <div className="flex flex-col divide-y divide-border max-h-[340px] overflow-y-auto">
              {preview.map((entry) => (
                <ActivityRow key={entry.id} entry={entry} onNavigate={() => setOpen(false)} />
              ))}
            </div>
          )}

          <Link
            to="/results"
            onClick={() => setOpen(false)}
            className="block px-4 py-2.5 border-t border-border text-center text-2xs
              text-accent-blue no-underline transition-opacity hover:opacity-60"
          >
            View all activity
          </Link>
        </div>
      )}
    </div>
  )
}

/** One event: what kind it was, what it said, and when. */
function ActivityRow({ entry, onNavigate }: { entry: LogEntry; onNavigate: () => void }) {
  const meta = eventMeta(entry.event, entry.level)

  return (
    <Link
      to={activityHref(entry)}
      onClick={onNavigate}
      className="block px-4 py-3 no-underline transition-opacity hover:opacity-75"
    >
      <span className="flex items-center gap-1.5">
        <span className={`w-1.5 h-1.5 rounded-full bg-current shrink-0 ${TONE_CLASS[meta.tone]}`} />
        <span className={`font-mono text-2xs uppercase tracking-caps ${TONE_CLASS[meta.tone]}`}>
          {meta.label}
        </span>
        <span className="ml-auto font-mono text-2xs text-content-muted shrink-0">
          {formatWhen(entry.timestamp)}
        </span>
      </span>
      <span className="block text-xs tracking-body text-content-secondary leading-relaxed mt-1">
        {entry.message}
      </span>
    </Link>
  )
}
