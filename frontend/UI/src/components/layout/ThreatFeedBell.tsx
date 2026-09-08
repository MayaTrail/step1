import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useThreatFeed } from '@/hooks/useThreatFeed'
import type { ThreatFeedItem } from '@/types/threatintel'
import { IconBell } from '@/components/ui/Icons'
import { FeedMark } from '@/components/threatfeed/FeedMark'
import { formatWhen } from '@/components/threatfeed/feedMeta'

/**
 * Threat Feed notification bell.
 *
 * Answers "is there anything new worth opening the feed for?" without making
 * the reader navigate. Needed no backend work: the feed response already
 * carries publishedAt per item and fetchedAt for the run, which is everything
 * both halves of the question need.
 *
 * Deliberately does not report feed health. Which subscriptions are failing is
 * an operator's concern, and putting it in front of every reader gives them a
 * number they cannot act on.
 */

/** Where the last-seen marker lives. Per browser, never sent anywhere. */
const LAST_SEEN_KEY = 'mayatrail.threatfeed.lastSeenAt'

/** Items pulled for the panel. Enough to count against, few enough to be cheap. */
const FETCH_LIMIT = 60

/** Rows listed inside the panel before the reader is sent to the full page. */
const PREVIEW_COUNT = 4

/**
 * A run is scheduled daily, so this much silence means the ingest has missed at
 * least one window and the feed is no longer trustworthy as "what is new".
 */
const STALE_AFTER_HOURS = 36

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

export function ThreatFeedBell() {
  const [open, setOpen] = useState(false)
  const [lastSeen, setLastSeen] = useState<string | null>(readLastSeen)
  const panelRef = useRef<HTMLDivElement>(null)

  const { data: feed } = useThreatFeed({ limit: FETCH_LIMIT })
  const items = feed?.items ?? []

  /*
   * A browser with no marker has never opened the feed. Counting every item in
   * the window as unread would greet a first-time reader with "294 new", which
   * is noise rather than news, so the marker is planted on first sight and the
   * count starts from what arrives after that.
   */
  useEffect(() => {
    if (lastSeen === null && feed) {
      const now = new Date().toISOString()
      writeLastSeen(now)
      setLastSeen(now)
    }
  }, [lastSeen, feed])

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (panelRef.current && !panelRef.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
    return undefined
  }, [open])

  const unseen = lastSeen
    ? items.filter((item) => item.publishedAt !== null && item.publishedAt > lastSeen)
    : []

  const stale = isStale(feed?.fetchedAt ?? null)

  /*
   * Opening the panel marks everything seen, but the list rendered is the one
   * captured at that moment, so the reader can still act on what was new
   * instead of watching it clear out from under them.
   */
  const [snapshot, setSnapshot] = useState<ThreatFeedItem[]>([])

  function toggle() {
    if (!open) {
      setSnapshot(unseen)
      const now = new Date().toISOString()
      writeLastSeen(now)
      setLastSeen(now)
    }
    setOpen((wasOpen) => !wasOpen)
  }

  const listed = (snapshot.length > 0 ? snapshot : items).slice(0, PREVIEW_COUNT)

  return (
    <div className="relative" ref={panelRef}>
      <button
        type="button"
        onClick={toggle}
        aria-label={unseen.length > 0 ? `Threat Feed, ${unseen.length} new` : 'Threat Feed'}
        className="relative flex items-center justify-center w-8 h-8 rounded-btn text-content-dim
          transition-colors hover:text-content-primary hover:bg-surface-elevated"
      >
        <IconBell size={17} />
        {unseen.length > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 rounded-full
            bg-accent-blue text-button-fg font-mono text-[9px] font-bold
            flex items-center justify-center">
            {unseen.length > 99 ? '99+' : unseen.length}
          </span>
        )}
        {unseen.length === 0 && stale && (
          <span
            title="The threat feed has not refreshed recently"
            className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-warning"
          />
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-[calc(100%+8px)] w-[320px] bg-surface-card border border-border
          rounded-card shadow-float overflow-hidden z-[200] animate-fadeSlideIn">
          <div className="px-4 py-3 border-b border-border">
            <div className="font-mono text-2xs uppercase tracking-label text-content-dim">Threat Feed</div>
            <div className={`text-xs mt-1 ${stale ? 'text-warning' : 'text-content-secondary'}`}>
              {feed?.fetchedAt
                ? `Updated ${formatWhen(feed.fetchedAt)}${stale ? ', longer ago than expected' : ''}`
                : 'Not refreshed yet'}
            </div>
            <div className="text-xs text-content-dim mt-0.5">
              {snapshot.length > 0
                ? `${snapshot.length} new since you last looked`
                : 'Nothing new since you last looked'}
            </div>
          </div>

          {listed.length === 0 ? (
            <div className="px-4 py-6 text-center text-xs text-content-dim">
              No items yet.
            </div>
          ) : (
            <div className="flex flex-col divide-y divide-border max-h-[320px] overflow-y-auto">
              {listed.map((item) => (
                <BellRow key={item.id} item={item} />
              ))}
            </div>
          )}

          <Link
            to="/threat-feed"
            onClick={() => setOpen(false)}
            className="block px-4 py-2.5 border-t border-border text-xs font-medium tracking-btn
              text-content-secondary no-underline transition-opacity hover:opacity-60"
          >
            View all
          </Link>
        </div>
      )}
    </div>
  )
}

/**
 * Decide whether the ingest has gone quiet.
 *
 * @param fetchedAt - When the last run completed, or null if it never has.
 * @returns True once more than STALE_AFTER_HOURS have passed.
 */
function isStale(fetchedAt: string | null): boolean {
  if (!fetchedAt) return true
  const then = new Date(fetchedAt).getTime()
  if (Number.isNaN(then)) return false
  return Date.now() - then > STALE_AFTER_HOURS * 3_600_000
}

/** One row in the panel: the mark, the title, and a dot when it correlates. */
function BellRow({ item }: { item: ThreatFeedItem }) {
  return (
    <a
      href={item.link || undefined}
      target="_blank"
      /* noreferrer also suppresses the Referer header, so the publisher is not
         told the reader came from MayaTrail. */
      rel="noopener noreferrer"
      className="flex items-start gap-2.5 px-4 py-2.5 no-underline transition-opacity hover:opacity-60"
    >
      <FeedMark feedId={item.feedId} feedTitle={item.feedTitle} size={24} />
      <span className="min-w-0 flex-1">
        <span className="flex items-start gap-1.5">
          <span className="text-xs text-content-secondary leading-snug tracking-body line-clamp-2">
            {item.title}
          </span>
          {item.matches.length > 0 && (
            <span
              title={`Relates to ${item.matches.map((match) => match.displayName).join(', ')}`}
              className="mt-1 shrink-0 w-1.5 h-1.5 rounded-full bg-accent-blue"
            />
          )}
        </span>
        <span className="block font-mono text-2xs text-content-muted mt-1 truncate">
          {item.feedTitle}
          {item.publishedAt && ` · ${formatWhen(item.publishedAt)}`}
        </span>
      </span>
    </a>
  )
}
