import { useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import type { MatchKind, ThreatFeedItem, ThreatFeedMatch } from '@/types/threatintel'
import { IconExternalLink, IconFlask } from '@/components/ui/Icons'
import { FeedMark } from './FeedMark'
import { KIND_LABEL, formatWhen } from './feedMeta'

/**
 * The selected item, rendered as a briefing rather than a reader.
 *
 * MayaTrail does not hold the article. All a feed gives is a title and a
 * summary the publisher wrote, capped at 400 characters backend-side, and
 * re-hosting the full text would be someone else's copyright. So the borrowed
 * summary sits at the top and the pane below it is filled with the part
 * MayaTrail does own: which emulations the post relates to, on what evidence,
 * and a way through to them. Reading the article itself happens on the
 * publisher's site, one clearly-marked link away.
 */

/** How a match was made, phrased for a reader rather than as a field name. */
const MATCH_EXPLANATION: Record<MatchKind, string> = {
  cited: 'This emulation already cites this article as a reference.',
  technique: 'The article names a technique this emulation maps.',
  campaign: 'The article names the campaign this emulation reproduces.',
}

interface FeedItemDetailProps {
  item: ThreatFeedItem
  /** Height utilities from the page, so this pane matches the index rail. */
  className?: string
}

/**
 * The pane is sized by the page rather than by its own content, so the layout
 * does not resize every time a different item is selected. Overflow is handled
 * on an inner element: the card keeps its rounded corners and ring shadow while
 * only the content behind them scrolls.
 *
 * Carries no entry animation and is never keyed on the item. Both would force a
 * remount on selection and replay the animation, which reads as the pane
 * flashing. Scrolling back to the top is done directly instead, which is the
 * only thing the remount was actually needed for.
 */
export function FeedItemDetail({ item, className = '' }: FeedItemDetailProps) {
  const scrollRef = useRef<HTMLDivElement>(null)

  // Without this, selecting a shorter item after scrolling through a long one
  // would open it already scrolled past its own title.
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: 0 })
  }, [item.id])

  return (
    <article
      className={`bg-surface-card border border-border rounded-card shadow-ring
        flex flex-col overflow-hidden ${className}`}
    >
      <div ref={scrollRef} className="overflow-y-auto p-6">
        <header className="flex items-start gap-3">
          <FeedMark feedId={item.feedId} feedTitle={item.feedTitle} size={40} />
          <div className="min-w-0">
            <div className="font-mono text-2xs uppercase tracking-label text-accent-blue">
              {item.feedTitle}
            </div>
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 mt-1 text-xs text-content-dim">
              <span>{KIND_LABEL[item.kind]}</span>
              <span aria-hidden="true">&middot;</span>
              <span>{item.publishedAt ? formatWhen(item.publishedAt) : 'undated'}</span>
              {item.author && (
                <>
                  <span aria-hidden="true">&middot;</span>
                  <span>{item.author}</span>
                </>
              )}
            </div>
          </div>
        </header>

        <h2 className="font-display text-xl font-semibold text-content-primary leading-snug tracking-body mt-4">
          {item.title}
        </h2>

        {item.summary && (
          <p className="text-sm text-content-secondary leading-relaxed tracking-body mt-3">
            {item.summary}
          </p>
        )}

        {item.link && (
          <a
            href={item.link}
            target="_blank"
            /* noreferrer also suppresses the Referer header, so the publisher is
               not told that the reader arrived from MayaTrail. */
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 mt-5 px-4 py-2 rounded-btn text-sm font-medium tracking-btn
              no-underline text-content-primary border border-border bg-transparent shadow-button
              transition-opacity hover:opacity-60"
          >
            Read the original
            <IconExternalLink size={14} />
          </a>
        )}

        {item.tags.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-5">
            {item.tags.map((tag) => (
              <span
                key={tag}
                className="font-mono text-2xs uppercase tracking-caps text-content-dim
                  bg-surface-elevated border border-border rounded-btn px-2 py-0.5"
              >
                {tag}
              </span>
            ))}
          </div>
        )}

        <RelatedEmulations matches={item.matches} />
      </div>
    </article>
  )
}

/**
 * The MayaTrail-native half of the pane.
 *
 * Rendered even when empty. A reader who sees "no emulation covers this yet"
 * has learned something actionable about coverage; a section that silently
 * disappears teaches them nothing and makes them wonder whether it ran.
 */
function RelatedEmulations({ matches }: { matches: ThreatFeedMatch[] }) {
  return (
    <section className="mt-6 pt-5 border-t border-border">
      <h3 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-3">
        Related emulations
      </h3>

      {matches.length === 0 ? (
        <p className="text-sm text-content-dim leading-relaxed tracking-body">
          Nothing in the emulation catalogue matches this post. Matching is
          deliberately strict, so an absence here means no confident link rather
          than no possible one.
        </p>
      ) : (
        <div className="flex flex-col gap-2">
          {matches.map((match) => (
            <MatchRow key={`${match.emulationId}-${match.kind}`} match={match} />
          ))}
        </div>
      )}
    </section>
  )
}

/** One matched emulation, showing the evidence so the link can be judged. */
function MatchRow({ match }: { match: ThreatFeedMatch }) {
  return (
    <Link
      to={`/${match.platform}/emulations/${match.emulationId}`}
      className="group flex items-start gap-3 p-3 rounded-btn no-underline
        bg-surface-elevated border border-border transition-opacity hover:opacity-60"
    >
      <span className="mt-0.5 text-accent-blue shrink-0">
        <IconFlask size={15} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-sm font-medium text-content-primary tracking-body">
          {match.displayName}
        </span>
        <span className="block text-xs text-content-dim mt-0.5 leading-relaxed">
          {MATCH_EXPLANATION[match.kind]}
        </span>
      </span>
      <code className="shrink-0 font-mono text-2xs text-content-secondary bg-surface-base
        border border-border rounded px-1.5 py-0.5 max-w-[40%] truncate" title={match.evidence}>
        {match.evidence}
      </code>
    </Link>
  )
}
