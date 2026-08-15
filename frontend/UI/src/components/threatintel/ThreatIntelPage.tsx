import { ThreatIntelFeedPanel } from './ThreatIntelFeedPanel'

/**
 * Threat Intel section shell.
 *
 * Follows the layout of the other Security Content pages: eyebrow, display
 * title, subtitle.
 *
 * The APT advisory library that once sat beside the feed behind a view switcher
 * is not built yet, so the switcher is gone rather than offering one option.
 * Restore it, and the `?view=` query parameter it read, when advisory content
 * exists.
 */
export function ThreatIntelPage() {
  return (
    <div>
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Security Content
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Threat Intel
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          Cloud security research, breach reporting and provider advisories
        </div>
      </div>

      <ThreatIntelFeedPanel />
    </div>
  )
}
