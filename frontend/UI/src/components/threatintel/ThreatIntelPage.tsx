import { useSearchParams } from 'react-router-dom'
import type { ThreatIntelView } from '@/types'
import { IconBroadcast, IconChevron, IconWarning } from '@/components/ui/Icons'
import { ThreatIntelFeedPanel } from './ThreatIntelFeedPanel'
import { AdvisoryPanel } from './AdvisoryPanel'

interface ViewOption {
  value: ThreatIntelView
  label: string
  hint: string
  icon: React.ReactNode
}

const VIEWS: ViewOption[] = [
  {
    value: 'feed',
    label: 'Threat Intel Feed',
    hint: 'Cloud security publications',
    icon: <IconBroadcast size={16} />,
  },
  {
    value: 'advisory',
    label: 'Advisory',
    hint: 'MayaTrail notices',
    icon: <IconWarning size={16} />,
  },
]

/**
 * Threat Intel section shell.
 *
 * Follows the layout of the other Security Content pages — eyebrow, display
 * title, subtitle — and adds the vertical selector the section is organised
 * around: a two-option rail down the left of the content area, using the
 * sidebar's active treatment (left accent rail plus a faint blue tint) so
 * selection reads the same everywhere in the app. Below `md` the rail has no
 * room, so it becomes a row above the panel.
 *
 * The active panel is held in the query string rather than component state so
 * a view is linkable and survives a reload.
 */
export function ThreatIntelPage() {
  const [params, setParams] = useSearchParams()
  const raw = params.get('view')
  const view: ThreatIntelView = raw === 'advisory' ? 'advisory' : 'feed'

  const select = (next: ThreatIntelView) => {
    // `replace` keeps the back button pointing at the previous page rather
    // than accumulating one history entry per tab click.
    setParams(next === 'feed' ? {} : { view: next }, { replace: true })
  }

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

      <div className="flex flex-col md:flex-row gap-5 md:gap-6 items-stretch md:items-start">
        <ViewSelector active={view} onSelect={select} />
        <div className="flex-1 min-w-0">
          {view === 'feed' ? <ThreatIntelFeedPanel /> : <AdvisoryPanel />}
        </div>
      </div>
    </div>
  )
}

/** The vertical two-option selector that organises the section. */
function ViewSelector({
  active,
  onSelect,
}: {
  active: ThreatIntelView
  onSelect: (view: ThreatIntelView) => void
}) {
  return (
    <nav
      aria-label="Threat Intel sections"
      className="w-full md:w-[210px] shrink-0 bg-surface-card border border-border rounded-card overflow-hidden md:sticky md:top-4"
    >
      <div className="font-mono text-[9px] font-bold tracking-[2px] text-content-dim px-4 pt-3 pb-2 uppercase">
        Sections
      </div>
      {VIEWS.map((option) => {
        const isActive = option.value === active
        return (
          <button
            key={option.value}
            type="button"
            onClick={() => onSelect(option.value)}
            aria-current={isActive ? 'page' : undefined}
            className={`w-full flex items-center gap-2.5 px-4 py-2.5 text-left cursor-pointer
              transition-all duration-150 border-l-2 text-[13px] font-medium
              ${isActive
                ? 'text-content-primary border-l-accent-blue bg-accent-blue/[0.06]'
                : 'text-content-secondary border-l-transparent hover:bg-white/[0.03] hover:text-content-primary'
              }`}
          >
            <span className={isActive ? 'text-accent-blue' : 'text-content-dim'}>{option.icon}</span>
            <span className="min-w-0 flex-1">
              <span className="block truncate">{option.label}</span>
              <span className="block font-mono text-[10px] text-content-dim truncate">{option.hint}</span>
            </span>
            <IconChevron
              size={13}
              className={`shrink-0 transition-opacity ${isActive ? 'text-accent-blue opacity-100' : 'opacity-0'}`}
            />
          </button>
        )
      })}
    </nav>
  )
}
