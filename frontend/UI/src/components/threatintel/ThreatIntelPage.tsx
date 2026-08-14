import { useSearchParams } from 'react-router-dom'
import type { ThreatIntelView } from '@/types'
import { FilterDropdown, type DropdownOption } from '@/components/ui/FilterDropdown'
import { IconBroadcast, IconWarning } from '@/components/ui/Icons'
import { ThreatIntelFeedPanel } from './ThreatIntelFeedPanel'
import { AdvisoryPanel } from './AdvisoryPanel'

const VIEW_OPTIONS: DropdownOption<ThreatIntelView>[] = [
  { value: 'feed', label: 'Threat Intel Feed', icon: <IconBroadcast size={14} /> },
  { value: 'advisory', label: 'Advisory', icon: <IconWarning size={14} /> },
]

/**
 * Threat Intel section shell.
 *
 * Follows the layout of the other Security Content pages — eyebrow, display
 * title, subtitle — with the section switcher sitting beside the title as a
 * dropdown. Reuses FilterDropdown rather than a bespoke control so the
 * open/close behaviour (outside click, Escape, close on select) and the
 * Raycast-Blue active row match every other dropdown in the app.
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
    // than accumulating one history entry per switch.
    setParams(next === 'feed' ? {} : { view: next }, { replace: true })
  }

  return (
    <div>
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Security Content
        </div>
        <div className="flex items-center gap-3.5 flex-wrap">
          <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
            Threat Intel
          </div>
          <FilterDropdown label="View" value={view} options={VIEW_OPTIONS} onChange={select} />
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          {view === 'feed'
            ? 'Cloud security research, breach reporting and provider advisories'
            : 'APT threat-actor dossiers — TTPs, tooling and known exploited CVEs by actor'}
        </div>
      </div>

      {view === 'feed' ? <ThreatIntelFeedPanel /> : <AdvisoryPanel />}
    </div>
  )
}
