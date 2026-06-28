import type { Emulation, Reference } from '@/types'
import { Card } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'

/**
 * References tab. Organises an emulation's reference list into a threat-intel
 * hub: sources grouped by purpose, each rendered as a tile that links out to
 * the real source in a new tab.
 *
 * Cards show what the MANIFEST provides: title, the authored `source` line
 * (publisher and date), the type, and an icon. The link target is the explicit
 * `url` when present, falling back to the `source` if it is itself a URL.
 */

/** Maps a reference `type` to a human group heading. */
const LABEL_FOR_TYPE: Record<string, string> = {
  REPORT: 'Threat Intelligence',
  ADVISORY: 'Threat Intelligence',
  DETECTION: 'Detection Engineering',
  DOCUMENTATION: 'Technical Documentation',
  REFERENCE: 'Technical Documentation',
  MITRE: 'MITRE ATT&CK',
  BLOG: 'Research Blogs',
  VIDEO: 'Conference Talks',
  TALK: 'Conference Talks',
  POC: 'Proof of Concept',
  GITHUB: 'Proof of Concept',
}

/** Group display order; groups not listed here fall to the end. */
const GROUP_ORDER = [
  'Threat Intelligence',
  'Detection Engineering',
  'MITRE ATT&CK',
  'Technical Documentation',
  'Research Blogs',
  'Conference Talks',
  'Proof of Concept',
  'References',
]

/** Reference accent color name -> design-token utility classes. */
const REF_COLOR: Record<string, string> = {
  cyan: 'text-cyan border-cyan/30 bg-cyan/[0.06]',
  purple: 'text-purple border-purple/30 bg-purple/[0.06]',
  orange: 'text-orange border-orange/30 bg-orange/[0.06]',
  green: 'text-green border-green/30 bg-green/[0.06]',
  yellow: 'text-yellow border-yellow/30 bg-yellow/[0.06]',
  blue: 'text-accent-blue border-accent-blue/30 bg-accent-blue/[0.06]',
}

function groupLabel(type: string): string {
  return LABEL_FOR_TYPE[type?.toUpperCase()] ?? 'References'
}

function asUrl(source: string): string | undefined {
  return /^https?:\/\//i.test(source) ? source : undefined
}

/** Hostname of a URL for a compact meta line; falls back to the raw string. */
function safeHostname(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '')
  } catch {
    return url
  }
}

interface ReferencesTabProps {
  emulation: Emulation
}

export function ReferencesTab({ emulation: em }: ReferencesTabProps) {
  if (em.references.length === 0) {
    return (
      <EmptyState
        icon="&#128279;"
        title="No references yet"
        body="This emulation has no linked intelligence reports or documentation."
      />
    )
  }

  // Bucket references by their display group, preserving authored order within.
  const buckets = new Map<string, Reference[]>()
  for (const ref of em.references) {
    const label = groupLabel(ref.type)
    const list = buckets.get(label) ?? []
    list.push(ref)
    buckets.set(label, list)
  }

  const groups = Array.from(buckets.entries()).sort((a, b) => {
    const ia = GROUP_ORDER.indexOf(a[0])
    const ib = GROUP_ORDER.indexOf(b[0])
    return (ia === -1 ? GROUP_ORDER.length : ia) - (ib === -1 ? GROUP_ORDER.length : ib)
  })

  return (
    <div className="flex flex-col gap-7 animate-fadeIn">
      {groups.map(([label, refs]) => (
        <div key={label}>
          <div className="font-mono text-2xs tracking-label uppercase text-content-dim mb-3 flex items-center gap-2.5">
            {label}
            <span className="text-content-muted">{refs.length}</span>
            <div className="flex-1 h-px bg-border" />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {refs.map((ref, i) => (
              <RefCard key={`${label}-${i}`} reference={ref} />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

/* ── Reference tile ────────────────────────────────────────────────── */

function RefCard({ reference: ref }: { reference: Reference }) {
  const url = ref.url ?? asUrl(ref.source)
  const meta = asUrl(ref.source) ? safeHostname(ref.source) : ref.source
  const colorCls = REF_COLOR[ref.color] ?? 'text-content-secondary border-border bg-surface-elevated'

  const tile = (
    <div className="flex flex-col h-full min-h-[148px] p-[18px]">
      <div className="flex items-start justify-between gap-2.5">
        <span className={`font-mono w-9 h-9 flex items-center justify-center rounded-btn border text-[15px] shrink-0 ${colorCls}`}>
          {ref.icon}
        </span>
        <span className={`font-mono text-[9px] tracking-caps uppercase px-2 py-0.5 rounded-[5px] border whitespace-nowrap ${colorCls}`}>
          {ref.type}
        </span>
      </div>
      <div className="text-[14px] font-semibold text-content-primary leading-snug mt-3.5 line-clamp-3">
        {ref.title}
      </div>
      <div className="flex-1" />
      <div className="font-mono text-[10px] text-content-dim mt-3 flex items-center gap-1.5 truncate">
        <span className="truncate">{meta}</span>
        {url && <span className="text-accent-blue shrink-0">{'↗'}</span>}
      </div>
    </div>
  )

  if (url) {
    return (
      <a href={url} target="_blank" rel="noreferrer noopener" className="no-underline text-inherit block h-full">
        <Card interactive className="h-full">{tile}</Card>
      </a>
    )
  }
  return <Card className="h-full">{tile}</Card>
}
