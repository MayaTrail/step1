import type { ThreatOrigin } from '@/types'

const originStyles: Record<ThreatOrigin, string> = {
  russia: 'bg-[rgba(248,113,113,0.1)] border-[rgba(248,113,113,0.3)] text-[#f87171]',
  china: 'bg-[rgba(251,191,36,0.1)] border-[rgba(251,191,36,0.3)] text-[#fbbf24]',
  nk: 'bg-[rgba(167,139,250,0.1)] border-[rgba(167,139,250,0.3)] text-purple',
  iran: 'bg-[rgba(16,185,129,0.1)] border-[rgba(16,185,129,0.3)] text-green',
  unknown: 'bg-[rgba(148,163,184,0.1)] border-[rgba(148,163,184,0.3)] text-content-secondary',
}

export function ThreatOriginBadge({ origin, label }: { origin: ThreatOrigin; label: string }) {
  return (
    <span className={`font-mono text-[9px] px-[7px] py-0.5 rounded-[3px] font-normal tracking-wider border
      ${originStyles[origin]}`}>
      {label}
    </span>
  )
}
