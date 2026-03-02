function tacticColorClass(tactic: string): string {
  const t = tactic.toLowerCase()
  if (t.includes('initial')) return 'bg-[rgba(248,113,113,0.1)] text-[#f87171]'
  if (t.includes('execution')) return 'bg-[rgba(251,191,36,0.1)] text-[#fbbf24]'
  if (t.includes('persistence')) return 'bg-[rgba(167,139,250,0.1)] text-purple'
  if (t.includes('priv')) return 'bg-[rgba(16,185,129,0.1)] text-green'
  if (t.includes('defense')) return 'bg-[rgba(0,212,255,0.1)] text-cyan'
  if (t.includes('lateral')) return 'bg-[rgba(255,107,53,0.1)] text-orange'
  if (t.includes('exfil')) return 'bg-[rgba(248,113,113,0.1)] text-[#f87171]'
  if (t.includes('collection')) return 'bg-[rgba(251,191,36,0.1)] text-[#fbbf24]'
  if (t.includes('discovery')) return 'bg-[rgba(0,212,255,0.1)] text-cyan'
  if (t.includes('credential')) return 'bg-[rgba(167,139,250,0.1)] text-purple'
  if (t.includes('impact')) return 'bg-[rgba(248,113,113,0.15)] text-[#f87171]'
  return 'bg-[rgba(0,212,255,0.1)] text-cyan'
}

export function TacticBadge({ tactic }: { tactic: string }) {
  return (
    <span className={`font-mono text-[9px] px-[7px] py-0.5 rounded-[3px] ${tacticColorClass(tactic)}`}>
      {tactic}
    </span>
  )
}
