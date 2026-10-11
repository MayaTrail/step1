/**
 * Every path of a scan at once, in three columns.
 *
 * Starts as (each path's origin), ends as (the identity holding the impact)
 * and gains (the impact). A path with several steps shows its first and last
 * identity here; Path view shows every step. The selected path stays lit and
 * the rest fade, and clicking a box or a curve selects that path.
 */

import type { AttackChain } from '@/types/attackGraph'

import { impactLabel, nodeFromArn } from './pathModel'

const GAP = 150
const PAD = 16
const ROW_SPAN = 280
const MAX_LABEL = 30

const shorten = (label: string) => (label.length > MAX_LABEL ? `${label.slice(0, MAX_LABEL - 1)}…` : label)

/** A box as wide as its label, estimated at 7.4px a character so a wider fallback font still fits. */
const boxWidth = (label: string) => Math.max(120, Math.round(shorten(label).length * 7.4) + 40)

interface MapPath {
  start: string
  end: string
  gain: string
  direct: boolean
}

interface Column {
  title: string
  labels: string[]
  x: number
}

export function PathMap({
  chains, selected, onSelect,
}: { chains: AttackChain[]; selected: number; onSelect: (index: number) => void }) {
  const paths: MapPath[] = chains.map((chain) => {
    const start = nodeFromArn(chain.source.arn).name
    const lastStep = chain.steps[chain.steps.length - 1]
    const end = lastStep ? nodeFromArn(lastStep.to).name : start
    return { start, end, gain: impactLabel(chain.terminal_impact), direct: !lastStep }
  })
  const chosen = paths[selected]
  if (!chosen) return null

  const unique = (values: string[]) => [...new Set(values)]
  const startLabels = unique(paths.map((p) => p.start))
  const endLabels = unique(paths.filter((p) => !p.direct).map((p) => p.end))
  const gainLabels = unique(paths.map((p) => p.gain))
  const widest = (labels: string[]) => Math.max(120, ...labels.map(boxWidth))

  const startW = widest(startLabels)
  const endW = widest(endLabels)
  const gainW = widest(gainLabels)
  const starts: Column = { title: 'STARTS AS', labels: startLabels, x: PAD + startW / 2 }
  const ends: Column = { title: 'ENDS AS', labels: endLabels, x: starts.x + startW / 2 + GAP + endW / 2 }
  const gains: Column = { title: 'GAINS', labels: gainLabels, x: ends.x + endW / 2 + GAP + gainW / 2 }
  const width = gains.x + gainW / 2 + PAD
  const height = ROW_SPAN + 80

  const y = (col: Column, label: string) => 56 + col.labels.indexOf(label) * (ROW_SPAN / Math.max(col.labels.length - 1, 1))
  const right = (col: Column, label: string) => col.x + boxWidth(label) / 2
  const left = (col: Column, label: string) => col.x - boxWidth(label) / 2
  const curve = (x1: number, y1: number, x2: number, y2: number) =>
    `M${x1} ${y1} C ${x1 + 80} ${y1}, ${x2 - 80} ${y2}, ${x2} ${y2}`

  const lit = (col: Column, label: string) => {
    if (col === starts) return label === chosen.start
    if (col === ends) return !chosen.direct && label === chosen.end
    return label === chosen.gain
  }

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="mt-3 w-full" role="img" aria-label="All attack paths">
      {[starts, ends, gains].map((col) => (
        <text key={col.title} x={col.x} y={18} textAnchor="middle" className="fill-content-dim font-mono text-2xs tracking-label">
          {col.title}
        </text>
      ))}

      {paths.map((p, i) => {
        const on = i === selected
        const common = {
          fill: 'none',
          strokeWidth: on ? 2 : 1.4,
          className: `cursor-pointer transition-opacity ${on ? 'stroke-accent-blue' : 'stroke-content-dim opacity-25'}`,
          onClick: () => onSelect(i),
        }
        const sy = y(starts, p.start)
        const gy = y(gains, p.gain)
        if (p.direct) {
          return <path key={i} d={curve(right(starts, p.start), sy, left(gains, p.gain), gy)} strokeDasharray="2 4" {...common} />
        }
        const ey = y(ends, p.end)
        return (
          <g key={i}>
            <path d={curve(right(starts, p.start), sy, left(ends, p.end), ey)} {...common} />
            <path d={curve(right(ends, p.end), ey, left(gains, p.gain), gy)} {...common} />
          </g>
        )
      })}

      {[starts, ends, gains].map((col) =>
        col.labels.map((label) => {
          const w = boxWidth(label)
          const firstPath = col === starts ? paths.findIndex((p) => p.start === label) : -1
          return (
            <g
              key={`${col.title}-${label}`}
              className={`transition-opacity ${lit(col, label) ? '' : 'opacity-40'} ${firstPath >= 0 ? 'cursor-pointer' : ''}`}
              onClick={firstPath >= 0 ? () => onSelect(firstPath) : undefined}
            >
              <title>{label}</title>
              <rect
                x={col.x - w / 2} y={y(col, label) - 15} width={w} height={30} rx={8}
                className={`fill-surface-elevated ${col === gains ? 'stroke-danger' : 'stroke-content-muted'}`}
              />
              <text x={col.x} y={y(col, label) + 4} textAnchor="middle" className="fill-content-secondary text-xs">
                {shorten(label)}
              </text>
            </g>
          )
        }),
      )}
    </svg>
  )
}
