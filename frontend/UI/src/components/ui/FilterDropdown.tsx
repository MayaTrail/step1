import { useState, useRef, useEffect } from 'react'
import type { ReactNode } from 'react'
import { IconChevron } from './Icons'

export interface DropdownOption<T extends string> {
  value: T
  label: string
  /** Optional leading icon (e.g. a platform glyph). */
  icon?: ReactNode
}

interface FilterDropdownProps<T extends string> {
  /** Static label shown before the selected value, e.g. "Status". */
  label: string
  value: T
  options: DropdownOption<T>[]
  onChange: (value: T) => void
}

/**
 * Compact label + value dropdown for table filters.
 *
 * Chosen over a row of chips so the control's width stays constant as the
 * option set grows (the platform list, in particular, will keep expanding).
 * Closes on outside click, Escape, or selection. Follows the design system:
 * surface-elevated trigger, double-ring popover shadow, Raycast-Blue active row.
 */
export function FilterDropdown<T extends string>({ label, value, options, onChange }: FilterDropdownProps<T>) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const selected = options.find((o) => o.value === value)

  useEffect(() => {
    if (!open) return
    function onDocClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDocClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDocClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-2 bg-surface-elevated border border-border rounded-lg px-3 py-2
          text-sm transition-colors hover:border-border-active min-w-[150px]"
      >
        <span className="font-mono text-[10px] uppercase tracking-[1px] text-content-dim">{label}</span>
        <span className="flex items-center gap-1.5 text-content-primary">
          {selected?.icon}
          {selected?.label ?? 'All'}
        </span>
        <IconChevron size={14} className={`ml-auto text-content-dim transition-transform duration-150 ${open ? 'rotate-90' : ''}`} />
      </button>

      {open && (
        <div
          className="absolute left-0 z-[120] mt-1.5 w-max min-w-full bg-surface-card border border-border rounded-lg overflow-hidden
            shadow-[rgb(27,28,30)_0px_0px_0px_1px,rgba(0,0,0,0.5)_0px_8px_24px]"
        >
          {options.map((opt) => {
            const active = opt.value === value
            return (
              <button
                key={opt.value}
                onClick={() => { onChange(opt.value); setOpen(false) }}
                className={`w-full flex items-center gap-2 px-3 py-2 text-sm text-left whitespace-nowrap transition-colors
                  ${active
                    ? 'text-accent-blue bg-accent-blue/[0.08]'
                    : 'text-content-secondary hover:bg-white/[0.03] hover:text-content-primary'
                  }`}
              >
                {opt.icon}
                {opt.label}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
