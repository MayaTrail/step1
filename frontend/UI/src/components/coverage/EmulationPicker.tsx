import { useEffect, useRef, useState } from 'react'
import { IconChevron, IconSearch } from '@/components/ui/Icons'

/**
 * Which emulation Coverage History is showing, picked from a small panel.
 *
 * A compact button rather than a row of tabs: the row grew with every
 * emulation run, and registry ids such as
 * aws_credential_access_secretsmanager_retrieve_secrets made it wrap across
 * the page. The panel filters as you type and gives each emulation two lines,
 * so a long id is shown whole instead of cut off, with its run count beneath.
 *
 * Arrow keys move through the filtered list, Enter picks, Escape closes.
 */

/** One emulation the user has completed runs of. */
export interface EmulationRuns {
  type: string
  runs: number
  /** When its most recent run finished. */
  last: string | null
}

/** "5 runs · last 5 Oct" for an option's second line. */
function runsText(entry: EmulationRuns): string {
  const count = entry.runs === 1 ? '1 run' : `${entry.runs} runs`
  if (!entry.last) return count
  const when = new Date(entry.last).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  return `${count} · last ${when}`
}

interface EmulationPickerProps {
  entries: EmulationRuns[]
  value: string
  onChange: (type: string) => void
}

export function EmulationPicker({ entries, value, onChange }: EmulationPickerProps) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const rootRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const current = entries.find((entry) => entry.type === value) ?? null
  const term = query.trim().toLowerCase()
  const shown = term ? entries.filter((entry) => entry.type.toLowerCase().includes(term)) : entries

  useEffect(() => {
    if (!open) return undefined
    inputRef.current?.focus()
    function onPointerDown(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    return () => document.removeEventListener('mousedown', onPointerDown)
  }, [open])

  useEffect(() => {
    setActive(0)
  }, [query])

  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [active])

  function toggle() {
    setQuery('')
    setActive(Math.max(0, entries.findIndex((entry) => entry.type === value)))
    setOpen((was) => !was)
  }

  function choose(type: string) {
    onChange(type)
    setOpen(false)
  }

  function onKeyDown(event: React.KeyboardEvent) {
    if (!open) return
    if (event.key === 'Escape') {
      setOpen(false)
    } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      if (shown.length === 0) return
      const step = event.key === 'ArrowDown' ? 1 : -1
      setActive((index) => (index + step + shown.length) % shown.length)
    } else if (event.key === 'Enter') {
      event.preventDefault()
      const entry = shown[active]
      if (entry) choose(entry.type)
    }
  }

  return (
    <div ref={rootRef} className="relative" onKeyDown={onKeyDown}>
      <button
        type="button"
        onClick={toggle}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="inline-flex max-w-full items-center gap-2 rounded-lg border border-border bg-surface-elevated
          px-3 py-2 text-sm transition-opacity hover:opacity-60"
      >
        <span className="font-mono text-2xs uppercase tracking-label text-content-dim">Emulation</span>
        <span className="min-w-0 truncate text-content-primary">{current?.type ?? 'Choose'}</span>
        {current && (
          <span className="shrink-0 font-mono text-2xs text-content-dim">
            {current.runs === 1 ? '1 run' : `${current.runs} runs`}
          </span>
        )}
        <IconChevron
          size={14}
          className={`shrink-0 text-content-dim transition-transform duration-150 ${open ? 'rotate-90' : ''}`}
        />
      </button>

      {open && (
        <div
          className="animate-fadeIn absolute right-0 z-50 mt-1.5 w-80 overflow-hidden rounded-lg border border-border
            bg-surface-card shadow-ring sm:w-96"
        >
          <div className="flex items-center gap-2 border-b border-border px-3 py-2.5">
            <IconSearch size={14} className="shrink-0 text-content-dim" />
            <input
              ref={inputRef}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={`Filter ${entries.length} emulation${entries.length === 1 ? '' : 's'}`}
              aria-label="Filter emulations"
              autoComplete="off"
              className="w-full bg-transparent text-sm text-content-primary outline-none placeholder:text-content-dim"
            />
          </div>

          <div ref={listRef} role="listbox" aria-label="Emulations" className="max-h-72 overflow-y-auto py-1">
            {shown.length === 0 ? (
              <p className="px-3 py-3 text-xs text-content-dim">No emulation matches.</p>
            ) : (
              shown.map((entry, index) => {
                const selected = entry.type === value
                const highlighted = index === active
                return (
                  <button
                    key={entry.type}
                    type="button"
                    role="option"
                    aria-selected={selected}
                    data-index={index}
                    onClick={() => choose(entry.type)}
                    onMouseEnter={() => setActive(index)}
                    className={`block w-full px-3 py-2 text-left transition-opacity hover:opacity-60 ${
                      selected ? 'bg-accent-blue/10 text-accent-blue' : highlighted ? 'text-content-primary' : 'text-content-secondary'
                    }`}
                  >
                    <span className="block break-all text-sm">{entry.type}</span>
                    <span className="mt-0.5 block font-mono text-2xs text-content-dim">{runsText(entry)}</span>
                  </button>
                )
              })
            )}
          </div>

          <p className="border-t border-border px-3 py-2 text-2xs text-content-muted">
            Only emulations with a completed run are listed.
          </p>
        </div>
      )}
    </div>
  )
}
