import { useEffect, useMemo, useRef, useState } from 'react'
import { IconChevron, IconSearch } from './Icons'

/**
 * A type-to-filter select.
 *
 * A native select is fine for a handful of options and unusable for fifty: the
 * reader has to recognise a name in a long unsorted list rather than recall a
 * few letters of it. This filters as you type and is fully keyboard navigable,
 * so picking an emulation costs three keystrokes rather than a scroll hunt.
 *
 * Matching is a plain case-insensitive substring over the label, deliberately.
 * Fuzzy matching would surface the wrong emulation for a near-miss, and picking
 * the wrong one here spends real money in a real AWS account.
 */

export interface ComboboxOption {
  value: string
  label: string
  /** Optional second line, for example the emulation's platform or tier. */
  hint?: string
}

interface ComboboxProps {
  options: ComboboxOption[]
  value: string
  onChange: (value: string) => void
  placeholder?: string
  /** Announced to assistive technology in place of a visible label. */
  ariaLabel?: string
}

export function Combobox({
  options,
  value,
  onChange,
  placeholder = 'Search…',
  ariaLabel = 'Search and select',
}: ComboboxProps) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const rootRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLUListElement>(null)

  const selected = options.find((option) => option.value === value) ?? null

  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase()
    if (!term) return options
    return options.filter(
      (option) =>
        option.label.toLowerCase().includes(term) ||
        option.value.toLowerCase().includes(term),
    )
  }, [options, query])

  // Keep the highlight inside the filtered list as it narrows, so Enter never
  // selects something the reader can no longer see.
  useEffect(() => {
    setActive(0)
  }, [query])

  useEffect(() => {
    if (!open) return
    function onPointerDown(event: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    return () => document.removeEventListener('mousedown', onPointerDown)
  }, [open])

  // Scroll the highlighted row into view when moving by keyboard, which is the
  // only time the highlight can leave the visible slice of a long list.
  useEffect(() => {
    if (!open || !listRef.current) return
    const node = listRef.current.children[active] as HTMLElement | undefined
    node?.scrollIntoView({ block: 'nearest' })
  }, [active, open])

  function choose(option: ComboboxOption) {
    onChange(option.value)
    setQuery('')
    setOpen(false)
  }

  function onKeyDown(event: React.KeyboardEvent) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      if (!open) {
        setOpen(true)
        return
      }
      const step = event.key === 'ArrowDown' ? 1 : -1
      setActive((current) => {
        const next = current + step
        if (next < 0) return filtered.length - 1
        if (next >= filtered.length) return 0
        return next
      })
    } else if (event.key === 'Enter') {
      const option = filtered[active]
      if (open && option) {
        event.preventDefault()
        choose(option)
      }
    } else if (event.key === 'Escape') {
      setOpen(false)
    }
  }

  return (
    <div ref={rootRef} className="relative flex-1 min-w-[240px]">
      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-content-dim pointer-events-none">
        <IconSearch size={14} />
      </span>

      <input
        role="combobox"
        aria-expanded={open}
        aria-controls="combobox-list"
        aria-label={ariaLabel}
        autoComplete="off"
        value={open ? query : selected?.label ?? ''}
        placeholder={selected ? selected.label : placeholder}
        onFocus={() => setOpen(true)}
        onChange={(event) => {
          setQuery(event.target.value)
          setOpen(true)
        }}
        onKeyDown={onKeyDown}
        className="w-full bg-surface-base border border-border rounded-btn pl-9 pr-8 py-2
          text-sm text-content-primary placeholder:text-content-dim outline-none
          transition-colors focus:border-border-active"
      />

      <span
        aria-hidden="true"
        className={`absolute right-3 top-1/2 -translate-y-1/2 text-content-dim
          transition-transform ${open ? 'rotate-180' : ''}`}
      >
        <IconChevron size={13} />
      </span>

      {open && (
        <ul
          id="combobox-list"
          ref={listRef}
          role="listbox"
          className="absolute left-0 right-0 top-[calc(100%+4px)] z-50 max-h-72 overflow-y-auto
            bg-surface-card border border-border rounded-btn shadow-float py-1"
        >
          {filtered.length === 0 ? (
            <li className="px-3 py-2 text-xs text-content-dim">No emulation matches that.</li>
          ) : (
            filtered.map((option, index) => {
              const highlighted = index === active
              const isSelected = option.value === value
              return (
                <li
                  key={option.value}
                  role="option"
                  aria-selected={isSelected}
                  onMouseEnter={() => setActive(index)}
                  onClick={() => choose(option)}
                  /* The highlight is a left rail plus brighter text, not a
                     filled block. The design system asks interactive states to
                     change opacity and emphasis rather than swap backgrounds. */
                  className={`flex flex-col gap-0.5 px-3 py-1.5 cursor-pointer border-l-2
                    ${highlighted
                      ? 'border-l-accent-blue text-content-primary'
                      : 'border-l-transparent text-content-secondary'}`}
                >
                  <span className="text-xs tracking-body truncate">{option.label}</span>
                  {option.hint && (
                    <span className="font-mono text-2xs text-content-muted truncate">
                      {option.hint}
                    </span>
                  )}
                </li>
              )
            })
          )}
        </ul>
      )}
    </div>
  )
}
