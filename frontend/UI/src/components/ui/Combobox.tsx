import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'
import { IconChevron, IconSearch } from './Icons'

/**
 * A type-to-filter select.
 *
 * A native select is fine for a handful of options and unusable for fifty: the
 * reader has to recognise a name in a long unsorted list rather than recall a
 * few letters of it. This filters as you type and is fully keyboard navigable,
 * so picking an emulation costs three keystrokes rather than a scroll hunt.
 *
 * Matching is a plain case-insensitive substring over the label and the hint,
 * deliberately. Fuzzy matching would surface the wrong option for a near-miss,
 * and widening the match to every field on the row is worse still: "iam" then
 * returns the twenty-two emulations that touch IAM somewhere instead of the
 * eight that are about it. Picking the wrong one here spends real money in a
 * real AWS account, so the extra facts on each row are shown, not searched.
 *
 * The menu is a floating surface with its own width rather than a strip pinned
 * to the input. The input is usually a flex child sharing a row with a button,
 * which made the list too narrow to read a full name in.
 *
 * It renders through a portal, positioned from the input's measured rectangle.
 * An absolutely positioned menu is clipped by any positioned ancestor with a
 * hidden overflow, and Card is exactly that, so the list was cut off at the
 * bottom edge of a card only tall enough to hold the input itself. Measuring
 * also lets the menu take the height actually available below the input rather
 * than a fixed guess.
 */

export interface ComboboxOption {
  value: string
  label: string
  /** Second line under the label, for example a registry id. Also matched. */
  hint?: string
  /** Heading this option is filed under. Ungrouped options are listed last. */
  group?: string
  /** Extra facts appended to the hint line, divided by a thin separator. */
  meta?: string[]
  /** Rendered at the end of the label row, for example a severity. */
  badge?: ReactNode
}

interface ComboboxProps {
  options: ComboboxOption[]
  value: string
  onChange: (value: string) => void
  placeholder?: string
  /** Announced to assistive technology in place of a visible label. */
  ariaLabel?: string
  /** Group headings in display order. Groups absent here follow, as first seen. */
  groupOrder?: string[]
  /** Plural noun for the footer count, for example "emulations". */
  noun?: string
  /** Second line of the empty state, saying what is and is not searched. */
  emptyHint?: string
}

/** Stable empty default, so the grouping memo does not rerun every render. */
const NO_GROUP_ORDER: string[] = []

/** Preferred menu width. Wide enough for a full emulation name on one line. */
const MENU_WIDTH = 640

/** Upper bound on height, so a short list does not stretch down the viewport. */
const MENU_MAX_HEIGHT = 560

/** Gap between the input and the menu. */
const MENU_GAP = 6

/** Breathing room kept between the menu and every viewport edge. */
const VIEWPORT_MARGIN = 16

interface MenuRect {
  left: number
  top: number
  width: number
  maxHeight: number
}

/**
 * Place the menu under its input, inside the viewport.
 *
 * @param anchor - The element the menu hangs from.
 * @returns Fixed-position coordinates and the height available below the
 *   anchor, so the list is as long as the screen allows instead of a guess.
 */
function measure(anchor: HTMLElement): MenuRect {
  const rect = anchor.getBoundingClientRect()
  const width = Math.min(MENU_WIDTH, window.innerWidth - VIEWPORT_MARGIN * 2)
  const top = rect.bottom + MENU_GAP
  return {
    left: Math.max(VIEWPORT_MARGIN, Math.min(rect.left, window.innerWidth - width - VIEWPORT_MARGIN)),
    top,
    width,
    maxHeight: Math.min(MENU_MAX_HEIGHT, window.innerHeight - top - VIEWPORT_MARGIN),
  }
}

interface OptionGroup {
  name: string
  items: ComboboxOption[]
}

export function Combobox({
  options,
  value,
  onChange,
  placeholder = 'Search…',
  ariaLabel = 'Search and select',
  groupOrder = NO_GROUP_ORDER,
  noun = 'options',
  emptyHint,
}: ComboboxProps) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const [rect, setRect] = useState<MenuRect | null>(null)
  const rootRef = useRef<HTMLDivElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const selected = options.find((option) => option.value === value) ?? null

  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase()
    if (!term) return options
    return options.filter(
      (option) =>
        option.label.toLowerCase().includes(term) ||
        (option.hint ?? '').toLowerCase().includes(term),
    )
  }, [options, query])

  /*
   * Grouping changes the order rows appear in, so the highlight has to index
   * into the grouped order rather than the filtered one. Keeping both in step
   * is the whole reason `ordered` exists.
   */
  const groups = useMemo<OptionGroup[]>(() => {
    const buckets = new Map<string, ComboboxOption[]>()
    for (const option of filtered) {
      const name = option.group ?? ''
      const bucket = buckets.get(name)
      if (bucket) bucket.push(option)
      else buckets.set(name, [option])
    }
    const named = groupOrder.filter((name) => buckets.has(name))
    const rest = [...buckets.keys()].filter((name) => !named.includes(name))
    return [...named, ...rest].map((name) => ({
      name,
      items: buckets.get(name) as ComboboxOption[],
    }))
  }, [filtered, groupOrder])

  const ordered = useMemo(() => groups.flatMap((group) => group.items), [groups])

  // Keep the highlight inside the list as it narrows, so Enter never selects
  // something the reader can no longer see.
  useEffect(() => {
    setActive(0)
  }, [query])

  /*
   * The menu is a portal, so it is not a descendant of the root and has to be
   * excluded from the outside test explicitly. Without this, pressing an option
   * closed the menu on mousedown and the click never reached the row.
   */
  useEffect(() => {
    if (!open) return
    function onPointerDown(event: MouseEvent) {
      const target = event.target as Node
      if (rootRef.current?.contains(target)) return
      if (menuRef.current?.contains(target)) return
      setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    return () => document.removeEventListener('mousedown', onPointerDown)
  }, [open])

  const reposition = useCallback(() => {
    if (rootRef.current) setRect(measure(rootRef.current))
  }, [])

  /*
   * Measured before paint so the menu never appears at the wrong place for a
   * frame, and again on scroll or resize because fixed positioning does not
   * follow the anchor on its own. Scroll is captured, since the page scrolls in
   * a nested container rather than on the document.
   */
  useLayoutEffect(() => {
    if (!open) return
    reposition()
    window.addEventListener('scroll', reposition, true)
    window.addEventListener('resize', reposition)
    return () => {
      window.removeEventListener('scroll', reposition, true)
      window.removeEventListener('resize', reposition)
    }
  }, [open, reposition])

  /*
   * Scroll the highlighted row into view when moving by keyboard, which is the
   * only time the highlight can leave the visible slice. The row is found by
   * its index attribute rather than by child position, because group headings
   * sit among the options and would shift every position by one.
   */
  useEffect(() => {
    if (!open || !listRef.current) return
    const node = listRef.current.querySelector(`[data-index="${active}"]`)
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
        if (next < 0) return ordered.length - 1
        if (next >= ordered.length) return 0
        return next
      })
    } else if (event.key === 'Enter') {
      const option = ordered[active]
      if (open && option) {
        event.preventDefault()
        choose(option)
      }
    } else if (event.key === 'Escape') {
      setOpen(false)
    }
  }

  let index = -1

  return (
    <div ref={rootRef} className="relative flex-1 min-w-[240px]">
      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-content-dim pointer-events-none">
        <IconSearch size={14} />
      </span>

      <input
        role="combobox"
        aria-expanded={open}
        aria-controls="combobox-list"
        aria-activedescendant={open && ordered[active] ? `combobox-option-${active}` : undefined}
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
          transition-transform ${open ? 'rotate-90' : ''}`}
      >
        <IconChevron size={13} />
      </span>

      {open && rect && createPortal(
        <div
          ref={menuRef}
          id="combobox-list"
          role="listbox"
          aria-label={ariaLabel}
          style={{
            position: 'fixed',
            left: rect.left,
            top: rect.top,
            width: rect.width,
            maxHeight: rect.maxHeight,
          }}
          className="z-[300] flex flex-col overflow-hidden bg-surface-card border border-border
            rounded-card shadow-float"
        >
          {ordered.length === 0 ? (
            <div className="px-4 py-6 text-center">
              <p className="text-xs tracking-body text-content-dim">
                Nothing matches “{query.trim()}”.
              </p>
              {emptyHint && (
                <p className="text-2xs text-content-muted mt-1.5">{emptyHint}</p>
              )}
            </div>
          ) : (
            <>
              <div ref={listRef} className="flex-1 min-h-0 overflow-y-auto py-1">
                {groups.map((group) => (
                  <div key={group.name || 'ungrouped'} role="group" aria-label={group.name}>
                    {group.name && (
                      <div
                        className="sticky top-0 z-10 bg-surface-card flex items-baseline gap-2
                          px-3.5 pt-2.5 pb-1.5 font-mono text-2xs uppercase tracking-label
                          text-content-muted"
                      >
                        <span>{group.name}</span>
                        <span className="ml-auto">{group.items.length}</span>
                      </div>
                    )}

                    {group.items.map((option) => {
                      index += 1
                      const position = index
                      const highlighted = position === active
                      return (
                        <div
                          key={option.value}
                          id={`combobox-option-${position}`}
                          data-index={position}
                          role="option"
                          aria-selected={option.value === value}
                          onMouseEnter={() => setActive(position)}
                          onClick={() => choose(option)}
                          /* The highlight is a left rail plus brighter text, not
                             a filled block. The design system asks interactive
                             states to change opacity and emphasis rather than
                             swap backgrounds. */
                          className={`px-3.5 py-2 cursor-pointer border-l-2 transition-opacity
                            ${highlighted
                              ? 'border-l-accent-blue'
                              : 'border-l-transparent hover:opacity-75'}`}
                        >
                          <div className="flex items-baseline gap-2.5">
                            <span
                              className={`flex-1 min-w-0 truncate text-sm tracking-body
                                ${highlighted ? 'text-content-primary' : 'text-content-secondary'}`}
                            >
                              {option.label}
                            </span>
                            {option.badge && <span className="flex-none">{option.badge}</span>}
                          </div>

                          {(option.hint || option.meta?.length) && (
                            <div
                              className="flex items-center gap-1.5 mt-0.5 overflow-hidden
                                whitespace-nowrap font-mono text-2xs text-content-muted"
                            >
                              {option.hint && <span className="truncate">{option.hint}</span>}
                              {option.meta?.map((fact, position) => (
                                <span
                                  key={`${position}-${fact}`}
                                  className="flex items-center gap-1.5 flex-none"
                                >
                                  <span aria-hidden="true" className="opacity-40">/</span>
                                  <span>{fact}</span>
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                ))}
              </div>

              <div
                className="flex-none flex items-center justify-between gap-3 px-3.5 py-2
                  border-t border-border text-2xs text-content-muted"
              >
                <span>
                  {query.trim()
                    ? `${ordered.length} of ${options.length} matching “${query.trim()}”`
                    : `${options.length} ${noun}`}
                </span>
                <span className="flex items-center gap-1.5">
                  <Key>↑</Key>
                  <Key>↓</Key>
                  <span>move</span>
                  <Key>↵</Key>
                  <span>select</span>
                  <Key>esc</Key>
                  <span>close</span>
                </span>
              </div>
            </>
          )}
        </div>,
        document.body,
      )}
    </div>
  )
}

/** A key cap in the footer hint, using the design system's key gradient. */
function Key({ children }: { children: ReactNode }) {
  return (
    <kbd className="font-mono text-2xs px-1.5 rounded border border-border bg-key text-content-dim">
      {children}
    </kbd>
  )
}
