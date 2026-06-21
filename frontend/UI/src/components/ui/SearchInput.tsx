import { IconSearch } from './Icons'

interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
}

/**
 * Search input with a leading magnifier, styled to match the Operations
 * (Active Runs / Results) toolbars. Shared across the content-library hubs.
 */
export function SearchInput({ value, onChange, placeholder = 'Search…' }: SearchInputProps) {
  return (
    <div className="relative flex-1 min-w-[200px] max-w-sm">
      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-content-dim pointer-events-none">
        <IconSearch size={15} />
      </span>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-surface-base border border-border rounded-lg pl-9 pr-3 py-2 text-sm text-content-primary
          placeholder:text-content-dim outline-none transition-colors focus:border-border-active"
      />
    </div>
  )
}
