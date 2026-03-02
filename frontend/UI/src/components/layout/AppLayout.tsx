import { useState, useCallback, useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import { TopNav } from './TopNav'
import { Sidebar } from './Sidebar'

export function AppLayout() {
  const [searchOpen, setSearchOpen] = useState(false)

  const openSearch = useCallback(() => setSearchOpen(true), [])
  const closeSearch = useCallback(() => setSearchOpen(false), [])

  // Keyboard shortcut: "/" to open search, Escape to close
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === '/' && !searchOpen && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
        e.preventDefault()
        openSearch()
      }
      if (e.key === 'Escape' && searchOpen) {
        closeSearch()
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [searchOpen, openSearch, closeSearch])

  return (
    <div className="h-screen flex flex-col overflow-hidden bg-surface-deep">
      <TopNav onOpenSearch={openSearch} />

      <div className="flex flex-1 overflow-hidden">
        <Sidebar />

        <main className="flex-1 overflow-hidden relative">
          <div className="h-full overflow-y-auto px-8 py-7 animate-fadeIn">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Search overlay — placeholder until Step 10 */}
      {searchOpen && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[200] flex items-start justify-center pt-20"
          onClick={(e) => { if (e.target === e.currentTarget) closeSearch() }}
        >
          <div className="bg-surface-card border border-border rounded-card w-[600px] overflow-hidden animate-modalIn shadow-[0_12px_40px_rgba(0,0,0,0.6)]">
            <div className="flex items-center gap-3 px-5 py-4 border-b border-border">
              <span className="text-base">&#128269;</span>
              <input
                type="text"
                autoFocus
                placeholder="Search emulations, techniques, threat actors..."
                className="flex-1 bg-transparent border-none outline-none font-mono text-sm text-content-primary placeholder:text-content-dim"
              />
              <span
                onClick={closeSearch}
                className="font-mono text-[10px] text-content-dim cursor-pointer hover:text-content-secondary"
              >
                ESC
              </span>
            </div>
            <div className="p-2 max-h-[400px] overflow-y-auto">
              <div className="text-center py-8 text-content-dim font-mono text-xs">
                Start typing to search across all platforms...
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
