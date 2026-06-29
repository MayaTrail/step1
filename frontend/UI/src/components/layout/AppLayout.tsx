import { useState, useCallback, useEffect } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { TopNav } from './TopNav'
import { Sidebar } from './Sidebar'
import { SearchPalette } from '@/components/search/SearchPalette'

export function AppLayout() {
  const [searchOpen, setSearchOpen] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const location = useLocation()

  const openSearch = useCallback(() => setSearchOpen(true), [])
  const closeSearch = useCallback(() => setSearchOpen(false), [])
  const toggleSidebar = useCallback(() => setSidebarOpen(v => !v), [])
  const closeSidebar = useCallback(() => setSidebarOpen(false), [])

  // Close mobile sidebar on route change
  useEffect(() => {
    setSidebarOpen(false)
  }, [location.pathname])

  // Keyboard shortcuts: Cmd/Ctrl-K or "/" to open search, Escape to close.
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault()
        openSearch()
      }
      if (e.key === '/' && !searchOpen && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
        e.preventDefault()
        openSearch()
      }
      if (e.key === 'Escape') {
        if (searchOpen) closeSearch()
        else if (sidebarOpen) closeSidebar()
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [searchOpen, sidebarOpen, openSearch, closeSearch, closeSidebar])

  return (
    <div className="h-screen flex flex-col overflow-hidden bg-surface-deep">
      <TopNav onOpenSearch={openSearch} onToggleSidebar={toggleSidebar} />

      <div className="flex flex-1 overflow-hidden relative">
        {/* Mobile backdrop — sits above content, below sidebar */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 top-[58px] bg-black/60 z-[140] lg:hidden"
            onClick={closeSidebar}
          />
        )}

        <Sidebar isOpen={sidebarOpen} onClose={closeSidebar} />

        <main className="flex-1 overflow-hidden relative min-w-0">
          <div className="h-full overflow-y-auto px-6 lg:px-8 py-7 animate-fadeIn">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Global command palette */}
      {searchOpen && <SearchPalette onClose={closeSearch} />}
    </div>
  )
}
