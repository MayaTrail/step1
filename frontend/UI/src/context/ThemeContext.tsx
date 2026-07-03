import { useEffect, type ReactNode } from 'react'

/**
 * The app is dark-only; the light/white theme has been removed.
 *
 * The design system's CSS variables default to dark under :root, so this
 * provider just pins document.documentElement to the dark theme on mount,
 * overriding any preference previously stored in localStorage.
 */
export function ThemeProvider({ children }: { children: ReactNode }) {
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', 'dark')
  }, [])
  return <>{children}</>
}
