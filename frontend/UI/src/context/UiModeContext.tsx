import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'

/**
 * Global UI mode — one switch, whole app.
 *
 * 'classic'  the original, technical surface (jargon, the old dashboard).
 * 'new'      the plain-language surface: command-center dashboard, human nav
 *            labels, "caught/missed" instead of "fired/silent".
 *
 * Promoted from the dashboard-local toggle so the same control reframes the
 * nav and the coverage report too, and so a single flip back to 'classic'
 * rolls the entire experience back. Default is 'classic' — nothing changes
 * until someone opts in, which keeps the before/after demo and rollback clean.
 */

export type UiMode = 'classic' | 'new'

const STORAGE_KEY = 'mt:ui-mode'

function readMode(): UiMode {
    try {
        return localStorage.getItem(STORAGE_KEY) === 'new' ? 'new' : 'classic'
    } catch {
        return 'classic'
    }
}

interface UiModeValue {
    mode: UiMode
    plain: boolean
    setMode: (m: UiMode) => void
    toggle: () => void
}

const UiModeContext = createContext<UiModeValue>({
    mode: 'classic',
    plain: false,
    setMode: () => {},
    toggle: () => {},
})

export function UiModeProvider({ children }: { children: ReactNode }) {
    const [mode, setModeState] = useState<UiMode>(readMode)

    const setMode = useCallback((m: UiMode) => {
        setModeState(m)
        try {
            localStorage.setItem(STORAGE_KEY, m)
        } catch {
            /* private mode — the switch still works for this session */
        }
    }, [])

    // Flip from the *current state*, not from storage. Reading storage here
    // meant that when localStorage is unavailable (private mode, blocked site
    // data) readMode() always answered 'classic', so the switch would go to
    // 'new' once and then stick there.
    const toggle = useCallback(
        () =>
            setModeState((prev) => {
                const next: UiMode = prev === 'new' ? 'classic' : 'new'
                try {
                    localStorage.setItem(STORAGE_KEY, next)
                } catch {
                    /* private mode - the switch still works for this session */
                }
                return next
            }),
        [],
    )

    return (
        <UiModeContext.Provider value={{ mode, plain: mode === 'new', setMode, toggle }}>
            {children}
        </UiModeContext.Provider>
    )
}

/** Read the global UI mode. `plain` is the convenient boolean (mode === 'new'). */
export function useUiMode(): UiModeValue {
    return useContext(UiModeContext)
}
