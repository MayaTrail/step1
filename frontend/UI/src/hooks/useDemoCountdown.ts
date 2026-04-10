import { useState, useEffect } from 'react'

interface DemoCountdown {
  /** Milliseconds remaining until demo expiry. Null when there is no active demo session. */
  remaining: number | null
  /** True when the countdown has reached zero. */
  isExpired: boolean
  /** True when the user is a demo user with a known expiry time. */
  isActive: boolean
}

/**
 * Tracks the remaining time on a demo session.
 *
 * Accepts the ISO-formatted expiry timestamp from the user object
 * (user.demoExpiresAt) and returns a live countdown that ticks
 * every second. Components consuming this hook re-render once per
 * second while the countdown is active.
 *
 * @param demoExpiresAt - ISO timestamp string, or null/undefined
 *                        when the user is not in demo mode.
 */
export function useDemoCountdown(demoExpiresAt: string | null | undefined): DemoCountdown {
  const [remaining, setRemaining] = useState<number | null>(null)

  useEffect(() => {
    if (!demoExpiresAt) {
      setRemaining(null)
      return
    }

    const expiresAt = new Date(demoExpiresAt).getTime()

    const update = () => {
      const diff = expiresAt - Date.now()
      setRemaining(Math.max(0, diff))
    }

    update()
    const interval = setInterval(update, 1000)
    return () => clearInterval(interval)
  }, [demoExpiresAt])

  return {
    remaining,
    isExpired: remaining !== null && remaining <= 0,
    isActive: remaining !== null,
  }
}

/**
 * Formats a millisecond duration as M:SS.
 *
 * @param ms - Duration in milliseconds (clamped to >= 0).
 */
export function formatCountdown(ms: number): string {
  const totalSec = Math.ceil(ms / 1000)
  const min = Math.floor(totalSec / 60)
  const sec = totalSec % 60
  return `${min}:${sec.toString().padStart(2, '0')}`
}
