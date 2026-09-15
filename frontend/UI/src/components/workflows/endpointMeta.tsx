import { useState } from 'react'
import { IconCheck, IconCopy } from '@/components/ui/Icons'

/**
 * Pieces shared between the endpoints table and the endpoint panel.
 *
 * Extracted so the panel does not import from the section that renders it,
 * which would be a cycle.
 */

/**
 * Build the URL a SIEM posts to.
 *
 * Composed client-side from the current origin, so it is right whether the
 * platform is reached on localhost or a customer's own hostname.
 *
 * @param endpointId - UUID of the endpoint.
 * @returns The absolute webhook URL.
 */
export function endpointUrl(endpointId: string): string {
  return `${window.location.origin}/api/workflows/alerts/${endpointId}/`
}

interface CopyValueProps {
  value: string
  /** Rendered in place of the value, for a secret that is still masked. */
  masked?: boolean
}

/** A value with a copy button, for things that must be transcribed exactly. */
export function CopyValue({ value, masked = false }: CopyValueProps) {
  const [copied, setCopied] = useState(false)

  return (
    <span className="flex items-center gap-1.5 min-w-0">
      <code
        className="min-w-0 flex-1 truncate bg-surface-base border border-border rounded px-2 py-1
          font-mono text-2xs text-content-secondary"
      >
        {masked ? '•'.repeat(32) : value}
      </code>
      {/* The confirmation swaps one 12px glyph for another rather than for the
          word "copied". Text is wider than the icon, so the button grew, shoved
          the row's neighbours aside, and snapped back a second and a half
          later. A same-size swap cannot move anything. */}
      <button
        type="button"
        disabled={masked}
        onClick={() => {
          navigator.clipboard?.writeText(value)
          setCopied(true)
          window.setTimeout(() => setCopied(false), 1500)
        }}
        aria-label={copied ? 'Copied' : 'Copy'}
        className={`shrink-0 p-1 rounded-btn transition-colors disabled:opacity-30
          ${copied ? 'text-safe' : 'text-content-dim hover:text-content-primary'}`}
      >
        {copied ? <IconCheck size={12} /> : <IconCopy size={12} />}
      </button>
    </span>
  )
}
