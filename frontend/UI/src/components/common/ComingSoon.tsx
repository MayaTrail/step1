import type { ReactNode } from 'react'
import { EmptyState } from '@/components/ui/EmptyState'

interface ComingSoonProps {
  /** SVG icon node shown in the framed circle. */
  icon: ReactNode
  /** Page title, e.g. "Active Runs". */
  title: string
  /** Supporting sentence explaining what will live here. */
  body: string
}

/**
 * Honest placeholder for navigation destinations whose data layer does not
 * exist yet (e.g. Active Runs / Results need an EmulationRun list endpoint,
 * Reports and Documentation are unbuilt). Keeps the new information
 * architecture fully navigable without faking content.
 */
export function ComingSoon({ icon, title, body }: ComingSoonProps) {
  return <EmptyState icon={icon} title={title} body={body} />
}
