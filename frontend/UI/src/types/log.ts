/**
 * Types for the logs endpoint (/api/logs/).
 *
 * LogEntry is the immutable audit record written by Celery tasks and views.
 * The endpoint returns entries relevant to the authenticated user (their own
 * actions plus events on stacks they own), newest activity included.
 */

export type LogLevel = 'info' | 'warning' | 'error'

/**
 * Well-known event names emitted by the backend.  Typed as a loose string so a
 * newly emitted event (e.g. a future detection.added) renders gracefully
 * instead of breaking the feed.
 */
export type LogEvent =
  | 'stack.deployed'
  | 'stack.destroyed'
  | 'emulation.started'
  | 'emulation.completed'
  | 'emulation.failed'
  | (string & {})

export interface LogEntry {
  id: string
  level: LogLevel
  event: LogEvent
  message: string
  /** Username of the actor, or null if the entry has no associated user. */
  actor: string | null
  /** UUID of the referenced stack, or null. */
  stack: string | null
  /** ISO 8601 timestamp. */
  timestamp: string
}
