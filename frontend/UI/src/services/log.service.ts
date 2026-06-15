/**
 * Log Service — API calls for the audit log feed.
 *
 * Endpoint:
 *   GET /api/logs/ → list log entries relevant to the authenticated user
 *
 * The endpoint is not paginated, so it returns a plain array. Entries are
 * sorted newest-first and trimmed client-side for the dashboard's Recent
 * Activity feed.
 */

import api from './api'
import type { LogEntry } from '@/types/log'

/**
 * List recent log entries, newest first.
 *
 * @param limit - Maximum number of entries to return (default 20).
 */
export async function listLogs(limit = 20): Promise<LogEntry[]> {
  const { data } = await api.get<LogEntry[]>('/logs/')
  // Guard: if the SPA fallback returns HTML, or the shape is unexpected.
  if (!Array.isArray(data)) return []
  return [...data]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit)
}
