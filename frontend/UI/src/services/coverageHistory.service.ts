/**
 * Coverage-over-time, regressions, and scheduled runs.
 *
 * The continuous-assurance surface: a coverage trend across runs, the
 * fired -> silent regressions since the last run, and recurring schedules.
 */

import api from './api'
import type {
  CoverageTrendPoint,
  RegressionReport,
  ScheduleCadence,
  ScheduledRun,
} from '@/types'

export async function getCoverageTrend(emulationType?: string): Promise<CoverageTrendPoint[]> {
  const { data } = await api.get<{ points: CoverageTrendPoint[] }>('/emulations/coverage-trend/', {
    params: emulationType ? { emulation_type: emulationType } : {},
  })
  return data.points
}

export async function getRunRegressions(runId: string): Promise<RegressionReport> {
  const { data } = await api.get<RegressionReport>(`/emulations/${runId}/regressions/`)
  return data
}

export async function listSchedules(): Promise<ScheduledRun[]> {
  const { data } = await api.get<ScheduledRun[]>('/emulations/schedules/')
  return data
}

export async function createSchedule(
  emulationType: string,
  cadence: ScheduleCadence,
): Promise<ScheduledRun> {
  const { data } = await api.post<ScheduledRun>('/emulations/schedules/', {
    emulation_type: emulationType,
    cadence,
  })
  return data
}

export async function updateSchedule(
  id: string,
  patch: { enabled?: boolean; cadence?: ScheduleCadence },
): Promise<ScheduledRun> {
  const { data } = await api.patch<ScheduledRun>(`/emulations/schedules/${id}/`, patch)
  return data
}

export async function deleteSchedule(id: string): Promise<void> {
  await api.delete(`/emulations/schedules/${id}/`)
}

export async function getAssuranceSummary(): Promise<import('@/types').AssuranceSummary> {
  const { data } = await api.get('/emulations/assurance/')
  return data
}
