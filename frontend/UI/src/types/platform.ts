export type PlatformId = 'aws' | 'azure' | 'gcp' | 'ai' | 'k8s'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export type ThreatOrigin = 'russia' | 'china' | 'nk' | 'iran' | 'unknown'

export interface Technique {
  id: string
  name: string
}

export interface AttackPhase {
  phase: number
  name: string
  techniques: Technique[]
}

export interface MitreMapping {
  id: string
  name: string
  tactic: string
  platform: string
  description: string
}

export interface Reference {
  icon: string
  title: string
  source: string
  type: string
  color: string
}

/** Enterprise emulation package — driven by the backend MANIFEST and API. */
export interface Emulation {
  id: string
  name: string
  origin: ThreatOrigin
  originLabel: string
  tags: string[]
  techniqueCount: number
  severity: Severity
  aliases: string
  attribution: string
  activeSince: string
  targets: string
  incidents: string[]
  attackPath: AttackPhase[]
  mitreMappings: MitreMapping[]
  references: Reference[]
  phaseCount?: number
  schemaVersion?: number
}

export interface DetectionRule {
  title: string
  code: string
}

export interface DetectionData {
  emulationType?: string
  displayName?: string
  sigma: DetectionRule[]
  kql: DetectionRule[]
  totalCount: number
  formats: string
}

export interface Guardrails {
  excluded: string[]
  schedule: string
  scopeLimits: string[]
}

export interface PlaybookStep {
  title: string
  body: string
  code?: string
}

export interface Playbook {
  steps: PlaybookStep[]
}

export interface PlaybookRaw {
  emulationType: string
  displayName: string
  content: string
}

export interface PlatformData {
  emulations: Emulation[]
  detections: DetectionData
  guardrails: Guardrails
  playbooks: Playbook[]
}

export interface PlatformMeta {
  id: PlatformId
  label: string
  icon: string
  route: string
  badgeCount: number
}

/* ── Stack (mirrors backend infrastructure.Stack model) ── */

export type StackStatus =
  | 'pending'
  | 'deploying'
  | 'ready'
  | 'destroying'
  | 'refreshing'
  | 'failed'
  | 'ec2_booting'
  | 'ready_for_attack'
  | 'attacking'
  | 'attack_complete'
  | 'destroyed'

/** One captured Pulumi output line with the time it was emitted. */
export interface StackLogEntry {
  /** ISO-8601 UTC timestamp. */
  t: string
  line: string
}

/**
 * Actual deployed-resource inventory derived from Pulumi state on the last
 * successful deploy/refresh. `by_type` powers the card's resource counts;
 * `resources` powers resource-name search.
 */
export interface StackResourceSummary {
  total: number
  by_type: Record<string, number>
  /** Graph nodes. `urn` is the stable id used for edges. */
  resources: Array<{ urn: string; name: string; type: string }>
  /**
   * Dependency edges (from = depended-upon, to = dependent).
   * Optional: stacks deployed before M2 have a resource_summary with no edges
   * key, so consumers must treat this as possibly undefined.
   */
  edges?: Array<{ from: string; to: string }>
}

export interface Stack {
  id: string
  name: string
  region: string
  status: StackStatus
  outputs: Record<string, unknown>
  owner: string
  emulation_type?: string
  expires_at?: string | null
  /** Persisted log of the most recent operation (Milestone 1 Phase 2). */
  last_logs?: StackLogEntry[]
  /** Failure reason from the most recent operation; empty on success. */
  last_error?: string
  /** Actual deployed-resource inventory; empty before first deploy. */
  resource_summary?: StackResourceSummary
  created_at: string
  updated_at: string
}

export interface CreateStackRequest {
  name: string
  region?: string
}

export interface StackActionResponse {
  stack: Stack
  task_id: string
}

/**
 * Live deployment progress for a stack, returned by GET /api/stacks/{id}/progress/.
 *
 * Backed by the Celery task's PROGRESS state in Redis, so values stay current
 * within a few seconds while a deploy is running. `recent_logs` is ephemeral
 * (it disappears once the task result expires) — persisted deployment logs
 * arrive in Milestone 1 Phase 2.
 */
export interface StackProgress {
  stack_id: string
  status: StackStatus
  resources_created: number
  total_resources: number
  percentage: number
  recent_logs: string[]
}

/* ── Enterprise EmulationRun (mirrors backend EmulationRun model) ── */

export type EmulationRunStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface EmulationRunRecord {
  id: string
  stack: string
  emulation_type: string
  status: EmulationRunStatus
  phase_current: number
  phase_total: number
  stdout: string
  stderr: string
  triggered_by: string
  started_at: string | null
  completed_at: string | null
  created_at: string
}

export interface DeployEmulationResponse {
  stackId: string
  stackName: string
}

export interface TriggerAttackResponse {
  runId: string
  stackId: string
}

export interface EmulationEstimate {
  emulationType: string
  displayName: string
  resources: Array<{ name: string; count: number; cost_per_hour_usd: number }>
  totalCostPerHourUsd: number
  defaultTtlHours: number
  estimatedTotalUsd: number
  note: string
}

