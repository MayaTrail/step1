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

export interface Stack {
  id: string
  name: string
  region: string
  status: StackStatus
  outputs: Record<string, unknown>
  owner: string
  emulation_type?: string
  expires_at?: string | null
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

