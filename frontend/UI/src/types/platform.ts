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
}

export interface DetectionRule {
  title: string
  code: string
}

export interface DetectionData {
  ruleCount: number
  formats: string
  rules: DetectionRule[]
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

export type StackStatus = 'pending' | 'deploying' | 'ready' | 'destroying' | 'refreshing' | 'failed'

export interface Stack {
  id: string
  name: string
  region: string
  status: StackStatus
  outputs: Record<string, unknown>
  owner: string
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

/* ── Simulation Module (from GET /api/simulations/modules/) ── */

export interface SimulationModule {
  id: number
  name: string
  description: string
}

/* ── Simulation Run (mirrors backend SimulationRun model) ── */

export type SimulationStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface SimulationRun {
  id: string
  stack: string
  module: string
  status: SimulationStatus
  stdout: string
  stderr: string
  triggered_by: string
  started_at: string | null
  completed_at: string | null
  created_at: string
}

export interface TriggerSimulationRequest {
  stack_id: string
  module_id: number
}

export interface TriggerSimulationResponse {
  run: SimulationRun
  task_id: string
}

/**
 * Maps UI emulation IDs to backend simulation module IDs.
 * IDs correspond to the `id` field from GET /api/simulations/modules/.
 */
export const EMULATION_MODULE_MAP: Record<string, number> = {
  'priv-esc-attach-role-policy': 1,
  'iam-enumeration': 2,
  'eventual-consistency-attack': 3,
  's3-initial-access': 4,
  's3-kms-ransomware': 5,
}
