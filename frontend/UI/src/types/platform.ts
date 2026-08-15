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
  /** Human-readable publisher/date line, e.g. "Sysdig TRT · sysdig.com · Feb 2023". */
  source: string
  /** Canonical link to the source; when present the card opens it in a new tab. */
  url?: string
  type: string
  color: string
}

/** Enterprise emulation package — driven by the backend MANIFEST and API. */
export interface Emulation {
  id: string
  name: string
  /** Short summary from the MANIFEST; shown on library cards. */
  description?: string
  /** Owning platform, derived from the MANIFEST (defaults to 'aws'). */
  platform: PlatformId
  /** Month the emulation was added ("YYYY-MM"); drives "Recently Added" ordering. */
  added?: string
  /** Cloud services this emulation exercises; drives Attack Surface Coverage. */
  services?: string[]
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
  /** Authored static estimate of attack runtime in minutes (Overview key metric). */
  estimatedDurationMinutes?: number
  /** Authored static hourly cost of the deployed stack; combined with TTL for a per-run figure. */
  estimatedCostPerHourUsd?: number
  /** Hours before the stack auto-destroys; drives Prerequisites + Safety copy. */
  defaultTtlHours?: number
  /** Total AWS resources the emulation provisions (0 for self-cleaning atomics). */
  totalResources?: number
  /** Coarse resource footprint from the MANIFEST (EC2 count, instance types, feature flags). */
  resources?: {
    ec2_count?: number
    instance_types?: string[]
    uses_lambda?: boolean
    uses_secrets_manager?: boolean
    uses_cloudtrail?: boolean
  }
  schemaVersion?: number
}

/* ── AI assistant connector (mirrors backend apps.ai) ── */

export type LLMProvider = 'openai' | 'anthropic' | 'bedrock'

/** Masked connector shape returned by GET /api/ai/connector/. Never carries the key. */
export interface LLMConnector {
  provider: LLMProvider | null
  model: string | null
  /** AWS region for the bedrock provider; empty/null for key-based providers. */
  region?: string | null
  enabled: boolean
  has_key: boolean
  /** Last 4 chars of the stored key, for masked display. */
  key_hint?: string
  updated_at?: string
}

export interface LLMConnectorTestResult {
  ok: boolean
  detail: string
}

export type ChatRole = 'user' | 'assistant'

export interface ChatMessage {
  id: string
  role: ChatRole
  content: string
  created_at: string
}

/** A persisted multi-turn conversation about one emulation (mirrors apps.ai). */
export interface Conversation {
  id: string
  emulation_type: string
  title: string
  created_at: string
  updated_at: string
  /** Present on the detail fetch; omitted from list responses. */
  messages?: ChatMessage[]
}

/**
 * One rule in the detection library, grouping the Sigma and KQL variants for
 * a single technique. Code bodies are inlined so the master-detail preview
 * pane needs no follow-up request.
 */
export interface DetectionRuleSummary {
  ruleId: string
  technique: TechniqueRef
  title: string
  severity: string
  logSource: { product?: string; service?: string }
  formats: { sigma: boolean; kql: boolean }
  sigma: string | null
  kql: string | null
}

export interface DetectionData {
  emulationType?: string
  displayName?: string
  totalCount: number
  formats: string
  rules: DetectionRuleSummary[]
}

export type ValidationVerdict = 'matched' | 'missed' | 'quiet' | 'false positive' | 'caught'

/** One synthetic test event, its expected behaviour, and the rule's verdict. */
export interface ValidationScenario {
  label: 'positive' | 'benign' | 'evasion'
  rationale: string
  event: Record<string, unknown>
  expected: boolean
  matched: boolean
  verdict: ValidationVerdict
  firedSelections: string[]
}

/**
 * Ephemeral result of validating a Sigma rule against AI-generated events.
 * When `evaluable` is false (aggregation rules), only `reason` is populated.
 */
export interface DetectionValidation {
  evaluable: boolean
  reason?: string
  fidelity?: number
  summary?: { positiveHit: string; benignQuiet: string; evasionCaught: string }
  scenarios?: ValidationScenario[]
  suggestions?: string[]
}

/** MITRE technique reference: id plus, when available, name and tactic. */
export interface TechniqueRef {
  id: string
  name?: string
  tactic?: string
}

/** Detection coverage for the parent emulation (counts, not fabricated rates). */
export interface DetectionCoverage {
  techniquesCovered: number
  techniquesTotal: number
  phasesCovered: number
  phasesTotal: number
}

/**
 * Full detail for a single detection rule, keyed by its technique id.
 * Every field is parsed from the rule's own Sigma frontmatter or the parent
 * emulation's MANIFEST. No validation metrics are included at this stage.
 */
export interface DetectionDetail {
  emulationType: string
  displayName: string
  ruleId: string
  technique: TechniqueRef
  title: string
  description: string
  status: string
  severity: string
  logSource: { product?: string; service?: string }
  tags: string[]
  author: string
  date: string
  falsePositives: string[]
  references: string[]
  note: string | null
  threatActor: string
  hasPlaybook: boolean
  relatedTechniques: TechniqueRef[]
  services: string[]
  coverage: DetectionCoverage
  formats: { sigma: boolean; kql: boolean }
  sigma: string | null
  kql: string | null
}

/**
 * Service control policies attach to a principal, resource control policies to
 * a resource. The split is derived from the policy document, not authored.
 */
export type GuardrailType = 'SCP' | 'RCP'

/** The upstream repository a policy was copied from, so a reader can verify it. */
export interface GuardrailSource {
  label: string
  url: string
}

/**
 * One preventive policy as the library index lists it.
 *
 * `purpose` is the one-line description and doubles as the display title;
 * these policies have no separate name worth showing.
 */
export interface GuardrailSummary {
  id: string
  type: GuardrailType
  purpose: string
  /** AWS services the policy constrains; ["All services"] when it is org-wide. */
  services: string[]
  source: GuardrailSource
}

/** A single policy with its document, from the detail endpoint. */
export interface GuardrailDetail extends GuardrailSummary {
  /** Policy filename on disk, for tracing an entry back to its source repo. */
  file: string
  /** The policy document verbatim. */
  code: string
}

/**
 * The library index. Policy documents are excluded: the list never renders
 * them and carrying all of them would roughly triple the payload.
 */
export interface GuardrailLibrary {
  guardrails: GuardrailSummary[]
  totalCount: number
  formats: string
}

/** One H2 section of a PLAYBOOK.md, kept as raw markdown so it renders faithfully. */
export interface PlaybookSection {
  /** URL/tab-safe slug derived from the title. */
  id: string
  /** Section heading with any leading ordinal ("1. ") stripped. */
  title: string
  /** The section body as raw markdown (sub-headings, lists, tables, all code blocks). */
  markdown: string
}

export interface Playbook {
  /** The playbook's H1 title, if the document declares one. */
  title?: string
  sections: PlaybookSection[]
}

/** Result of attempting to run a playbook command via the backend runner. */
export interface CommandResult {
  /** False when the command is mutating, shell-using, or has unfilled placeholders. */
  runnable: boolean
  /** Why it is not runnable (present when runnable is false). */
  reason?: string
  /** True when the executed command exited 0. */
  ok?: boolean
  argv?: string[]
  returncode?: number
  stdout?: string
  stderr?: string
  /** Set when execution failed before running (e.g. assume-role error). */
  error?: string
}

export interface PlaybookRaw {
  emulationType: string
  displayName: string
  content: string
}

export interface PlatformData {
  emulations: Emulation[]
  detections: DetectionData
  guardrails: GuardrailLibrary
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

/**
 * How a detection rule fared against the logs archived for a run.
 *
 * `silent` and `no_logs` are deliberately distinct. A silent rule had telemetry
 * to work with and did not match, which is a finding about the rule or the
 * attack. A `no_logs` rule never saw its event source at all, so it was never
 * exercised and the fix belongs in the log pipeline.
 */
export type DetectionVerdict = 'fired' | 'silent' | 'no_logs'

/** The first matching event, shown only under a rule that fired. */
export interface DetectionEvidence {
  eventTime: string | null
  eventName: string | null
  eventSource: string | null
  sourceIPAddress: string | null
  /** Who triggered it, so an operator's own session is not read as the attack. */
  actor: string
  isEmulation: boolean
}

export interface DetectionRuleOutcome {
  ruleId: string
  title: string
  severity: string
  verdict: DetectionVerdict
  matchCount: number
  /** AWS event sources the rule needs; empty when it declares none. */
  requiredSources: string[]
  evidence: DetectionEvidence | null
  technique: { id?: string; name?: string; tactic?: string }
}

export interface DetectionCheck {
  status: 'ok' | 'not_configured' | 'unknown_emulation' | 'error'
  detail?: string
  window?: { start?: string; end?: string }
  eventCount?: number
  /** Event sources the archive actually carried for this window. */
  coveredSources?: string[]
  ruleCount?: number
  counts?: Record<DetectionVerdict, number>
  rules?: DetectionRuleOutcome[]
}

export interface EmulationRunRecord {
  id: string
  stack: string
  stack_name: string
  emulation_type: string
  status: EmulationRunStatus
  phase_current: number
  phase_total: number
  stdout: string
  stderr: string
  triggered_by: string
  triggered_by_email: string | null
  /** Null until the coverage check runs, about a minute after the attack ends. */
  detection_check: DetectionCheck | null
  started_at: string | null
  completed_at: string | null
  created_at: string
}

/**
 * One row in the Operations runs list (Active Runs / Results pages).
 *
 * Lighter than EmulationRunRecord: omits stdout/stderr (those load on the
 * per-run detail view) and adds display fields the table needs —
 * emulation_name, platform (derived from the registry), and stack_name.
 */
export interface EmulationRunListItem {
  id: string
  stack: string
  stack_name: string
  emulation_type: string
  emulation_name: string
  platform: PlatformId
  status: EmulationRunStatus
  phase_current: number
  phase_total: number
  triggered_by: string | null
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

