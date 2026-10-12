/**
 * Plain-language readings of Scout's attack paths.
 *
 * Scout reports a path as ARNs, a 0-100 risk score, an impact enum and a
 * mechanism name per step. The page needs words a security engineer can act
 * on, so the translations live here, in one place, and every one of them is
 * derived from a field Scout actually sent. Nothing here invents a fact about
 * the account: when a value has no reading, the raw value is shown instead.
 */

import type { AttackChain, ChainStep } from '@/types/attackGraph'

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

/**
 * Severity bands over Scout's risk score (agreed with the product owner).
 * A missing score reads as Low rather than hiding the path.
 */
export function severityOf(score: number | null): Severity {
  if (score === null) return 'Low'
  if (score >= 75) return 'Critical'
  if (score >= 60) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

export const SEVERITY_TEXT: Record<Severity, string> = {
  Critical: 'text-danger',
  High: 'text-danger',
  Medium: 'text-warning',
  Low: 'text-content-secondary',
}

/** "FULL_ACCOUNT_COMPROMISE" -> "Full account compromise". */
export function impactLabel(impact: string | null): string {
  if (!impact) return 'Unspecified impact'
  const words = impact.toLowerCase().replace(/_/g, ' ')
  return words.charAt(0).toUpperCase() + words.slice(1)
}

export interface PathNode {
  id: string
  /** "IAM user", "IAM role", "Resource", ... */
  kind: string
  /** The resource segment after its type prefix: "ops-admin" for user/ops-admin. */
  name: string
  /** Last four digits of the owning account, or "" when the ARN has none. */
  accountTail: string
}

const KIND_LABEL: Record<string, string> = {
  user: 'IAM user',
  role: 'IAM role',
  group: 'IAM group',
  root: 'Account root',
  'assumed-role': 'Assumed role',
  'instance-profile': 'Instance profile',
  policy: 'IAM policy',
}

/**
 * A node read from an ARN, the same way the backend's envelope._node reads it.
 *
 * arn:aws:iam::111122223333:role/deploy-role -> IAM role "deploy-role", account …3333.
 * Non-IAM ARNs (an S3 bucket, a Lambda function) keep their service as the kind.
 */
export function nodeFromArn(arn: string): PathNode {
  const parts = arn.split(':')
  const service = parts[2] ?? ''
  const account = parts[4] ?? ''
  const resource = parts.slice(5).join(':')
  const slash = resource.indexOf('/')
  const prefix = slash === -1 ? '' : resource.slice(0, slash)
  const name = slash === -1 ? resource : resource.slice(slash + 1)
  const kind = service === 'iam' || service === 'sts'
    ? KIND_LABEL[prefix] ?? 'IAM entity'
    : service ? `${service.toUpperCase()} resource` : 'Entity'
  return {
    id: arn,
    kind,
    name: name || arn || 'unknown',
    accountTail: account.length >= 4 ? account.slice(-4) : '',
  }
}

/** The ordered identities a path walks through, from source to the last hop's target. */
export function pathNodes(chain: AttackChain): PathNode[] {
  const first = chain.steps[0]
  if (!first) return [nodeFromArn(chain.source.arn)]
  return [nodeFromArn(first.from), ...chain.steps.map((step) => nodeFromArn(step.to))]
}

/**
 * The IAM calls behind one step, from Scout's concrete API sequence.
 *
 * Entries look like "iam:CreateAccessKey(UserName=ops-admin)". Entries in angle
 * brackets ("<lambda: launch compute ...>") describe an effect rather than an
 * IAM call, so they are left out. Duplicates collapse; order is kept.
 */
export function stepCalls(step: ChainStep): string[] {
  const calls: string[] = []
  for (const entry of step.concrete_api_sequence) {
    const call = /^([a-z0-9-]+:[A-Za-z0-9]+)/.exec(entry.trim())?.[1]
    if (call && !calls.includes(call)) calls.push(call)
  }
  return calls
}

/**
 * One sentence on how a step works, keyed on Scout's mechanism name.
 *
 * Covers the mechanisms Scout's chain builder emits most often; any other one
 * falls back to naming the mechanism itself rather than guessing at it.
 */
const MECHANISM_SENTENCE: Record<string, (from: string, to: string) => string> = {
  credential: (from, to) => `${from} can create credentials for ${to} and act as it.`,
  service_credential: (from, to) => `${from} can obtain service credentials that act as ${to}.`,
  assume_role: (from, to) => `${from} is allowed to assume ${to}.`,
  passrole_service: (from, to) => `${from} can hand ${to} to a service it controls, then run code as ${to}.`,
  existing_passrole: (from, to) => `${from} can take over a service that already runs as ${to}.`,
  trust_rewrite: (from, to) => `${from} can rewrite ${to}'s trust policy to let itself in.`,
  add_to_group: (from, to) => `${from} can add itself to ${to} and inherit its permissions.`,
  policy_version_rewrite: (from, to) => `${from} can rewrite a policy that applies to ${to} and widen it.`,
  ssm_run_command: (from, to) => `${from} can run commands on an instance that runs as ${to}.`,
  instance_profile: (from, to) => `${from} can attach ${to} to an instance it controls.`,
  lambda_role_overwrite: (from, to) => `${from} can change a Lambda function to run as ${to}.`,
  ec2_instance_connect: (from, to) => `${from} can open a shell on an instance that runs as ${to}.`,
  ecs_exec: (from, to) => `${from} can open a shell in a container that runs as ${to}.`,
  direct_iam: (from, to) => `${from} already holds permissions that reach ${to}.`,
  resource_access: (from, to) => `${from} can read ${to}.`,
  resource_control: (from, to) => `${from} can change or run ${to}.`,
}

export function stepSentence(step: ChainStep): string {
  const from = nodeFromArn(step.from).name
  const to = nodeFromArn(step.to).name
  const sentence = MECHANISM_SENTENCE[step.mechanism]
  if (sentence) return sentence(from, to)
  return `${from} reaches ${to} through ${step.mechanism.replace(/_/g, ' ') || 'a step Scout did not name'}.`
}

/** "dev-alice → full account compromise, 2 steps" (or "already holds ..." when there are none). */
export function pathTitle(chain: AttackChain): string {
  const origin = nodeFromArn(chain.source.arn).name
  const impact = impactLabel(chain.terminal_impact).toLowerCase()
  if (chain.steps.length === 0) return `${origin} already holds ${impact}`
  return `${origin} → ${impact}, ${chain.steps.length} step${chain.steps.length > 1 ? 's' : ''}`
}
