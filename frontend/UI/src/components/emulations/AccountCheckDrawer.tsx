import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { IconCheck, IconChevron, IconClose } from '@/components/ui/Icons'
import type {
  AccountCheck,
  AccountCheckError,
  CheckedAction,
  CheckedPhase,
  CheckIdentity,
  IdentityKind,
  IdentityStatus,
  PreventionAnalysis,
} from '@/types/prevention'

/**
 * What the account check asked AWS, and what AWS answered.
 *
 * The check is a single request, so there is no real progress to report.
 * Instead the drawer opens on the question itself (whose permissions, which
 * actions, which policy layers) and turns into the answer when it arrives.
 * A reader who saw the question understands what "allowed" can and cannot
 * mean before they see one.
 *
 * Colours follow the defender's point of view: green is a guardrail refusing,
 * yellow is a gap or a setup problem, and red is never used, because nothing
 * here is the platform failing.
 */

// Width and stacking are inline because the lint rule forbids bracket values.
// The clamp gives a full-width panel on a phone, half the screen on a laptop,
// and stops at 720px on a large monitor, matching the other drawers.
const PANEL_STYLE = { width: 'clamp(min(460px, 100vw), 50vw, 720px)' }
const OVERLAY_STYLE = { zIndex: 200 }

interface AccountCheckDrawerProps {
  open: boolean
  /** True while AWS is answering; the drawer shows the question. */
  running: boolean
  check: AccountCheck | null
  refusal: AccountCheckError | null
  /** The emulation's declared phases and actions, known before the check. */
  prevention: PreventionAnalysis
  /** When the browser received the answer. */
  checkedAt: Date | null
  onClose: () => void
  /**
   * Omitted where the result is a record rather than a live question, as on a
   * workflow run: rechecking there would replace what the run was judged on.
   */
  onRecheck?: () => void
}

export function AccountCheckDrawer({
  open,
  running,
  check,
  refusal,
  prevention,
  checkedAt,
  onClose,
  onRecheck,
}: AccountCheckDrawerProps) {
  // Mounted before shown so the panel transitions in rather than appearing.
  const [shown, setShown] = useState(false)

  useEffect(() => {
    if (!open) {
      setShown(false)
      return undefined
    }
    const id = requestAnimationFrame(() => setShown(true))
    return () => cancelAnimationFrame(id)
  }, [open])

  useEffect(() => {
    if (!open) return undefined
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  // With nothing that runs as the connected role, the answer comes back
  // without an AWS call, in milliseconds, so an "Asking AWS" view would only
  // flash. The drawer stays on its answer instead, and offers no recheck: the
  // answer depends on the emulation's declarations, not on the account, so
  // checking again cannot change it.
  const nothingToSend = !canRecheck(askedAbout(prevention).identities)
  const asking = running && !nothingToSend

  const name = prevention.displayName
  let title = `${name} against your account`
  let subtitle = 'The check could not run.'
  if (asking) {
    title = `Checking ${name} against your account`
    subtitle = 'Nothing is performed in your account. AWS only reads your policies.'
  } else if (check) {
    subtitle = `Checked ${formatCheckedAt(checkedAt)} · role ${check.identity} · ${check.region}`
  }

  return (
    <div className="fixed inset-0 flex justify-end" style={OVERLAY_STYLE} role="dialog" aria-modal="true">
      <div
        onClick={onClose}
        className={`absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity duration-300
          ${shown ? 'opacity-100' : 'opacity-0'}`}
      />
      <aside
        style={PANEL_STYLE}
        className={`relative flex h-full flex-col border-l border-border bg-surface-card
          transition-transform duration-300 ease-out motion-reduce:transition-none
          ${shown ? 'translate-x-0' : 'translate-x-full'}`}
      >
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="absolute right-5 top-5 z-10 text-content-dim transition-opacity hover:opacity-60"
        >
          <IconClose size={16} />
        </button>

        <div className="border-b border-border px-6 pb-4 pt-5">
          <div className="mb-2 font-mono text-2xs uppercase tracking-label text-content-dim">
            Your account &middot; simulated
          </div>
          <div className="pr-8 text-lg font-semibold leading-snug text-content-primary">{title}</div>
          <div className="mt-1.5 break-all text-xs text-content-dim">{subtitle}</div>
        </div>

        <div className="flex-1 overflow-y-auto px-6 pb-8 pt-5">
          {asking && <Asking prevention={prevention} />}
          {!asking && check && <Answer key={checkedAt?.getTime()} check={check} prevention={prevention} />}
          {!asking && !check && refusal && <Refused refusal={refusal} prevention={prevention} />}
          {running && nothingToSend && !check && (
            <Section label="Who performs these actions">
              <IdentityList identities={askedAbout(prevention).identities} />
            </Section>
          )}
        </div>

        <div className="flex items-center gap-3 border-t border-border px-6 py-3">
          {asking ? (
            <>
              <SecondaryButton onClick={onClose}>Close</SecondaryButton>
              <span className="text-xs text-content-dim">The result will wait on the page.</span>
            </>
          ) : (
            <>
              {onRecheck && !nothingToSend && <SecondaryButton onClick={onRecheck}>Check again</SecondaryButton>}
              {check && (
                <span className="text-xs text-content-dim">
                  {nothingToSend
                    ? 'Nothing here runs as your connected role or a lab identity, so checking again would give the same answer.'
                    : 'Simulated, not observed. Nothing was performed.'}
                </span>
              )}
            </>
          )}
        </div>
      </aside>
    </div>
  )
}

/** The 8px-radius secondary button used in the drawer footer. */
function SecondaryButton({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-btn border border-white/10 px-3 py-1.5 text-xs font-medium tracking-btn
        text-content-primary transition-opacity hover:opacity-60"
    >
      {children}
    </button>
  )
}

/** "2 Oct, 18:52" in the reader's locale. */
export function formatCheckedAt(date: Date | null): string {
  if (!date) return ''
  return date.toLocaleString(undefined, {
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  })
}

/** Why an identity's actions were, or were not, sent to AWS, by its kind. */
export const KIND_TEXT: Record<IdentityKind, string> = {
  connected_role: 'Checked against your AWS policies.',
  anonymous: "Sent without an identity, so no IAM policy applies; only the resource's own policy decides.",
  lab_user: 'Created by the lab. Checked in your deployed lab of this emulation, if you have one.',
  lab_role: 'Created by the lab. Checked in your deployed lab of this emulation, if you have one.',
  attack_created: 'Created during the attack, so it cannot be checked.',
  undeclared: 'The emulation does not say who performs these, so they are not checked.',
}

/** A few words naming an identity's kind, for tagging an action row. */
const KIND_TAG: Record<IdentityKind, string> = {
  connected_role: 'your role',
  anonymous: 'anonymous',
  lab_user: 'lab identity',
  lab_role: 'lab identity',
  attack_created: 'created by attack',
  undeclared: 'not declared',
}

/** Where an identity stands after the check, as a word and a sentence. */
const STATUS_TEXT: Record<IdentityStatus, { word: string; why: string }> = {
  checked: { word: 'Checked', why: 'Checked against your AWS policies.' },
  not_deployed: { word: 'Deploy to check', why: 'Exists once the lab is deployed. Deploy this emulation to check it.' },
  not_exported: {
    word: 'Redeploy to check',
    why: "Your lab was deployed before it published this identity's name. Redeploy it to check this identity.",
  },
  attack_created: { word: 'Not checked', why: 'Created during the attack, so it cannot be checked.' },
  no_identity: { word: 'No identity', why: KIND_TEXT.anonymous },
  undeclared: { word: 'Not checked', why: KIND_TEXT.undeclared },
}

/** The word and sentence for one identity, from its status when the result carries one. */
function identityText(identity: CheckIdentity): { word: string; why: string } {
  const lab = identity.kind === 'lab_user' || identity.kind === 'lab_role'
  if (identity.status === 'checked' && lab) {
    return {
      word: 'Checked in your lab',
      why: "Checked as it exists in your deployed lab, with your organisation's SCPs applied to it.",
    }
  }
  if (identity.status) return STATUS_TEXT[identity.status]
  return { word: identity.checked ? 'Checked' : 'Not checked', why: KIND_TEXT[identity.kind] }
}

/**
 * Whether checking again could change the answer: only when some identity is
 * the connected role or a lab identity. One made only of anonymous requests and
 * identities the attack creates always gives the same answer.
 */
export function canRecheck(identities: Pick<CheckIdentity, 'kind'>[]): boolean {
  return identities.some((identity) => ['connected_role', 'lab_user', 'lab_role'].includes(identity.kind))
}

/** "runs as the lab's stolen user", from an identity's label. */
export function runsAs(identity: Pick<CheckIdentity, 'label' | 'kind'>): string {
  if (identity.kind === 'anonymous') return 'sent with no identity'
  return `runs as ${identity.label.replace(/^(The|A|An) /, (article) => article.toLowerCase())}`
}

/**
 * What the check is about to ask, worked out from the declared identities
 * before the answer arrives: the actions your connected role performs, and
 * every other identity with how many actions it performs.
 */
function askedAbout(prevention: PreventionAnalysis): { toCheck: number; identities: CheckIdentity[] } {
  const declared = new Map((prevention.identities ?? []).map((identity) => [identity.key, identity]))
  const pairs = new Map<string, Set<string>>()
  for (const phase of prevention.phases) {
    for (const [who, actions] of Object.entries(phase.actingAs ?? {})) {
      const set = pairs.get(who) ?? new Set<string>()
      actions.forEach((action) => set.add(action.toLowerCase()))
      pairs.set(who, set)
    }
  }
  const identities = [...pairs.entries()].map(([who, actions]) => ({
    key: who,
    label: declared.get(who)?.label ?? who,
    kind: declared.get(who)?.kind ?? 'undeclared',
    actions: actions.size,
    checked: who === 'connected_role',
  }))
  const toCheck = identities
    .filter((identity) => ['connected_role', 'lab_user', 'lab_role'].includes(identity.kind))
    .reduce((sum, identity) => sum + identity.actions, 0)
  return { toCheck, identities }
}

/** A labelled block of the drawer body. */
function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <section className="mt-7 first:mt-0">
      <div className="mb-2.5 font-mono text-2xs uppercase tracking-label text-content-dim">{label}</div>
      {children}
    </section>
  )
}

/**
 * Who, where and how much: the question itself.
 *
 * The role's name and the region only arrive with the answer, so here they
 * are described rather than named; the answer's header names them. Fetching the profile to name the role
 * earlier would bring its full ARN, account id included, into a page that has
 * no other use for it.
 */
function Facts({ prevention }: { prevention: PreventionAnalysis }) {
  const { toCheck, identities } = askedAbout(prevention)
  const others = identities
    .filter((identity) => !['connected_role', 'lab_user', 'lab_role'].includes(identity.kind))
    .reduce((sum, identity) => sum + identity.actions, 0)
  const facts = [
    ['Acting as', 'Your role and lab identities', 'Lab identities when your lab is deployed'],
    ['Region', "The lab's region", 'Where an emulation deploys'],
    [
      'Actions',
      `${toCheck} to check`,
      others > 0 ? `${others} more cannot be checked` : `Across ${prevention.phases.length} attack phases`,
    ],
  ]
  return (
    <div className="grid grid-cols-1 gap-px overflow-hidden rounded-btn border border-border bg-border sm:grid-cols-3">
      {facts.map(([label, value, hint]) => (
        <div key={label} className="bg-surface-card px-3.5 py-3">
          <div className="font-mono text-2xs uppercase tracking-label text-content-dim">{label}</div>
          <div className="mt-1.5 break-all text-sm text-content-primary">{value}</div>
          <div className="mt-0.5 text-xs leading-snug text-content-dim">{hint}</div>
        </div>
      ))}
    </div>
  )
}

const LAYERS = [
  {
    title: "Your role's own policies",
    detail: 'What the connected role is permitted to do. A refusal here is a setup problem, not protection.',
    tag: 'IAM',
  },
  {
    title: 'Permissions boundary',
    detail: 'The most this role can ever be allowed, set by an administrator.',
    tag: 'Boundary',
  },
  {
    title: 'Organisation policies',
    detail: 'Service control policies your AWS organisation applies to this account.',
    tag: 'SCP',
  },
]

/** The three policy layers AWS evaluates; their dots pulse while it does. */
function Layers({ live }: { live: boolean }) {
  return (
    <div>
      {LAYERS.map((layer) => (
        <div key={layer.tag} className="flex items-start gap-3 border-b border-border px-0.5 py-2.5 first:border-t">
          <span
            aria-hidden="true"
            className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full
              ${live ? 'animate-pulse bg-accent-blue motion-reduce:animate-none' : 'bg-content-muted'}`}
          />
          <div className="min-w-0 flex-1">
            <div className="text-sm text-content-primary">{layer.title}</div>
            <div className="mt-0.5 text-xs leading-relaxed text-content-dim">{layer.detail}</div>
          </div>
          <span className="shrink-0 rounded border border-border px-1.5 py-px font-mono text-2xs uppercase
            tracking-label text-content-dim">
            {layer.tag}
          </span>
        </div>
      ))}
    </div>
  )
}

// Ring and glow share one box-shadow, so both live in the same inline value.
const NODE_LIT = { boxShadow: '0 0 0 1px var(--blue), 0 0 0 4px hsla(202, 100%, 67%, 0.15)' }

/** A numbered node on the vertical phase track. Glows when its phase is open. */
function Node({ phase, lit }: { phase: number; lit: boolean }) {
  return (
    <span
      className={`absolute left-0 top-2 grid h-6 w-6 place-items-center rounded-full bg-surface-elevated
        font-mono text-2xs transition-shadow
        ${lit ? 'text-content-primary' : 'text-content-secondary ring-1 ring-border'}`}
      style={lit ? NODE_LIT : undefined}
    >
      {phase}
    </span>
  )
}

/** The thin vertical line the phase nodes sit on. */
function Track({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative">
      <span aria-hidden="true" className="absolute bottom-4 left-3 top-4 w-px bg-border" />
      {children}
    </div>
  )
}

/** While AWS answers: the question, laid out so the reader can follow it. */
function Asking({ prevention }: { prevention: PreventionAnalysis }) {
  return (
    <>
      <section className="flex items-center gap-3.5">
        <span className="relative h-11 w-10 shrink-0" aria-hidden="true">
          <svg viewBox="0 0 38 44" className="absolute inset-0 h-full w-full" fill="none"
            stroke="currentColor" strokeWidth={1.6}>
            <path className="text-content-muted" d="M19 2l15 6v11c0 10-6.5 18.5-15 23C10.5 37.5 4 29 4 19V8l15-6z" />
          </svg>
          <span className="absolute inset-x-1.5 top-2 h-0.5 rounded-full bg-accent-blue animate-scanBeam
            motion-reduce:animate-none" />
        </span>
        <div>
          <div className="text-base font-semibold text-content-primary">Asking AWS</div>
          <div className="mt-0.5 text-sm leading-relaxed text-content-secondary">
            AWS is evaluating your connected role and, if your lab of this emulation is deployed, the
            identities it creates. This usually takes a few seconds.
          </div>
        </div>
      </section>

      <Section label="What is being asked">
        <Facts prevention={prevention} />
      </Section>

      <Section label="Who performs these actions">
        <IdentityList identities={askedAbout(prevention).identities} />
      </Section>

      <Section label="Actions, by attack phase">
        <Track>
          {prevention.phases.map((phase) => (
            <div key={phase.phase} className="relative pb-2.5 pl-10">
              <Node phase={phase.phase} lit={false} />
              <div className="py-2.5 text-sm text-content-primary">{phase.name}</div>
              <div className="flex flex-wrap gap-1">
                {phase.actions.length === 0 ? (
                  <span className="text-xs text-content-dim">No IAM-authorised call</span>
                ) : (
                  phase.actions.map((action) => (
                    <span key={action} className="rounded bg-surface-elevated px-1.5 py-0.5 font-mono
                      text-2xs text-content-secondary">
                      {action}
                    </span>
                  ))
                )}
              </div>
            </div>
          ))}
        </Track>
      </Section>

      <Section label="AWS checks each action against">
        <Layers live />
      </Section>
    </>
  )
}

const PHASE_WORD: Record<CheckedPhase['verdict'], { text: string; tone: string }> = {
  denied: { text: 'Refused', tone: 'text-safe' },
  undecided: { text: 'Undecided', tone: 'text-warning' },
  role_cannot_perform: { text: "Role can't perform", tone: 'text-warning' },
  allowed: { text: 'Allowed', tone: 'text-content-secondary' },
  no_iam_call: { text: 'No IAM call', tone: 'text-content-dim' },
  not_checked: { text: 'Not checked', tone: 'text-content-dim' },
  no_identity: { text: 'No identity', tone: 'text-content-dim' },
}

export const REFUSED_BY: Record<string, string> = {
  organization_scp: "by your organisation's SCP",
  permissions_boundary: 'by a permissions boundary',
}

/**
 * One action's outcome: the word, and in plain terms who or what decided it.
 *
 * @param identity - Who performs it, shown as a small tag when known.
 */
export function ActionRow({ row, identity }: { row: CheckedAction; identity?: CheckIdentity }) {
  let word = 'Allowed'
  let tone = 'text-content-secondary'
  let why: React.ReactNode = null
  if (row.verdict === 'not_checked' || row.verdict === 'no_identity') {
    word = row.verdict === 'no_identity' ? 'No identity' : 'Not checked'
    tone = 'text-content-dim'
  } else if (row.deniedBy === 'identity_policy') {
    word = 'Not permitted'
    tone = 'text-warning'
    why = row.identity && row.identity !== 'connected_role' ? 'the lab identity lacks it' : 'your role lacks it'
  } else if (row.deniedBy) {
    word = 'Refused'
    tone = 'text-safe'
    why = REFUSED_BY[row.deniedBy]
  } else if (row.verdict === 'undecided') {
    word = 'Undecided'
    tone = 'text-warning'
    why = (
      <>
        needs <span className="font-mono">{row.missingContext[0]}</span>
      </>
    )
  }
  return (
    <div className="flex items-baseline gap-2.5 border-t border-border py-2 text-xs">
      <span className="min-w-0 flex-1 break-all font-mono text-content-secondary">
        {row.action}
        {identity && (
          <span className="ml-1.5 rounded border border-border px-1 font-mono text-2xs text-content-dim">
            {KIND_TAG[identity.kind]}
          </span>
        )}
        {/* Judged against all resources rather than the one the attack targets:
            either no lab is deployed to name it yet (fallback), or the result
            predates resource declarations (unspecified). A rule written for a
            specific resource would not have been matched. */}
        {(row.resourceScope === 'fallback' || row.resourceScope === 'unspecified') &&
          row.verdict !== 'no_identity' && row.verdict !== 'not_checked' && (
          <span
            title={
              row.resourceScope === 'fallback'
                ? 'No lab is deployed yet, so AWS judged this against all resources. Deploy the lab to check the exact resource.'
                : 'No resource is declared for this action, so AWS judged it against all resources'
            }
            className="ml-1.5 rounded border border-dashed border-border px-1 font-mono text-2xs text-content-dim"
          >
            {row.resourceScope === 'fallback' ? 'deploy to check' : 'all resources'}
          </span>
        )}
      </span>
      {why && <span className="text-right text-content-dim">{why}</span>}
      <span className={`w-24 shrink-0 text-right ${tone}`}>{word}</span>
    </div>
  )
}

/** One sentence under a phase saying what its outcome means for the reader. */
function phaseExplanation(
  phase: CheckedPhase,
  rows: CheckedAction[],
  identities: Map<string, CheckIdentity>,
): React.ReactNode {
  const undecided = rows.find((row) => row.verdict === 'undecided')
  const parts: React.ReactNode[] = []
  if (phase.verdict === 'not_checked') {
    const who = (phase.notCheckedIdentities ?? []).map((key) => identities.get(key)).filter(Boolean) as CheckIdentity[]
    const reasons = new Set(who.map((identity) => identity.status))
    let because = 'A verdict about your connected role would describe the wrong identity, so none is given.'
    if (reasons.size === 1 && reasons.has('not_deployed')) because = 'Deploy this emulation to check it.'
    if (reasons.size === 1 && reasons.has('not_exported')) because = 'Redeploy your lab to check it.'
    parts.push(
      `Not checked: ${who.length === 1 && who[0] ? runsAs(who[0]) : 'some actions run as other identities'}. ${because} `,
    )
  }
  if (phase.verdict === 'denied') {
    parts.push('One refused call is enough to stop this phase. ')
  }
  if (undecided) {
    parts.push(
      <span key="undecided">
        A policy&apos;s condition depends on{' '}
        <span className="font-mono text-content-secondary">{undecided.missingContext[0]}</span>, which
        only exists in the real request, so AWS could not say yes or no.{' '}
      </span>,
    )
  }
  if (phase.roleCannotPerform.length > 0) {
    parts.push(
      <span key="role">
        Your role is missing{' '}
        <span className="font-mono text-content-secondary">{phase.roleCannotPerform.join(', ')}</span>.
        That stops the emulation before any guardrail can, so it is a setup problem and is not counted
        as protection.
      </span>,
    )
  }
  return parts.length > 0 ? <p className="mt-2 text-xs leading-relaxed text-content-dim">{parts}</p> : null
}

/** "4", "4 and 5", "2, 4 and 5". */
function joinPhases(numbers: number[]): string {
  if (numbers.length <= 1) return numbers.join('')
  return `${numbers.slice(0, -1).join(', ')} and ${numbers[numbers.length - 1]}`
}

/**
 * The answer in one sentence: how many actions your guardrails refuse, and
 * which phases that stops. Shared with the workflow pipeline's check stage.
 */
export function CheckHeadline({ check, className = '' }: { check: AccountCheck; className?: string }) {
  const { prevented, undecided, roleCannotPerform, actionsChecked } = check.summary
  const notChecked = check.summary.notChecked?.length ?? 0
  const noIdentity = check.summary.noIdentity?.length ?? 0
  const stopped = check.phases.filter((phase) => phase.verdict === 'denied').map((phase) => phase.phase)
  const anonymous = noIdentity > 0
    ? ` ${noIdentity} ${noIdentity === 1 ? 'is' : 'are'} sent with no identity, which no IAM rule can judge.`
    : ''
  if (actionsChecked === 0) {
    return (
      <p className={`text-sm leading-relaxed text-content-secondary ${className}`}>
        <b className="font-semibold text-content-primary">Nothing could be checked yet.</b>{' '}
        {notChecked > 0 && `${notChecked} actions run as identities that cannot be checked right now; see who performs them below.`}
        {anonymous}
      </p>
    )
  }
  if (notChecked > 0 && prevented.length === 0) {
    return (
      <p className={`text-sm leading-relaxed text-content-secondary ${className}`}>
        <b className="font-semibold text-content-primary">
          {actionsChecked} of {actionsChecked + notChecked} actions
        </b>{' '}
        were checked and none would be refused by your guardrails. The other {notChecked} could not be checked
        yet.{anonymous}
      </p>
    )
  }
  return (
    <p className={`text-sm leading-relaxed text-content-secondary ${className}`}>
      {prevented.length === 0 ? (
        <>
          <b className="font-semibold text-content-primary">None of the {actionsChecked} actions</b>{' '}
          would be refused by your guardrails.
          {undecided.length === 0 && roleCannotPerform.length === 0
            && ` Every phase could run in ${check.region}.`}
          {anonymous}
        </>
      ) : (
        <>
          <b className="font-semibold text-content-primary">
            {prevented.length} of {actionsChecked} actions
          </b>{' '}
          would be refused by your guardrails, which stops {stopped.length === 1 ? 'phase' : 'phases'}{' '}
          {joinPhases(stopped)}.
          {notChecked > 0 && ` ${notChecked} more could not be checked yet.`}
          {anonymous}
        </>
      )}
    </p>
  )
}

/**
 * Which lab the lab identities were checked in, or how to get one.
 *
 * The stack id only builds the link and is never shown. A workflow's result
 * carries no lab: it always checks in the run's own lab, said by its stage.
 */
function LabLine({ check }: { check: AccountCheck }) {
  const linkClass = 'text-accent-blue no-underline transition-opacity hover:opacity-60'
  if (check.lab) {
    return (
      <p className="mt-3.5 text-xs leading-relaxed text-content-dim">
        Lab identities were checked in your deployed lab, deployed {formatCheckedAt(new Date(check.lab.deployedAt))}.{' '}
        <Link to={`/stacks?stack=${check.lab.stackId}`} className={linkClass}>View stack &rsaquo;</Link>
      </p>
    )
  }
  if ((check.identities ?? []).some((identity) => identity.status === 'not_deployed')) {
    return (
      <p className="mt-3.5 text-xs leading-relaxed text-content-dim">
        No deployed lab for this emulation, so its lab identities could not be checked.{' '}
        <Link to="?tab=live" className={linkClass}>Deploy this emulation &rsaquo;</Link>
      </p>
    )
  }
  return null
}

/** Who performs the attack's actions, and whether each identity could be checked. */
function IdentityList({ identities }: { identities: CheckIdentity[] }) {
  return (
    <div>
      {identities.map((identity) => (
        <div key={identity.key} className="flex items-start gap-3 border-b border-border px-0.5 py-2.5 first:border-t">
          <span
            aria-hidden="true"
            className={`mt-1 h-3 w-3 shrink-0 rounded-full border
              ${identity.checked ? 'border-content-secondary' : 'border-dashed border-content-dim'}`}
          />
          <div className="min-w-0 flex-1">
            <div className="text-sm text-content-primary">
              {identity.label}
              <span className="ml-1.5 rounded border border-border px-1 font-mono text-2xs text-content-dim">
                {identity.actions} {identity.actions === 1 ? 'action' : 'actions'}
              </span>
            </div>
            <div className="mt-0.5 text-xs leading-relaxed text-content-dim">{identityText(identity).why}</div>
          </div>
          <span className={`shrink-0 text-xs ${identity.checked ? 'text-content-secondary' : 'text-content-dim'}`}>
            {identityText(identity).word}
          </span>
        </div>
      ))}
    </div>
  )
}

/** The answer: counts first, then each phase, then what the check could not see. */
function Answer({ check, prevention }: { check: AccountCheck; prevention: PreventionAnalysis }) {
  // Phases with something to say start open; allowed ones wait for a click.
  const [opened, setOpened] = useState<Set<number>>(
    () => new Set(
      check.phases
        .filter((phase) => !['allowed', 'no_iam_call', 'not_checked'].includes(phase.verdict))
        .map((phase) => phase.phase),
    ),
  )

  // Each phase lists the (identity, action) pairs it was judged on, joined to
  // the per-action results; one action can be made by two identities, so the
  // identity is part of the key. Results stored before identities were
  // declared have no pairs, and fall back to the declared actions by name.
  // IAM action names are case-insensitive.
  const key = (identity: string | undefined, action: string) => `${identity ?? ''}|${action.toLowerCase()}`
  const byPair = new Map(check.actions.map((row) => [key(row.identity, row.action), row]))
  const byAction = new Map(check.actions.map((row) => [row.action.toLowerCase(), row]))
  const declared = new Map(prevention.phases.map((phase) => [phase.phase, phase.actions]))
  const identities = new Map((check.identities ?? []).map((identity) => [identity.key, identity]))
  const rowsOf = (phase: CheckedPhase): CheckedAction[] =>
    (phase.rows
      ? phase.rows.map((pair) => byPair.get(key(pair.identity, pair.action)))
      : (declared.get(phase.phase) ?? []).map((action) => byAction.get(action.toLowerCase()))
    ).filter((row): row is CheckedAction => Boolean(row))

  const { prevented, undecided, roleCannotPerform, allowed } = check.summary
  const notChecked = check.summary.notChecked?.length ?? 0

  function toggle(phase: number) {
    setOpened((current) => {
      const next = new Set(current)
      if (next.has(phase)) next.delete(phase)
      else next.add(phase)
      return next
    })
  }

  const counts = [
    { value: prevented.length, label: 'Refused by your guardrails', tone: 'text-safe' },
    { value: undecided.length, label: 'Could not be decided', tone: 'text-warning' },
    { value: roleCannotPerform.length, label: "Your role can't perform", tone: 'text-warning' },
    { value: allowed.length, label: 'Allowed', tone: 'text-content-primary' },
    { value: notChecked, label: 'Not checked', tone: 'text-content-secondary' },
  ]

  return (
    <>
      <section>
        <CheckHeadline check={check} className="mb-3.5" />
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-5">
          {counts.map((count) => (
            <div key={count.label} className="rounded-btn border border-border px-3 py-2.5 shadow-ring">
              <div className={`text-xl font-semibold ${count.value > 0 ? count.tone : 'text-content-muted'}`}>
                {count.value}
              </div>
              <div className="mt-0.5 text-xs leading-snug text-content-secondary">{count.label}</div>
            </div>
          ))}
        </div>
      </section>

      <LabLine check={check} />

      {identities.size > 0 && (
        <Section label="Who performs these actions">
          <IdentityList identities={[...identities.values()]} />
        </Section>
      )}

      <Section label="By attack phase">
        <Track>
          {check.phases.map((phase) => {
            const open = opened.has(phase.phase)
            const word = PHASE_WORD[phase.verdict]
            const rows = rowsOf(phase)
            return (
              <div key={phase.phase} className="relative pl-10">
                <Node phase={phase.phase} lit={open} />
                <button
                  type="button"
                  onClick={() => toggle(phase.phase)}
                  aria-expanded={open}
                  className="flex w-full items-center gap-2.5 py-2.5 text-left transition-opacity hover:opacity-60"
                >
                  <span className="flex-1 text-sm text-content-primary">{phase.name}</span>
                  <span className={`text-xs ${word.tone}`}>{word.text}</span>
                  <IconChevron
                    size={14}
                    className={`text-content-dim transition-transform ${open ? 'rotate-90' : ''}`}
                  />
                </button>
                {open && (
                  <div className="pb-3">
                    {rows.length === 0 ? (
                      <p className="text-xs text-content-dim">
                        This phase makes no call that an IAM policy can refuse.
                      </p>
                    ) : (
                      rows.map((row) => (
                        <ActionRow
                          key={`${row.identity ?? ''}-${row.action}`}
                          row={row}
                          identity={row.identity ? identities.get(row.identity) : undefined}
                        />
                      ))
                    )}
                    {phaseExplanation(phase, rows, identities)}
                  </div>
                )}
              </div>
            )
          })}
        </Track>
      </Section>

      <Section label="What this could and could not see">
        <SeenAndUnseen />
        <p className="mt-2.5 text-xs leading-relaxed text-content-dim">
          So &quot;allowed&quot; means none of the three layers on the left refuses it, not that the
          attack is unstoppable. Only a refusal seen during a real run proves prevention.
        </p>
      </Section>
    </>
  )
}

const SEEN = ["Your role's own policies", 'Its permissions boundary', "Your organisation's SCPs"]
const UNSEEN = [
  'Resource control policies (RCPs)',
  "A resource's own policy, such as a bucket policy",
  'Identities other than your connected role, listed above',
  'Rules written for one specific resource, for actions tagged "all resources"',
  'Values that only exist once the lab is deployed',
]

/** The layers the simulator evaluated beside the ones it cannot see. */
function SeenAndUnseen() {
  return (
    <div className="grid grid-cols-1 gap-x-5 sm:grid-cols-2">
      <ul className="divide-y divide-border">
        {SEEN.map((item) => (
          <li key={item} className="flex gap-2 py-1.5 text-xs leading-relaxed text-content-secondary">
            <IconCheck size={12} className="mt-0.5 shrink-0 text-safe" />
            {item}
          </li>
        ))}
      </ul>
      <ul className="divide-y divide-border">
        {UNSEEN.map((item) => (
          <li key={item} className="flex gap-2 py-1.5 text-xs leading-relaxed text-content-dim">
            <IconClose size={12} className="mt-0.5 shrink-0" />
            {item}
          </li>
        ))}
      </ul>
    </div>
  )
}

/**
 * Why the check could not run. The question stays visible, so the reader still
 * learns what the check does and why the missing permission is worth adding.
 */
function Refused({ refusal, prevention }: { refusal: AccountCheckError; prevention: PreventionAnalysis }) {
  if (!refusal.missingPermission) {
    return (
      <p className="text-sm leading-relaxed text-warning">AWS refused the check: {refusal.detail}</p>
    )
  }
  return (
    <>
      <section>
        <p className="text-sm leading-relaxed text-content-secondary">
          <b className="font-semibold text-content-primary">Your connected role cannot run this check yet.</b>{' '}
          Add <span className="font-mono text-content-primary">{refusal.missingPermission}</span> to it. It is
          read-only and changes nothing in your account.
        </p>
        <p className="mt-2 text-xs text-content-dim">
          <Link to="/me" className="text-accent-blue no-underline transition-opacity hover:opacity-60">
            Open the connect page
          </Link>{' '}
          Its policy already includes this permission.
        </p>
      </section>
      <Section label="What would have been asked">
        <Facts prevention={prevention} />
      </Section>
      <Section label="AWS would check each action against">
        <Layers live={false} />
      </Section>
    </>
  )
}
