import { useEffect, useState, type ReactNode } from 'react'
import type { AttackPhase } from '@/types/platform'
import type { AccountCheck, CheckedAction, CheckedPhase, PreventionAnalysis, PreventionPolicy } from '@/types/prevention'
import type { AlertEvidence, MatchTier, RuleOutcome, WorkflowRunDetail } from '@/types/workflow'
import { Card } from '@/components/ui/Card'
import { ActionRow, REFUSED_BY, runsAs } from '@/components/emulations/AccountCheckDrawer'
import { GuardrailDrawer } from '@/components/emulations/GuardrailDrawer'
import {
  Shield,
  perimeterPolicies,
  policiesFor,
  shieldFor,
  type ShieldState,
} from '@/components/emulations/preventionMeta'
import { SCORE_STATUS_NOTE, VERDICT_CLASS, VERDICT_LABEL, formatCoverage } from './workflowMeta'
import { canonicalTechnique, preventionCounts, rulesForPhase, unplacedRules } from './phaseMeta'

/**
 * The attack phases of one run, each read against two lanes.
 *
 * Prevention leads with what the client's own policies did, as AWS simulated
 * them just before the deploy, with the published library's advice under each
 * phase as the fix to consider. When the run has no account check (skipped,
 * or older than the check) the lane falls back to the library alone and is
 * labelled advice. Neither is observed, so neither feeds the detection score.
 * Detection is what the client's SIEM actually reported during the run.
 * Keeping them in separate lanes lets a reader see, per phase, whether a gap
 * is best closed with a policy or with a rule.
 *
 * Whether each phase actually executed is not recorded yet, so a phase shows
 * only what the controls did around it, never a "ran" or "succeeded" state.
 */

interface AttackPhasesProps {
  run: WorkflowRunDetail
  phases: AttackPhase[]
  /** Null when the analysis could not be loaded; the Prevention lane is then left out. */
  prevention: PreventionAnalysis | null
}

const LABEL_COLUMN_PX = 170
const PHASE_COLUMN_MIN_PX = 128

/** Width of the lane-label column, then one equal column per phase. */
function columns(count: number): string {
  return `${LABEL_COLUMN_PX}px repeat(${count}, minmax(${PHASE_COLUMN_MIN_PX}px, 1fr))`
}

/**
 * @param run - The finished (or collecting) workflow.
 * @param phases - The emulation's attack phases, in order.
 * @param prevention - The catalogue analysis, or null when unavailable.
 */
export function AttackPhases({ run, phases, prevention }: AttackPhasesProps) {
  const [selected, setSelected] = useState<number | null>(null)
  const [openPolicy, setOpenPolicy] = useState<PreventionPolicy | null>(null)
  const [openPerimeter, setOpenPerimeter] = useState(false)

  const score = run.score
  const rules = score?.rules ?? []
  const analysed = Boolean(prevention?.analysed)
  const account = run.accountCheck?.status === 'checked' ? run.accountCheck.result : null
  const perimeter = perimeterPolicies(prevention)
  const unplaced = score ? unplacedRules(phases, rules) : []
  const statusNote = score ? SCORE_STATUS_NOTE[score.status] : ''

  // Escape clears the selection, but only when no policy drawer is open: the
  // drawer handles its own Escape, and one key press should close one thing.
  useEffect(() => {
    if (selected === null || openPolicy || openPerimeter) return undefined
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setSelected(null)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [selected, openPolicy, openPerimeter])

  const perimeterButton = perimeter.length > 0 && (
    <button
      type="button"
      onClick={() => setOpenPerimeter(true)}
      className="block mt-1.5 text-accent-blue transition-opacity hover:opacity-60"
    >
      +{perimeter.length} perimeter policies
    </button>
  )

  /* Spotlight: once a phase is chosen, the others fade back. */
  const dim = (phase: number) => (selected !== null && phase !== selected ? 'opacity-40' : '')
  const toggle = (phase: number) => setSelected((current) => (current === phase ? null : phase))
  const chosen = phases.find((phase) => phase.phase === selected) ?? null

  return (
    <Card className="pt-5 pb-2">
      <div className="flex flex-wrap items-baseline justify-between gap-3 px-5 pb-3">
        <h2 className="text-base font-medium text-content-primary tracking-body">Attack phases</h2>
        <span className="text-xs text-content-dim">In order, left to right. Select a phase for its details.</span>
      </div>

      {statusNote && (
        <p className="px-5 pb-3 text-xs text-warning leading-relaxed tracking-body">{statusNote}</p>
      )}

      <div className="overflow-x-auto px-5 pb-4">
        {/* Past this width the phases scroll sideways instead of squeezing. */}
        <div style={{ minWidth: LABEL_COLUMN_PX + PHASE_COLUMN_MIN_PX * phases.length }}>
          <div className="grid" style={{ gridTemplateColumns: columns(phases.length) }}>
            <div />
            {phases.map((phase, index) => (
              <StepHeader
                key={phase.phase}
                phase={phase}
                first={index === 0}
                last={index === phases.length - 1}
                selected={phase.phase === selected}
                className={dim(phase.phase)}
                onClick={() => toggle(phase.phase)}
              />
            ))}

            {(prevention || account) && (
              <>
                <LaneLabel name="Prevention" tag={account ? 'simulated' : 'advice'}>
                  {account ? (
                    <>
                      <AccountSummary account={account} />
                      {analysed && ' Library advice under each.'}
                      {perimeterButton}
                    </>
                  ) : analysed && prevention ? (
                    <>
                      {run.accountCheck?.status === 'skipped' && 'Your account was not checked for this run. '}
                      <PreventionSummary phases={phases} prevention={prevention} />
                      {perimeterButton}
                    </>
                  ) : (
                    'Not mapped for this emulation yet.'
                  )}
                </LaneLabel>
                {phases.map((phase) => (
                  <LaneCell key={phase.phase} className={dim(phase.phase)} onClick={() => toggle(phase.phase)}>
                    {account && <AccountCell account={account} phase={phase.phase} />}
                    {analysed && (
                      <PreventionCell phase={phase.phase} prevention={prevention} underAccount={Boolean(account)} />
                    )}
                  </LaneCell>
                ))}
              </>
            )}

            <LaneLabel name="Detection">
              <DetectionSummary run={run} />
            </LaneLabel>
            {phases.map((phase) => (
              <LaneCell key={phase.phase} className={dim(phase.phase)} onClick={() => toggle(phase.phase)}>
                <DetectionCell rules={score ? rulesForPhase(phase, rules) : null} />
              </LaneCell>
            ))}
          </div>

          {chosen && (
            <>
              {/* An empty row whose chosen cell holds the pointer, so the panel
                  below visibly belongs to that phase's column. */}
              <div className="grid" style={{ gridTemplateColumns: columns(phases.length) }}>
                <div />
                {phases.map((phase) => (
                  <div key={phase.phase} className="relative h-3">
                    {phase.phase === chosen.phase && (
                      <span
                        aria-hidden="true"
                        className="absolute left-4 -bottom-1.5 z-10 w-3 h-3 rotate-45
                          bg-surface-base border-l border-t border-border"
                      />
                    )}
                  </div>
                ))}
              </div>
              <PhasePanel
                phase={chosen}
                run={run}
                account={account}
                prevention={analysed ? prevention : null}
                onClose={() => setSelected(null)}
                onPolicy={setOpenPolicy}
              />
            </>
          )}
        </div>
      </div>

      {unplaced.length > 0 && (
        <div className="px-5 pb-4">
          <h3 className="font-mono text-2xs uppercase tracking-label text-content-dim">Other detections</h3>
          <p className="text-xs text-content-dim leading-relaxed mt-1 mb-2">
            These rules name a technique outside this emulation&apos;s phases. They still count in the score.
          </p>
          {unplaced.map((rule) => (
            <DetectionRow key={`${rule.ruleId}-${rule.title}`} rule={rule} />
          ))}
        </div>
      )}

      <GuardrailDrawer
        policy={openPolicy}
        perimeter={perimeter}
        showPerimeter={openPerimeter}
        platformId={run.platform}
        onClose={() => {
          setOpenPolicy(null)
          setOpenPerimeter(false)
        }}
      />
    </Card>
  )
}

interface StepHeaderProps {
  phase: AttackPhase
  first: boolean
  last: boolean
  selected: boolean
  className: string
  onClick: () => void
}

/**
 * One node of the numbered step track.
 *
 * The connecting line runs through the node centres, so it starts at the first
 * node and stops at the last instead of running off either edge.
 *
 * The grid stretches every header to the tallest in the row, and a button
 * centres its content vertically by default. A phase whose name wraps to
 * fewer lines then had its node pushed down, breaking the line, so the
 * content is pinned to the top as a flex column.
 */
function StepHeader({ phase, first, last, selected, className, onClick }: StepHeaderProps) {
  return (
    <button
      type="button"
      aria-pressed={selected}
      onClick={onClick}
      className={`flex flex-col text-left px-3 pt-0.5 pb-3 transition-opacity hover:opacity-60 ${className}`}
    >
      <span className="flex items-center">
        {!first && <span aria-hidden="true" className="-ml-3 w-3 h-px bg-border" />}
        <span
          className={`grid place-items-center shrink-0 w-5 h-5 rounded-full bg-surface-card border
            font-mono text-2xs transition-shadow
            ${selected ? 'border-accent-blue text-accent-blue ring-4 ring-accent-blue-glow' : 'border-border text-content-secondary'}`}
        >
          {phase.phase}
        </span>
        {!last && <span aria-hidden="true" className="flex-1 -mr-3 h-px bg-border" />}
      </span>
      <span className={`block text-xs leading-snug tracking-body mt-2.5
        ${selected ? 'text-content-primary' : 'text-content-secondary'}`}>
        {phase.name}
      </span>
      <span className="block font-mono text-2xs text-content-dim mt-1">
        {phase.techniques.map((technique) => technique.id).join(' · ')}
      </span>
    </button>
  )
}

/** The left-hand label of a lane, with its summary underneath. */
function LaneLabel({ name, tag, children }: { name: string; tag?: string; children: ReactNode }) {
  return (
    <div className="border-t border-border py-3 pr-3.5">
      <div className="text-sm text-content-primary tracking-body">
        {name}
        {tag && (
          <span className="ml-1.5 font-mono text-2xs uppercase tracking-label text-content-dim border
            border-border rounded px-1.5 py-px">
            {tag}
          </span>
        )}
      </div>
      <div className="text-xs text-content-secondary leading-relaxed mt-1">{children}</div>
    </div>
  )
}

/**
 * One cell of a lane; clicking anywhere in the column selects its phase.
 *
 * Pinned to the top like StepHeader, so a row's verdicts line up however their
 * text wraps. The single wrapper keeps chips at their natural width.
 */
function LaneCell({ className, onClick, children }: { className: string; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex flex-col border-t border-border px-3 py-3 text-left transition-opacity hover:opacity-60
        ${className}`}
    >
      <span className="block w-full">{children}</span>
    </button>
  )
}

/** "2 of 5 phases ... outright", phrased as advice and never as a percentage. */
function PreventionSummary({ phases, prevention }: { phases: AttackPhase[]; prevention: PreventionAnalysis }) {
  const { outright, conditional, total } = preventionCounts(phases, prevention)
  return (
    <>
      {outright} of {total} phases have a library policy that would block them outright
      {conditional > 0 && `, and ${conditional} more if a condition in your org holds`}
    </>
  )
}

const PREVENTION_TEXT: Record<Exclude<ShieldState, 'blocks' | 'conditional'>, string> = {
  none: 'No IAM call to deny',
  open: 'No library policy',
}

/**
 * A phase's shield and a few words on what the catalogue would do to it.
 *
 * @param underAccount - True when it sits under the account verdict, where it
 *   is the secondary line: smaller, dimmer and named as the library's.
 */
function PreventionCell({
  phase,
  prevention,
  underAccount = false,
}: {
  phase: number
  prevention: PreventionAnalysis | null
  underAccount?: boolean
}) {
  const state = shieldFor(phase, prevention)
  if (!state || !prevention) return null
  let text: string
  if (state === 'blocks') {
    const count = prevention.phases.find((row) => row.phase === phase)?.blockedBy.length ?? 0
    text = `Blocked by ${count} ${count === 1 ? 'policy' : 'policies'}`
  } else if (state === 'conditional') {
    const count = policiesFor(phase, prevention).filter((p) => p.verdict === 'blocks_conditional').length
    text = `${count} conditional ${count === 1 ? 'policy' : 'policies'}`
  } else {
    text = PREVENTION_TEXT[state]
  }
  if (underAccount) {
    return (
      <span className="flex items-start gap-1.5 mt-2 pt-2 border-t border-dashed border-border text-xs
        text-content-dim leading-snug tracking-body">
        <Shield state={state} size={13} />
        Library: {text.toLowerCase()}
      </span>
    )
  }
  return (
    <span className="flex items-start gap-2 text-xs text-content-secondary leading-snug tracking-body">
      <Shield state={state} size={16} />
      {text}
    </span>
  )
}

/** "2 of 5 phases refused by your policies", counted from the account check. */
function AccountSummary({ account }: { account: AccountCheck }) {
  const refused = account.phases.filter((phase) => phase.verdict === 'denied').length
  const unchecked = account.phases.filter((phase) => phase.verdict === 'not_checked').length
  if (account.summary.actionsChecked === 0) return <>No phase could be checked yet.</>
  const lead = refused === 0
    ? 'No phase is refused by your policies'
    : `${refused} of ${account.phases.length} phases refused by your policies`
  return <>{lead}{unchecked > 0 ? `; ${unchecked} not checked.` : '.'}</>
}

const ACCOUNT_WORD: Record<CheckedPhase['verdict'], { text: string; tone: string; by: string }> = {
  denied: { text: 'Refused', tone: 'text-safe', by: '' },
  undecided: { text: 'Undecided', tone: 'text-warning', by: 'needs a value from the real request' },
  role_cannot_perform: { text: "Role can't perform", tone: 'text-warning', by: 'a setup gap, not protection' },
  allowed: { text: 'Allowed', tone: 'text-content-secondary', by: 'nothing in your policies refuses it' },
  no_iam_call: { text: 'No IAM call', tone: 'text-content-dim', by: 'nothing for a policy to refuse' },
  not_checked: { text: 'Not checked', tone: 'text-content-dim', by: 'runs as other identities' },
  no_identity: { text: 'No identity', tone: 'text-content-dim', by: 'sent with no identity' },
}

/**
 * What the client's own policies did to one phase, in a word and who decided.
 *
 * A refusal names the layer that refused: the phase only lists its refused
 * actions, so the layer is read from the first of them.
 */
function AccountCell({ account, phase }: { account: AccountCheck; phase: number }) {
  const row = account.phases.find((item) => item.phase === phase)
  if (!row) return null
  const word = ACCOUNT_WORD[row.verdict]
  let by = word.by
  if (row.verdict === 'denied') {
    const first = account.actions.find((action) => action.action === row.preventedActions[0])
    by = (first?.deniedBy && REFUSED_BY[first.deniedBy]) || 'by your guardrails'
  } else if (row.verdict === 'not_checked') {
    // One identity is named; a mix is summarised by how much was checked.
    // Anonymous rows are neither checked nor unchecked, so they are left out of "n of m checked".
    const anonymous = new Set(
      (account.identities ?? []).filter((identity) => identity.status === 'no_identity').map((identity) => identity.key),
    )
    const judged = (row.rows ?? []).filter((pair) => !anonymous.has(pair.identity)).length
    const unchecked = row.notCheckedActions?.length ?? 0
    const who = (row.notCheckedIdentities ?? [])
      .map((key) => account.identities?.find((identity) => identity.key === key))
      .filter((identity) => identity !== undefined)
    const reasons = new Set(who.map((identity) => identity?.status))
    if (judged > unchecked) by = `${judged - unchecked} of ${judged} checked; the rest run as other identities`
    else if (reasons.size === 1 && reasons.has('not_deployed')) by = 'deploy the lab to check'
    else if (reasons.size === 1 && reasons.has('not_exported')) by = 'redeploy the lab to check'
    else if (reasons.size === 1 && reasons.has('attack_created')) by = 'runs as identities the attack creates'
    else if (who.length === 1 && who[0]) by = runsAs(who[0])
  }
  return (
    <span className="block text-xs leading-snug tracking-body">
      <span className={`block ${word.tone}`}>{word.text}</span>
      <span className="block text-content-dim mt-1">{by}</span>
    </span>
  )
}

/** The coverage figure and counts; the figure is a dash, never 0%, when nothing was exercised. */
function DetectionSummary({ run }: { run: WorkflowRunDetail }) {
  const score = run.score
  if (!score) return <>Waiting for your SIEM to report.</>
  const { fired = 0, silent = 0, not_integrated: notIntegrated = 0 } = score.counts
  return (
    <>
      <span className="block font-display text-lg font-semibold text-content-primary">
        {formatCoverage(score.detectionCoverage)}
      </span>
      coverage · {fired} caught · {silent} missed
      {notIntegrated > 0 && ` · ${notIntegrated} not exercised`}
    </>
  )
}

/** The verdict chips for one phase, or why there are none. */
function DetectionCell({ rules }: { rules: RuleOutcome[] | null }) {
  if (!rules) return <span className="text-xs text-content-dim">Waiting</span>
  if (rules.length === 0) return <Chip className={VERDICT_CLASS.not_integrated}>No detection</Chip>
  return (
    <span className="flex flex-wrap gap-1">
      {rules.map((rule) => (
        <Chip key={`${rule.ruleId}-${rule.title}`} className={VERDICT_CLASS[rule.verdict]}>
          {VERDICT_LABEL[rule.verdict]}
        </Chip>
      ))}
    </span>
  )
}

/** A small uppercase status chip. */
function Chip({ className, children }: { className: string; children: ReactNode }) {
  return (
    <span className={`inline-block shrink-0 font-mono text-2xs uppercase tracking-caps rounded-btn border
      px-1.5 py-0.5 whitespace-nowrap ${className}`}>
      {children}
    </span>
  )
}

interface PhasePanelProps {
  phase: AttackPhase
  run: WorkflowRunDetail
  account: AccountCheck | null
  prevention: PreventionAnalysis | null
  onClose: () => void
  onPolicy: (policy: PreventionPolicy) => void
}

/** Everything about one phase: its actions and policies beside its detections. */
function PhasePanel({ phase, run, account, prevention, onClose, onPolicy }: PhasePanelProps) {
  const rules = run.score ? rulesForPhase(phase, run.score.rules) : null
  return (
    <div className="relative bg-surface-base border border-border rounded-xl px-5 pt-4 pb-5">
      <div className="flex items-center justify-between gap-3 mb-3.5">
        <h3 className="text-sm font-medium text-content-primary tracking-body">
          <span className="font-mono text-2xs uppercase tracking-label text-content-dim mr-2">Phase {phase.phase}</span>
          {phase.name}
        </h3>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close phase details"
          className="text-content-dim text-lg leading-none transition-opacity hover:opacity-60"
        >
          &times;
        </button>
      </div>

      <div className={`grid gap-7 ${prevention || account ? 'sm:grid-cols-2' : ''}`}>
        {(prevention || account) && (
          <div>
            {account && (
              <div className="mb-5">
                <div className="font-mono text-2xs uppercase tracking-label text-content-dim">
                  Your account <span className="text-content-muted">(simulated)</span>
                </div>
                <PhaseAccount account={account} phase={phase.phase} prevention={prevention} />
              </div>
            )}
            {prevention && (
              <>
                <div className="font-mono text-2xs uppercase tracking-label text-content-dim">
                  {account ? 'Library' : 'Prevention'} <span className="text-content-muted">(advice)</span>
                </div>
                <PhasePrevention phase={phase.phase} prevention={prevention} onPolicy={onPolicy} />
              </>
            )}
          </div>
        )}
        <div>
          <div className="font-mono text-2xs uppercase tracking-label text-content-dim">Detection</div>
          <div className="mt-2">
            {!rules ? (
              <p className="text-xs text-content-dim">Waiting for your SIEM to report.</p>
            ) : rules.length === 0 ? (
              <p className="text-xs text-content-dim">This emulation ships no detection for this phase.</p>
            ) : (
              rules.map((rule) => <DetectionRow key={`${rule.ruleId}-${rule.title}`} rule={rule} />)
            )}
          </div>
          {account && (
            <p className="text-xs text-content-dim leading-relaxed mt-3">
              Scored on its own. A refusal in your account is simulated, so it never excuses a missed
              detection; only a refusal observed during the attack could.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

/**
 * Each of the phase's actions with what the client's policies did to it.
 *
 * The phase verdict lists only the actions that went wrong, so the full list
 * comes from the declared actions, joined to the results by name (IAM action
 * names are case-insensitive). Without the declaration, the results alone are
 * shown, which still covers every action that was refused or undecided.
 */
function PhaseAccount({
  account,
  phase,
  prevention,
}: {
  account: AccountCheck
  phase: number
  prevention: PreventionAnalysis | null
}) {
  const key = (identity: string | undefined, action: string) => `${identity ?? ''}|${action.toLowerCase()}`
  const byPair = new Map(account.actions.map((row) => [key(row.identity, row.action), row]))
  const byAction = new Map(account.actions.map((row) => [row.action.toLowerCase(), row]))
  const identities = new Map((account.identities ?? []).map((identity) => [identity.key, identity]))
  const declared = prevention?.phases.find((row) => row.phase === phase)?.actions
  const verdict = account.phases.find((row) => row.phase === phase)
  // Pairs when the result names them; otherwise, for a result stored before
  // identities were declared, the declared actions or the problem lists.
  const rows = verdict?.rows
    ? verdict.rows
      .map((pair) => byPair.get(key(pair.identity, pair.action)))
      .filter((row): row is CheckedAction => Boolean(row))
    : (declared ?? [
      ...(verdict?.preventedActions ?? []),
      ...(verdict?.undecidedActions ?? []),
      ...(verdict?.roleCannotPerform ?? []),
    ])
      .map((name) => byAction.get(name.toLowerCase()))
      .filter((row): row is CheckedAction => Boolean(row))
  if (rows.length === 0) {
    return <p className="text-xs text-content-dim mt-2">This phase makes no call an IAM policy can refuse.</p>
  }
  return (
    <div className="mt-2">
      {rows.map((row) => (
        <ActionRow
          key={`${row.identity ?? ''}-${row.action}`}
          row={row}
          identity={row.identity ? identities.get(row.identity) : undefined}
        />
      ))}
    </div>
  )
}

/** The phase's declared actions, then the policies that bear on them. */
function PhasePrevention({
  phase,
  prevention,
  onPolicy,
}: {
  phase: number
  prevention: PreventionAnalysis
  onPolicy: (policy: PreventionPolicy) => void
}) {
  if (shieldFor(phase, prevention) === 'none') {
    return (
      <p className="text-xs text-content-dim leading-relaxed mt-2">
        This phase makes no IAM-authorised AWS call, so no policy can deny it. Prevention here is a
        network or workload control.
      </p>
    )
  }
  const actions = prevention.phases.find((row) => row.phase === phase)?.actions ?? []
  const policies = policiesFor(phase, prevention)
  return (
    <>
      <div className="text-xs text-content-dim mt-2">Actions in this phase</div>
      <div className="flex flex-wrap gap-1 mt-1.5 mb-3.5">
        {actions.map((action) => (
          <span key={action} className="font-mono text-2xs text-content-secondary bg-surface-card border
            border-border rounded px-1.5 py-0.5">
            {action}
          </span>
        ))}
      </div>
      {policies.length === 0 ? (
        <p className="text-xs text-content-dim">No library policy denies these actions outright.</p>
      ) : (
        policies.map((policy) => <PolicyRow key={policy.id} policy={policy} onOpen={() => onPolicy(policy)} />)
      )}
    </>
  )
}

/** One policy as a divided list row: shield, title, verdict word, type tag. */
function PolicyRow({ policy, onOpen }: { policy: PreventionPolicy; onOpen: () => void }) {
  const blocks = policy.verdict === 'blocks'
  return (
    <button
      type="button"
      onClick={onOpen}
      className="w-full flex items-start gap-3 py-2.5 px-0.5 text-left border-b border-border first:border-t
        transition-opacity hover:opacity-60"
    >
      <Shield state={blocks ? 'blocks' : 'conditional'} size={18} />
      <span className="flex-1 min-w-0">
        <span className="block text-sm text-content-primary leading-snug tracking-body">{policy.purpose}</span>
        <span className="flex items-center gap-2 mt-1.5 text-xs">
          <span className={blocks ? 'text-safe' : 'text-warning'}>
            {blocks ? 'Blocks outright' : 'Blocks if a condition holds'}
          </span>
          <span className="font-mono text-2xs uppercase tracking-label text-content-dim border border-border
            rounded px-1.5 py-px">
            {policy.type}
          </span>
        </span>
      </span>
      <span aria-hidden="true" className="text-content-dim text-base leading-none mt-0.5">&rsaquo;</span>
    </button>
  )
}

/**
 * How an alert was tied to the rule, so a technique-level match is never
 * mistaken for an exact one.
 */
const TIER_TEXT: Record<MatchTier, string> = {
  exact: 'matched your alert by rule id',
  technique: 'matched by ATT&CK technique, so a rule of yours covers this',
  weak: 'matched during the run window',
  '': 'matched during the run window',
}

/** One expected detection and what the client's SIEM did about it. */
function DetectionRow({ rule }: { rule: RuleOutcome }) {
  return (
    <div className="flex items-start gap-3 py-2.5 px-0.5 border-b border-border first:border-t">
      <Chip className={VERDICT_CLASS[rule.verdict]}>{VERDICT_LABEL[rule.verdict]}</Chip>
      <span className="flex-1 min-w-0">
        <span className="block text-sm text-content-primary leading-snug tracking-body">{rule.title}</span>
        <span className="block font-mono text-2xs text-content-dim mt-1">
          {canonicalTechnique(rule.technique || rule.ruleId)}
          {rule.severity ? ` · ${rule.severity}` : ''}
        </span>
        {rule.evidence ? (
          <Evidence evidence={rule.evidence} tier={rule.matchTier} />
        ) : rule.verdict === 'silent' ? (
          <span className="block text-xs text-content-secondary leading-relaxed mt-1.5">
            No alert from your SIEM for this rule during the window.
          </span>
        ) : null}
      </span>
    </div>
  )
}

/** The client's alert behind a caught verdict, so the claim is traceable. */
function Evidence({ evidence, tier }: { evidence: AlertEvidence; tier: MatchTier }) {
  return (
    <span className="block text-xs text-content-secondary leading-relaxed mt-1.5">
      Your alert: {evidence.ruleName || evidence.ruleId || 'unnamed'} · {TIER_TEXT[tier]}
    </span>
  )
}
