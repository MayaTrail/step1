import { useCallback, useState } from 'react'

import { checkAgainstAccount } from '@/services/prevention.service'
import type { AccountCheck, AccountCheckError, CheckedPhase, PreventionAnalysis } from '@/types/prevention'
import { AccountCheckDrawer, canRecheck, formatCheckedAt } from './AccountCheckDrawer'

/**
 * Asking AWS what the reader's own policies would do to this emulation.
 *
 * The shields above this come from the policy library: "a published sample
 * would refuse this, if you deployed it". This answers the stronger question,
 * "your policies refuse it now", by having AWS evaluate the connected role
 * without performing anything.
 *
 * It sits behind a button rather than running on page load for two reasons:
 * it spends an AWS call per use, and an answer about someone's live
 * configuration should be something they asked for and can date, not a figure
 * that appeared while they were reading.
 *
 * The button opens a drawer at once, showing what is being asked while AWS
 * answers and then the answer itself. Once closed, one line stays here with a
 * way back to it.
 *
 * Every wording here keeps three things apart, because conflating them would
 * tell a reader they are protected when they are not:
 *   a guardrail refused the action,
 *   the connected role lacks the permission, which stops the attack for an
 *     unrelated reason and is a setup problem,
 *   AWS could not decide, because a policy's condition needed a value we
 *     cannot supply for an emulation that has not been deployed.
 */

interface AccountCheckPanelProps {
  emulationType: string
  /** The declared phases and actions, shown while AWS answers. */
  prevention: PreventionAnalysis
  /** The result, held by the parent so each phase can show its own verdict. */
  check: AccountCheck | null
  onChecked: (result: AccountCheck | null) => void
}

export function AccountCheckPanel({ emulationType, prevention, check, onChecked }: AccountCheckPanelProps) {
  const [running, setRunning] = useState(false)
  const [refusal, setRefusal] = useState<AccountCheckError | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [checkedAt, setCheckedAt] = useState<Date | null>(null)

  const closeDrawer = useCallback(() => setDrawerOpen(false), [])

  async function run() {
    if (running) return
    setRunning(true)
    setRefusal(null)
    setDrawerOpen(true)
    try {
      const result = await checkAgainstAccount(emulationType)
      setCheckedAt(new Date())
      onChecked(result)
    } catch (caught) {
      const body = (caught as { response?: { data?: Partial<AccountCheckError> } }).response?.data
      setRefusal({
        detail: body?.detail ?? 'The check could not be run.',
        missingPermission: body?.missingPermission ?? null,
      })
      onChecked(null)
    } finally {
      setRunning(false)
    }
  }

  let line: React.ReactNode
  if (check) {
    line = (
      <Summary
        check={check}
        checkedAt={checkedAt}
        running={running}
        onOpen={() => setDrawerOpen(true)}
        onRecheck={run}
      />
    )
  } else if (refusal && !running) {
    line = (
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="font-mono text-2xs uppercase tracking-label text-content-dim">Your account</span>
        <span className="text-sm text-content-secondary">The check could not run.</span>
        <LinkButton onClick={() => setDrawerOpen(true)}>View details &rsaquo;</LinkButton>
      </div>
    )
  } else {
    line = (
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <button
          type="button"
          onClick={run}
          disabled={running}
          className="px-3 py-1.5 rounded-btn border border-white/10 text-xs font-medium tracking-btn
            text-content-primary transition-opacity hover:opacity-60 disabled:opacity-40"
        >
          {running ? 'Asking AWS…' : 'Check against my account'}
        </button>
        {running && !drawerOpen ? (
          <LinkButton onClick={() => setDrawerOpen(true)}>See what is being asked &rsaquo;</LinkButton>
        ) : (
          <span className="text-xs text-content-dim leading-relaxed">
            Asks AWS whether your own policies would refuse these actions. Nothing is performed.
          </span>
        )}
      </div>
    )
  }

  return (
    <div className="mt-3.5 border-t border-border pt-3.5">
      {line}
      <AccountCheckDrawer
        open={drawerOpen}
        running={running}
        check={check}
        refusal={refusal}
        prevention={prevention}
        checkedAt={checkedAt}
        onClose={closeDrawer}
        onRecheck={run}
      />
    </div>
  )
}

/** A text-only blue action, for secondary links beside the summary. */
function LinkButton({
  onClick,
  disabled,
  children,
}: {
  onClick: () => void
  disabled?: boolean
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="text-xs text-accent-blue transition-opacity hover:opacity-60 disabled:opacity-40"
    >
      {children}
    </button>
  )
}

/** What the check found, in one line; the drawer holds the detail and caveats. */
function Summary({
  check,
  checkedAt,
  running,
  onOpen,
  onRecheck,
}: {
  check: AccountCheck
  checkedAt: Date | null
  running: boolean
  onOpen: () => void
  onRecheck: () => void
}) {
  const { prevented, undecided, roleCannotPerform, actionsChecked } = check.summary
  const notChecked = check.summary.notChecked?.length ?? 0
  const gaps = [
    undecided.length > 0 && `${undecided.length} undecided`,
    roleCannotPerform.length > 0 && `${roleCannotPerform.length} your role can't perform`,
  ].filter(Boolean)
  return (
    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
      <span className="font-mono text-2xs uppercase tracking-label text-content-dim">Your account</span>
      {actionsChecked === 0 ? (
        <span className="text-sm leading-relaxed text-content-secondary">
          Nothing could be checked yet: see who performs this attack&apos;s actions.
        </span>
      ) : (
        <span className="text-sm leading-relaxed text-content-secondary">
          <b className="font-semibold text-content-primary">
            {prevented.length === 0 ? `None of ${actionsChecked}` : `${prevented.length} of ${actionsChecked}`}
          </b>{' '}
          {notChecked > 0 ? 'checked actions' : 'actions'} would be refused by your guardrails.
          {gaps.length > 0 && <span className="text-warning"> {gaps.join(', ')}.</span>}
          {notChecked > 0 && <span className="text-content-dim"> {notChecked} not checked (other identities).</span>}
        </span>
      )}
      <span className="font-mono text-2xs text-content-muted">
        simulated · {formatCheckedAt(checkedAt)} · {check.region}
      </span>
      <span className="ml-auto flex gap-3">
        <LinkButton onClick={onOpen}>View details &rsaquo;</LinkButton>
        {/* With no connected role or lab identity involved, a recheck could not change the answer. */}
        {canRecheck(check.identities ?? [{ kind: 'connected_role' }]) && (
          <LinkButton onClick={onRecheck} disabled={running}>
            {running ? 'Asking AWS…' : 'Check again'}
          </LinkButton>
        )}
      </span>
    </div>
  )
}

const PHASE_TEXT: Record<CheckedPhase['verdict'], string> = {
  denied: 'Your policies refuse this phase',
  allowed: 'Your policies allow this phase',
  undecided: 'Your policies could not be decided for this phase',
  role_cannot_perform: 'Your role cannot perform this phase',
  no_iam_call: 'No IAM-authorised call to refuse',
  not_checked: 'Not checked: some of this phase runs as another identity',
  no_identity: 'Sent with no identity, so no IAM rule applies',
}

const PHASE_TONE: Record<CheckedPhase['verdict'], string> = {
  denied: 'text-safe',
  allowed: 'text-content-secondary',
  undecided: 'text-warning',
  role_cannot_perform: 'text-warning',
  no_iam_call: 'text-content-dim',
  not_checked: 'text-content-dim',
  no_identity: 'text-content-dim',
}

/**
 * One phase's account verdict, shown beside the catalogue advice for it.
 *
 * @param check - The result, or null before a check has been run.
 * @param phaseNumber - The phase to describe.
 */
export function PhaseAccountVerdict({
  check,
  phaseNumber,
}: {
  check: AccountCheck | null
  phaseNumber: number
}) {
  const row = check?.phases.find((phase) => phase.phase === phaseNumber)
  if (!row) return null
  const detail = row.preventedActions.length > 0 ? row.preventedActions : row.undecidedActions
  return (
    <p className="mt-2.5 text-xs leading-relaxed">
      <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
        Your account:{' '}
      </span>
      <span className={PHASE_TONE[row.verdict]}>{PHASE_TEXT[row.verdict]}</span>
      {detail.length > 0 && (
        <span className="font-mono text-content-dim"> ({detail.join(', ')})</span>
      )}
    </p>
  )
}
