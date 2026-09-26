import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { IconClose } from '@/components/ui/Icons'
import type { PreventionPolicy } from '@/types/prevention'

/**
 * One guardrail policy, read beside the attack phase it would refuse.
 *
 * A right-hand panel rather than a section on the page: the policy document is
 * reference material a reader dips into and leaves, and inlining ten of them
 * turned the prevention view into something to read rather than something to
 * use.
 *
 * The verdict is stated once, here, in the context of the phase the reader
 * selected. A conditional deny says plainly that the deciding value belongs to
 * their organisation, because the alternative is a green row implying
 * protection MayaTrail never measured.
 */

const PANEL_WIDTH = 'w-full sm:w-[min(720px,50vw)] sm:min-w-[460px]'

interface GuardrailDrawerProps {
  /** The policy to show, or null when the drawer is closed. */
  policy: PreventionPolicy | null
  /** Perimeter policies, shown together when `policy` is the group sentinel. */
  perimeter: PreventionPolicy[]
  /** True when the drawer should show the collapsed perimeter family. */
  showPerimeter: boolean
  platformId: string
  onClose: () => void
}

/** Action chips, coloured by how certain the refusal is. */
function Actions({ actions, blocks }: { actions: string[]; blocks: boolean }) {
  return (
    <span className="flex flex-wrap gap-1">
      {actions.map((action) => (
        <span
          key={action}
          className={`rounded px-1.5 py-0.5 font-mono text-[10.5px] ${
            blocks ? 'bg-safe/10 text-safe' : 'bg-warning/10 text-warning'
          }`}
        >
          {action}
        </span>
      ))}
    </span>
  )
}

export function GuardrailDrawer({
  policy,
  perimeter,
  showPerimeter,
  platformId,
  onClose,
}: GuardrailDrawerProps) {
  const open = Boolean(policy) || showPerimeter
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

  const blocks = policy?.verdict === 'blocks'

  return (
    <div className="fixed inset-0 z-[200] flex justify-end" role="dialog" aria-modal="true">
      <div
        onClick={onClose}
        className={`absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity duration-300
          ${shown ? 'opacity-100' : 'opacity-0'}`}
      />
      <aside
        className={`relative h-full overflow-y-auto border-l border-border bg-surface-card
          transition-transform duration-300 ease-out ${PANEL_WIDTH}
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

        {showPerimeter ? (
          <>
            <div className="sticky top-0 z-[1] border-b border-border bg-surface-card px-6 pb-4 pt-5">
              <div className="mb-2 font-mono text-2xs uppercase tracking-label text-content-dim">
                Guardrail library
              </div>
              <div className="text-[17px] font-semibold text-content-primary">
                Data perimeter policies
              </div>
              <div className="mt-1.5 text-xs text-content-dim">
                {perimeter.length} policies &middot; SCP and RCP
              </div>
            </div>
            <div className="px-6 pb-10 pt-5">
              <div className="mb-4 flex gap-2.5 rounded-btn border-l-2 border-warning bg-surface-elevated px-3.5 py-3">
                <span className="flex-none text-warning">&#9888;</span>
                <p className="text-xs leading-relaxed text-content-secondary">
                  These deny a whole service unless the caller is inside a boundary you define.
                  Against this attack they are{' '}
                  <b className="font-semibold text-content-primary">one recommendation</b>: if your
                  perimeter holds, the attacker never reaches the resource. They touch every phase
                  because they match every action of the service.
                </p>
              </div>
              {perimeter.map((item) => (
                <Link
                  key={item.id}
                  to={`/${platformId}/guardrails/${item.id}`}
                  className="mb-1.5 flex items-center gap-3 rounded-btn bg-surface-elevated px-3.5 py-2.5 no-underline transition-opacity hover:opacity-65"
                >
                  <span className="flex-1 text-[12.5px] text-content-secondary">{item.purpose}</span>
                  <span className="rounded bg-white/5 px-1.5 py-px font-mono text-[9px] text-content-dim">
                    {item.type}
                  </span>
                </Link>
              ))}
            </div>
          </>
        ) : policy ? (
          <>
            <div className="sticky top-0 z-[1] border-b border-border bg-surface-card px-6 pb-4 pt-5">
              <div className="mb-2 font-mono text-2xs uppercase tracking-label text-content-dim">
                Guardrail &middot; {policy.type}
              </div>
              <div className="pr-8 text-[17px] font-semibold leading-snug text-content-primary">
                {policy.purpose}
              </div>
            </div>

            <div className="px-6 pb-10 pt-5">
              <div
                className={`mb-5 flex gap-2.5 rounded-btn border-l-2 bg-surface-elevated px-3.5 py-3 ${
                  blocks ? 'border-safe' : 'border-warning'
                }`}
              >
                <span className={`flex-none ${blocks ? 'text-safe' : 'text-warning'}`}>
                  {blocks ? '✓' : '⚠'}
                </span>
                <p className="text-xs leading-relaxed text-content-secondary">
                  {blocks ? (
                    <>
                      <b className="font-semibold text-content-primary">
                        Would block this phase outright.
                      </b>{' '}
                      The deny carries no condition, so if you deploy this policy these actions fail
                      for every principal.
                    </>
                  ) : (
                    <>
                      <b className="font-semibold text-content-primary">
                        Would block only if a condition holds.
                      </b>{' '}
                      The deny applies unless{' '}
                      <span className="font-mono">{policy.conditionKeys[0]}</span>
                      {policy.conditionKeys.length > 1
                        && ` and ${policy.conditionKeys.length - 1} other condition key${
                          policy.conditionKeys.length > 2 ? 's' : ''
                        }`}{' '}
                      is satisfied. That value belongs to your organisation, so MayaTrail cannot
                      tell you whether this protects you today.
                    </>
                  )}
                </p>
              </div>

              <div className="mb-5 grid grid-cols-[132px_1fr] gap-x-3.5 gap-y-2.5 text-[12.5px]">
                <span className="pt-0.5 font-mono text-[10px] uppercase tracking-label text-content-dim">
                  Denies
                </span>
                <Actions actions={policy.actions} blocks={Boolean(blocks)} />

                <span className="font-mono text-[10px] uppercase tracking-label text-content-dim">
                  Type
                </span>
                <span className="text-content-secondary">
                  {policy.type === 'SCP' ? 'Service control policy' : 'Resource control policy'}
                </span>

                {policy.phases.length > 0 && (
                  <>
                    <span className="font-mono text-[10px] uppercase tracking-label text-content-dim">
                      Phases
                    </span>
                    <span className="text-content-secondary">{policy.phases.join(', ')}</span>
                  </>
                )}

                {policy.source?.label && (
                  <>
                    <span className="font-mono text-[10px] uppercase tracking-label text-content-dim">
                      Source
                    </span>
                    <span>
                      {policy.source.url ? (
                        <a
                          href={policy.source.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-accent-blue no-underline transition-opacity hover:opacity-70"
                        >
                          {policy.source.label}
                        </a>
                      ) : (
                        <span className="text-content-secondary">{policy.source.label}</span>
                      )}
                    </span>
                  </>
                )}

                <span className="font-mono text-[10px] uppercase tracking-label text-content-dim">
                  Basis
                </span>
                <span className="text-content-dim">
                  Published AWS sample. Not read from your account.
                </span>
              </div>

              <Link
                to={`/${platformId}/guardrails/${policy.id}`}
                className="text-[12.5px] text-accent-blue no-underline transition-opacity hover:opacity-70"
              >
                Open in the guardrail library &rarr;
              </Link>
            </div>
          </>
        ) : null}
      </aside>
    </div>
  )
}
