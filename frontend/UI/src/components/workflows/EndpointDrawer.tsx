import { useEffect, useState } from 'react'
import type { AlertEndpoint } from '@/types/workflow'
import {
  deleteAlertEndpoint,
  revealEndpointSecret,
  rotateEndpointSecret,
} from '@/services/workflow.service'
import { Badge } from '@/components/ui/Badge'
import { IconClose } from '@/components/ui/Icons'
import { formatWhen } from '@/components/threatfeed/feedMeta'
import { CopyValue, endpointUrl } from './endpointMeta'

/**
 * One endpoint's configuration, slid in from the right over the list.
 *
 * The same panel shape as a workflow run, for the same reason: reading one
 * endpoint is part of scanning several, and the list keeps its scroll position
 * behind it.
 *
 * The secret is revealed on request rather than shown outright. It is stored
 * encrypted rather than hashed, because the server reproduces an HMAC with it
 * on every inbound alert, so it has always been recoverable and pretending
 * otherwise only cost a client their integration when they lost their copy.
 * Masking it by default keeps it out of screenshots and shared screens, which
 * is the actual risk: the secret authorises posting alerts, so a leak lets
 * someone inflate a detection score rather than read anything.
 */

/** Half the viewport, within bounds that stay readable on either extreme. */
const PANEL_WIDTH = 'w-full sm:w-[min(720px,50vw)] sm:min-w-[460px]'

interface EndpointDrawerProps {
  endpoint: AlertEndpoint
  onClose: () => void
  /** Called after a change the list has to refetch to show. */
  onChanged: () => void
}

export function EndpointDrawer({ endpoint, onClose, onChanged }: EndpointDrawerProps) {
  const [shown, setShown] = useState(false)
  const [secret, setSecret] = useState<string | null>(null)
  const [busy, setBusy] = useState<'reveal' | 'rotate' | 'delete' | null>(null)
  const [confirming, setConfirming] = useState<'rotate' | 'delete' | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Mount off-screen, then slide in on the next frame.
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => setShown(true))
    return () => window.cancelAnimationFrame(frame)
  }, [])

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = previous
    }
  }, [onClose])

  const used = endpoint.alertCount > 0 || Boolean(endpoint.lastAlertAt)

  async function reveal() {
    setBusy('reveal')
    setError(null)
    try {
      setSecret(await revealEndpointSecret(endpoint.id))
    } catch {
      setError('Could not read the secret. It may have been encrypted with a different key.')
    } finally {
      setBusy(null)
    }
  }

  async function rotate() {
    setBusy('rotate')
    setError(null)
    try {
      const updated = await rotateEndpointSecret(endpoint.id)
      setSecret(updated.secret)
      setConfirming(null)
      onChanged()
    } catch {
      setError('Could not rotate the secret.')
    } finally {
      setBusy(null)
    }
  }

  async function remove() {
    setBusy('delete')
    setError(null)
    try {
      await deleteAlertEndpoint(endpoint.id)
      onChanged()
      onClose()
    } catch (caught) {
      // The server refuses with a sentence explaining why, which is more use
      // than anything this component could invent.
      const detail = (caught as { response?: { data?: { detail?: string } } })
        .response?.data?.detail
      setError(detail ?? 'Could not delete the endpoint.')
      setConfirming(null)
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="fixed inset-0 z-[200] flex justify-end" role="dialog" aria-modal="true">
      <div
        onClick={onClose}
        aria-hidden="true"
        className={`absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity duration-300
          ${shown ? 'opacity-100' : 'opacity-0'}`}
      />

      <aside
        className={`relative h-full ${PANEL_WIDTH} bg-surface-base border-l border-border
          shadow-float flex flex-col transition-transform duration-300 ease-out
          ${shown ? 'translate-x-0' : 'translate-x-full'}`}
      >
        <header className="flex items-start gap-3 px-5 py-4 border-b border-border shrink-0">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="font-display text-lg font-semibold text-content-primary leading-tight truncate">
                {endpoint.name}
              </h2>
              <Badge tone={endpoint.enabled ? 'green' : 'neutral'} mono dot>
                {endpoint.enabled ? 'Enabled' : 'Disabled'}
              </Badge>
            </div>
            <p className="text-xs text-content-dim mt-1">
              Created {formatWhen(endpoint.createdAt)} by {endpoint.createdBy}
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="shrink-0 p-1.5 rounded-btn text-content-dim
              transition-colors hover:text-content-primary"
          >
            <IconClose size={16} />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-6">
          <Section title="Webhook URL">
            <CopyValue value={endpointUrl(endpoint.id)} />
            <p className="text-xs text-content-dim mt-2">
              Point your SIEM's webhook action here. Sign each request with the secret below.
            </p>
          </Section>

          <Section title="Signing secret">
            <CopyValue value={secret ?? ''} masked={secret === null} />
            <div className="flex flex-wrap items-center gap-2 mt-2.5">
              {secret === null ? (
                <SmallButton onClick={reveal} disabled={busy !== null}>
                  {busy === 'reveal' ? 'Reading…' : 'Reveal'}
                </SmallButton>
              ) : (
                <SmallButton onClick={() => setSecret(null)}>Hide</SmallButton>
              )}

              {confirming === 'rotate' ? (
                <>
                  <SmallButton onClick={rotate} disabled={busy !== null} tone="danger">
                    {busy === 'rotate' ? 'Rotating…' : 'Confirm rotate'}
                  </SmallButton>
                  <SmallButton onClick={() => setConfirming(null)}>Cancel</SmallButton>
                </>
              ) : (
                <SmallButton onClick={() => setConfirming('rotate')} disabled={busy !== null}>
                  Rotate
                </SmallButton>
              )}
              <span className="font-mono text-2xs text-content-muted">
                ends {endpoint.secretHint}
              </span>
            </div>
            <p className="text-xs text-content-dim mt-2">
              {confirming === 'rotate'
                ? 'Rotating takes effect immediately. Alerts signed with the current secret stop verifying, so update your SIEM before your next run.'
                : 'Revealing is recorded in the audit log. Rotate if the secret has been shared somewhere it should not have been.'}
            </p>
          </Section>

          <Section title="Usage">
            <div className="grid grid-cols-2 gap-x-4 gap-y-3">
              <Fact label="Alerts accepted" value={String(endpoint.alertCount)} />
              <Fact
                label="Last alert"
                value={endpoint.lastAlertAt ? formatWhen(endpoint.lastAlertAt) : 'never'}
              />
            </div>
            {!used && (
              <p className="text-xs text-content-dim mt-3">
                This endpoint has never received an alert. Send a test alert from your SIEM to
                confirm the integration before spending money on a run.
              </p>
            )}
          </Section>

          <Section title="Delete">
            {used ? (
              <p className="text-xs text-content-dim leading-relaxed">
                This endpoint has accepted {endpoint.alertCount}{' '}
                {endpoint.alertCount === 1 ? 'alert' : 'alerts'} and cannot be deleted. Those
                alerts are the evidence behind the verdicts in past workflow reports, and
                removing them would rewrite results a run already established.
              </p>
            ) : (
              <>
                <p className="text-xs text-content-dim leading-relaxed mb-2.5">
                  This endpoint has never been used, so deleting it removes it permanently and
                  leaves no report without its evidence.
                </p>
                {confirming === 'delete' ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <SmallButton onClick={remove} disabled={busy !== null} tone="danger">
                      {busy === 'delete' ? 'Deleting…' : 'Confirm delete'}
                    </SmallButton>
                    <SmallButton onClick={() => setConfirming(null)}>Cancel</SmallButton>
                  </div>
                ) : (
                  <SmallButton onClick={() => setConfirming('delete')} tone="danger">
                    Delete endpoint
                  </SmallButton>
                )}
              </>
            )}
          </Section>

          {error && <p className="text-xs text-danger leading-relaxed">{error}</p>}
        </div>
      </aside>
    </div>
  )
}

/** A labelled block within the panel. */
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-2.5">
        {title}
      </h3>
      {children}
    </section>
  )
}

/** One label and its value, for facts that need no interaction. */
function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="block font-mono text-2xs uppercase tracking-caps text-content-muted">
        {label}
      </span>
      <span className="block text-sm text-content-secondary mt-0.5">{value}</span>
    </div>
  )
}

/** A compact action button, matching the platform's opacity hover. */
function SmallButton({
  children,
  onClick,
  disabled = false,
  tone = 'default',
}: {
  children: React.ReactNode
  onClick: () => void
  disabled?: boolean
  tone?: 'default' | 'danger'
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn border
        transition-opacity hover:opacity-60 disabled:opacity-30 disabled:cursor-not-allowed
        ${tone === 'danger'
          ? 'border-danger/30 text-danger'
          : 'border-border text-content-primary shadow-button'}`}
    >
      {children}
    </button>
  )
}
