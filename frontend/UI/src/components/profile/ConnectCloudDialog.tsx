import { useEffect, useRef, useState } from 'react'
import { useAuth } from '@/context/AuthContext'
import { PlatformIcon } from '@/components/ui/PlatformIcons'
import { Button } from '@/components/ui/Button'
import type { PlatformId } from '@/types'

/**
 * ConnectCloudDialog — connect or review a cloud account without leaving the profile.
 *
 * Replaces the standalone /connector page. That page was shown immediately after
 * login, which forced a user to hand over a cross-account IAM role before seeing
 * anything. The connector now lives on the profile and opens on demand, so the
 * decision to connect is made after the user has looked around.
 *
 * The two columns answer different questions. The left is the task: pick a
 * provider, paste a role ARN, get a verdict. The right is the reason to trust
 * it: what MayaTrail will be able to do, and the trade-off between the two
 * policies it accepts.
 */

/** ARN format: arn:aws:iam::<12-digit-account-id>:role/<role-name> */
const ARN_RE = /^arn:aws:iam::\d{12}:role\/.+$/

/**
 * Scoped policy covering every AWS action the emulation catalogue calls.
 *
 * Resource is "*" because emulations name their resources at deploy time, so
 * there is nothing stable to scope to. That makes this least privilege by
 * action, not by resource, which the comparison panel states plainly rather
 * than letting the label overstate it.
 */
const SCOPED_POLICY = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MayaTrailEmulationAccess",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:ListAccessKeys",
        "sts:AssumeRole",
        "sts:GetCallerIdentity",
        "kms:CreateKey",
        "kms:ScheduleKeyDeletion",
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*"
    }
  ]
}`

const ADMIN_POLICY = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MayaTrailAdministratorAccess",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}`

type PolicyView = 'scoped' | 'admin'

interface Provider {
  id: PlatformId
  label: string
  /** Selectable providers are the ones the backend can actually verify. */
  soon?: boolean
}

const PROVIDERS: Provider[] = [
  { id: 'aws', label: 'Amazon Web Services' },
  { id: 'azure', label: 'Microsoft Azure', soon: true },
  { id: 'gcp', label: 'Google Cloud', soon: true },
]

interface PolicyOption {
  view: PolicyView
  title: string
  tagline: string
  pros: string[]
  cons: string[]
  useWhen: string
}

const POLICY_OPTIONS: PolicyOption[] = [
  {
    view: 'scoped',
    title: 'Least Privilege',
    tagline: 'Grants only the actions emulations actually call.',
    pros: [
      'The role can create and delete exactly the resources an emulation builds, and nothing else. A mistake or a compromise cannot reach the rest of the account.',
      'Readable blast radius. Anyone reviewing the policy can see the full extent of what MayaTrail may do.',
      'Usually the only version that clears a change-approval or security review.',
    ],
    cons: [
      'Can stop a run part-way. If an emulation calls an action the list is missing, the deploy fails with AccessDenied after it has already created resources.',
      'Needs updating as the catalogue grows. New emulations bring new services.',
      'Scoped by action, not by resource. Resource is still "*", so within these actions the role reaches every object of that type.',
    ],
    useWhen: 'the account holds anything you would not want touched, or the policy has to pass review.',
  },
  {
    view: 'admin',
    title: 'Administrator',
    tagline: 'Grants everything: "Action": "*".',
    pros: [
      'No emulation can ever be blocked by a missing permission, including ones added after you connected.',
      'Nothing to maintain. The policy never needs revisiting.',
    ],
    cons: [
      'MayaTrail can do anything in the account, including things unrelated to emulations.',
      'If the role or MayaTrail is compromised, the account is fully exposed.',
      'Unlikely to pass a security review outside a sandbox.',
    ],
    useWhen: 'this is a dedicated throwaway account holding nothing of value, which is how MayaTrail is meant to be run.',
  },
]

export function ConnectCloudDialog({ onClose }: { onClose: () => void }) {
  const { user, verifyConnector, disconnectConnector, error, clearError } = useAuth()

  const [provider, setProvider] = useState<PlatformId>('aws')
  const [providerOpen, setProviderOpen] = useState(false)
  const [roleArn, setRoleArn] = useState('')
  const [localError, setLocalError] = useState('')
  const [verifying, setVerifying] = useState(false)
  const [policyView, setPolicyView] = useState<PolicyView>('scoped')
  const [copied, setCopied] = useState(false)
  const [confirmingDisconnect, setConfirmingDisconnect] = useState(false)
  const [disconnecting, setDisconnecting] = useState(false)

  const providerRef = useRef<HTMLDivElement>(null)
  const arnRef = useRef<HTMLInputElement>(null)

  const connected = Boolean(user?.isVerified)

  useEffect(() => {
    arnRef.current?.focus()
  }, [])

  // Escape closes, and the page behind must not scroll while the dialog owns
  // the viewport. Neither is handled by the other modals in this codebase, but
  // this one holds a form a user can lose input in.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = previousOverflow
    }
  }, [onClose])

  useEffect(() => {
    const onClickOutside = (e: MouseEvent) => {
      if (providerRef.current && !providerRef.current.contains(e.target as Node)) {
        setProviderOpen(false)
      }
    }
    if (providerOpen) {
      document.addEventListener('mousedown', onClickOutside)
      return () => document.removeEventListener('mousedown', onClickOutside)
    }
  }, [providerOpen])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    clearError()
    setLocalError('')

    const trimmed = roleArn.trim()
    if (!trimmed) {
      setLocalError('Please enter a Role ARN.')
      return
    }
    if (!ARN_RE.test(trimmed)) {
      setLocalError('Invalid ARN format. Expected: arn:aws:iam::<account-id>:role/<role-name>')
      return
    }

    setVerifying(true)
    try {
      // Resolves only after AuthContext has refreshed the user, so `connected`
      // below reflects the new state without a second round trip.
      await verifyConnector({ role_arn: trimmed })
    } catch {
      // Surfaced through AuthContext's error state.
    } finally {
      setVerifying(false)
    }
  }

  const handleDisconnect = async () => {
    clearError()
    setLocalError('')
    setDisconnecting(true)
    try {
      await disconnectConnector()
      setConfirmingDisconnect(false)
      setRoleArn('')
    } catch {
      // Surfaced through AuthContext's error state. A 409 lands here with the
      // names of the stacks still mid-operation.
    } finally {
      setDisconnecting(false)
    }
  }

  const handleCopy = async () => {
    const policy = policyView === 'scoped' ? SCOPED_POLICY : ADMIN_POLICY
    try {
      await navigator.clipboard.writeText(policy)
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    } catch {
      setLocalError('Could not copy to the clipboard. Select the policy text and copy it manually.')
    }
  }

  const displayError = localError || error
  const activeProvider = PROVIDERS.find((p) => p.id === provider)

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-6"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="connect-cloud-title"
        className="bg-surface-card border border-border rounded-card w-full max-w-[1040px] max-h-[88vh]
          shadow-2xl flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4 px-6 py-5 border-b border-border shrink-0">
          <div>
            <h2 id="connect-cloud-title" className="font-display text-[17px] font-semibold text-content-primary">
              Cloud Connectors
            </h2>
            <p className="text-[13px] text-content-dim mt-1">
              {connected
                ? 'Your AWS account is connected. Verify a different role to replace it.'
                : 'Connect your AWS account to start running APT emulations.'}
            </p>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="shrink-0 w-7 h-7 flex items-center justify-center rounded-btn border border-white/10
              text-content-dim transition-opacity hover:opacity-60"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-[1fr_420px] flex-1 min-h-0 overflow-hidden">
          <div className="flex flex-col px-6 py-5 overflow-y-auto min-w-0">
            <div ref={providerRef} className="relative">
              <label className="block font-mono text-2xs uppercase tracking-label text-content-dim mb-1.5">
                Provider
              </label>
              <button
                type="button"
                onClick={() => setProviderOpen((open) => !open)}
                className="flex items-center gap-2 w-full px-2.5 py-2.5 bg-surface-elevated border border-border
                  rounded-lg text-[13px] font-medium text-content-primary transition-colors hover:border-accent-blue/30"
              >
                <PlatformIcon platformId={provider} size={20} />
                <span className="flex-1 text-left">{activeProvider?.label}</span>
                <svg
                  width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                  strokeWidth="2.5" strokeLinecap="round"
                  className={`transition-transform ${providerOpen ? 'rotate-180' : ''}`}
                >
                  <path d="m6 9 6 6 6-6" />
                </svg>
              </button>

              {/* Absolutely positioned so adding providers scrolls this list
                  instead of pushing the ARN field down the column. */}
              {providerOpen && (
                <div
                  className="absolute top-[calc(100%+4px)] left-0 right-0 z-50 max-h-[210px] overflow-y-auto
                    bg-surface-card border border-white/10 rounded-lg shadow-ring overflow-hidden"
                >
                  {PROVIDERS.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      disabled={p.soon}
                      onClick={() => {
                        setProvider(p.id)
                        setProviderOpen(false)
                      }}
                      className={`flex items-center gap-2 w-full px-3 py-2.5 text-left text-[13px] font-medium
                        text-content-primary border-b border-white/[0.04] last:border-b-0 transition-colors
                        ${p.soon ? 'opacity-50 cursor-not-allowed' : 'hover:bg-white/[0.06]'}
                        ${provider === p.id ? 'bg-white/[0.04]' : ''}`}
                    >
                      <PlatformIcon platformId={p.id} size={20} />
                      <span>{p.label}</span>
                      {p.soon && (
                        <span className="ml-auto font-mono text-[9px] uppercase tracking-wider text-content-dim
                          border border-white/10 rounded px-1.5 py-px">
                          Soon
                        </span>
                      )}
                      {!p.soon && provider === p.id && (
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                          strokeWidth="2.5" strokeLinecap="round" className="ml-auto text-safe">
                          <path d="M20 6 9 17l-5-5" />
                        </svg>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="flex gap-2 items-start bg-accent-blue/[0.06] border border-accent-blue/[0.18]
              rounded-lg px-3 py-2.5 my-4 text-[12px] leading-relaxed text-content-secondary">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                className="shrink-0 mt-0.5 text-accent-blue">
                <circle cx="12" cy="12" r="9" />
                <path d="M12 16v-5M12 8h.01" strokeLinecap="round" />
              </svg>
              <span>
                MayaTrail currently supports <span className="text-accent-blue font-semibold">AWS</span> only.
                Azure and GCP support is coming soon.
              </span>
            </div>

            <ol className="flex flex-col gap-2.5 mb-5">
              {[
                'Create an IAM role in your AWS account with one of the policies shown on the right.',
                "Set its trust policy to allow MayaTrail's account to assume it.",
                'Paste the role ARN below. We verify it with sts:AssumeRole before saving.',
              ].map((step, i) => (
                <li key={i} className="flex gap-2.5 items-start text-[12.5px] leading-relaxed text-content-secondary">
                  <span className="shrink-0 w-[19px] h-[19px] mt-px rounded-full bg-surface-elevated border border-border
                    font-mono text-[10px] text-content-dim flex items-center justify-center">
                    {i + 1}
                  </span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>

            <form onSubmit={handleSubmit}>
              <label
                htmlFor="connect-role-arn"
                className="block font-mono text-2xs uppercase tracking-label text-content-dim mb-1.5"
              >
                IAM Role ARN
              </label>
              <input
                id="connect-role-arn"
                ref={arnRef}
                type="text"
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                placeholder="arn:aws:iam::123456789012:role/MayaTrailRole"
                autoComplete="off"
                spellCheck={false}
                disabled={verifying}
                className="w-full bg-surface-deep border border-white/[0.08] rounded-lg px-3 py-2.5
                  font-mono text-[12.5px] text-content-primary placeholder:text-content-dim
                  focus:outline-none focus:border-accent-blue/50"
              />
              <p className="text-[11.5px] text-content-dim mt-2">
                Format: <span className="font-mono">arn:aws:iam::&lt;12-digit-account-id&gt;:role/&lt;role-name&gt;</span>
              </p>

              {displayError && (
                <div className="flex gap-2 items-start bg-danger/[0.06] border border-danger/[0.22]
                  rounded-lg px-3 py-2.5 mt-4 text-[12px] leading-relaxed text-danger">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                    className="shrink-0 mt-0.5">
                    <circle cx="12" cy="12" r="9" />
                    <path d="M12 8v5M12 16h.01" strokeLinecap="round" />
                  </svg>
                  <span><span className="font-semibold">Verification failed.</span> {displayError}</span>
                </div>
              )}

              {connected && !displayError && (
                <div className="flex gap-2 items-start bg-safe/[0.06] border border-safe/[0.22]
                  rounded-lg px-3 py-2.5 mt-4 text-[12px] leading-relaxed text-content-secondary">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
                    strokeLinecap="round" className="shrink-0 mt-0.5 text-safe">
                    <path d="M20 6 9 17l-5-5" />
                  </svg>
                  <span>
                    <span className="font-semibold text-safe">Connected.</span> Role verified through STS.
                    You can now deploy stacks and run emulations. Close this dialog to continue.
                  </span>
                </div>
              )}

              <div className="mt-auto pt-5 flex items-center gap-3">
                <Button type="submit" disabled={verifying || disconnecting}>
                  {verifying ? 'Verifying...' : connected ? 'Verify a different role' : 'Verify & connect'}
                </Button>
                {verifying && (
                  <span className="text-[11.5px] text-content-dim">Calling sts:AssumeRole...</span>
                )}
              </div>
            </form>

            {connected && (
              <div className="mt-6 pt-5 border-t border-border">
                <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-2">
                  Disconnect
                </div>
                <p className="text-[12px] leading-relaxed text-content-secondary mb-3">
                  Disconnecting removes the role ARN from MayaTrail. It does not change anything in
                  AWS: delete the IAM role in your own account if you want to fully revoke access.
                  Any stacks still deployed will stay deployed, and MayaTrail will no longer be able
                  to destroy them, including automatic TTL cleanup. Destroy them first if you want
                  them gone.
                </p>
                {confirmingDisconnect ? (
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="text-[12px] text-danger font-semibold">
                      Disconnect this AWS account?
                    </span>
                    <Button variant="danger" onClick={handleDisconnect} disabled={disconnecting}>
                      {disconnecting ? 'Disconnecting...' : 'Yes, disconnect'}
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={() => setConfirmingDisconnect(false)}
                      disabled={disconnecting}
                    >
                      Cancel
                    </Button>
                  </div>
                ) : (
                  <Button variant="secondary" onClick={() => setConfirmingDisconnect(true)}>
                    Disconnect AWS account
                  </Button>
                )}
              </div>
            )}
          </div>

          <div className="hidden lg:flex flex-col border-l border-border bg-surface-deep min-h-0">
            <div className="px-5 py-4 border-b border-border shrink-0">
              <div className="flex items-center gap-2 text-[14px] font-semibold text-content-primary mb-1">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
                  strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6l-7-3Z" />
                </svg>
                Choosing a policy
              </div>
              <p className="text-[12px] text-content-secondary leading-relaxed">
                MayaTrail never stores AWS keys. You create a role in your own account and we assume it
                through STS, only while a run is in progress. Attach one of these two policies to that role.
              </p>
            </div>

            <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-3.5 min-h-0">
              {POLICY_OPTIONS.map((option) => (
                <div
                  key={option.view}
                  className={`bg-surface-card border rounded-[10px] p-3.5 transition-colors
                    ${policyView === option.view ? 'border-accent-blue/35' : 'border-border'}`}
                >
                  <h4 className="text-[13px] font-semibold text-content-primary mb-1">{option.title}</h4>
                  <p className="text-[11.5px] text-content-dim mb-2.5 leading-relaxed">{option.tagline}</p>
                  <ul className="flex flex-col gap-1.5">
                    {option.pros.map((text) => (
                      <PolicyPoint key={text} kind="pro" text={text} />
                    ))}
                    {option.cons.map((text) => (
                      <PolicyPoint key={text} kind="con" text={text} />
                    ))}
                  </ul>
                  <p className="mt-2.5 pt-2 border-t border-border text-[11px] text-content-dim leading-relaxed">
                    <span className="font-semibold text-content-secondary">Use when</span> {option.useWhen}
                  </p>
                </div>
              ))}

              <div>
                <div className="flex gap-1.5 mb-2.5">
                  {POLICY_OPTIONS.map((option) => (
                    <button
                      key={option.view}
                      type="button"
                      onClick={() => setPolicyView(option.view)}
                      className={`font-mono text-[10.5px] uppercase tracking-wider rounded-btn px-2.5 py-1.5
                        border transition-opacity hover:opacity-60
                        ${policyView === option.view
                          ? 'bg-white/[0.06] text-content-primary border-white/20'
                          : 'bg-transparent text-content-secondary border-white/10'}`}
                    >
                      {option.title}
                    </button>
                  ))}
                </div>
                <pre className="bg-surface-deep border border-border rounded-lg p-3 font-mono text-[10.5px]
                  leading-relaxed text-content-secondary overflow-auto max-h-[260px] m-0">
                  {policyView === 'scoped' ? SCOPED_POLICY : ADMIN_POLICY}
                </pre>
              </div>
            </div>

            <div className="px-5 py-3 border-t border-border shrink-0 flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopy}
                className="font-mono text-[10.5px] border border-white/[0.12] rounded-btn px-2.5 py-1.5
                  text-content-secondary transition-opacity hover:opacity-60"
              >
                Copy policy JSON
              </button>
              {copied && <span className="text-[11px] text-safe">Copied</span>}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

/** One pro or con bullet in a policy comparison card. */
function PolicyPoint({ kind, text }: { kind: 'pro' | 'con'; text: string }) {
  return (
    <li className="flex gap-[7px] items-start text-[11.5px] leading-relaxed text-content-secondary">
      <span
        className={`shrink-0 w-3 h-3 mt-px rounded-full flex items-center justify-center font-mono text-[9px] font-bold
          ${kind === 'pro' ? 'bg-safe/[0.14] text-safe' : 'bg-warning/[0.14] text-warning'}`}
        aria-hidden="true"
      >
        {kind === 'pro' ? '+' : '-'}
      </span>
      <span>
        <span className="sr-only">{kind === 'pro' ? 'Advantage: ' : 'Trade-off: '}</span>
        {text}
      </span>
    </li>
  )
}
