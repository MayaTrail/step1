import { useEffect, useRef, useState } from 'react'
import { useAuth } from '@/context/AuthContext'
import { PlatformIcon } from '@/components/ui/PlatformIcons'
import { Button } from '@/components/ui/Button'

/**
 * ConnectScoutRoleDialog — connect the read-only role the Attack Graph scan assumes.
 *
 * Deliberately smaller than ConnectCloudDialog: one provider, one policy, one
 * action. This role grants a single IAM read, not a set of trade-offs to
 * weigh, so the dialog does not offer a comparison to make.
 */

/** ARN format: arn:aws:iam::<12-digit-account-id>:role/<role-name> */
const ARN_RE = /^arn:aws:iam::\d{12}:role\/.+$/

/**
 * Minimal policy for the Scout audit role — one read action.
 *
 * Stated as a single action on purpose. sts:GetCallerIdentity needs no
 * permission at all, and everything else Scout does is computed locally from
 * the authorization details this one call returns. A security product asking
 * for one read is a far better conversation with a customer's security team
 * than one asking for a broad managed policy.
 */
const AUDIT_POLICY = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MayaTrailScoutAudit",
      "Effect": "Allow",
      "Action": "iam:GetAccountAuthorizationDetails",
      "Resource": "*"
    }
  ]
}`

export function ConnectScoutRoleDialog({ onClose }: { onClose: () => void }) {
  const { verifyAuditRole, error, clearError } = useAuth()

  const [roleArn, setRoleArn] = useState('')
  const [localError, setLocalError] = useState('')
  const [verifying, setVerifying] = useState(false)
  const [copied, setCopied] = useState(false)

  const arnRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    arnRef.current?.focus()
  }, [])

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
      // The context's verifyAuditRole has already re-fetched /auth/me/ by the
      // time this resolves, so the caller sees hasAuditRole=true immediately.
      await verifyAuditRole({ role_arn: trimmed })
      onClose()
    } catch {
      // Surfaced through AuthContext's error state, rendered verbatim below.
    } finally {
      setVerifying(false)
    }
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(AUDIT_POLICY)
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    } catch {
      setLocalError('Could not copy to the clipboard. Select the policy text and copy it manually.')
    }
  }

  const displayError = localError || error

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-6"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="connect-scout-title"
        className="bg-surface-card border border-border rounded-card w-full max-w-[880px] max-h-[88vh]
          shadow-2xl flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4 px-6 py-5 border-b border-border shrink-0">
          <div>
            <h2 id="connect-scout-title" className="font-display text-[17px] font-semibold text-content-primary">
              Connect Scout Audit Role
            </h2>
            <p className="text-[13px] text-content-dim mt-1">
              Read-only. Used only to scan your account&apos;s IAM graph for privilege-escalation paths.
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

        <div className="grid grid-cols-1 lg:grid-cols-[1fr_380px] flex-1 min-h-0 overflow-hidden">
          <div className="flex flex-col px-6 py-5 overflow-y-auto min-w-0">
            <div className="flex items-center gap-2 mb-4">
              <PlatformIcon platformId="aws" size={20} />
              <span className="text-[13px] font-medium text-content-primary">Amazon Web Services</span>
            </div>

            <ol className="flex flex-col gap-2.5 mb-5">
              {[
                'Create a separate IAM role in your AWS account — do not reuse the emulation role.',
                'Attach the policy shown on the right, or the AWS managed SecurityAudit policy if your org standardises on it.',
                "Set its trust policy to allow MayaTrail's account to assume it.",
                'Paste the role ARN below. We assume it and confirm it can read IAM before saving.',
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
                htmlFor="connect-scout-role-arn"
                className="block font-mono text-2xs uppercase tracking-label text-content-dim mb-1.5"
              >
                IAM Role ARN
              </label>
              <input
                id="connect-scout-role-arn"
                ref={arnRef}
                type="text"
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                placeholder="arn:aws:iam::123456789012:role/MayaTrailScoutAudit"
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

              <div className="mt-auto pt-5 flex items-center gap-3">
                <Button type="submit" disabled={verifying}>
                  {verifying ? 'Verifying...' : 'Verify & connect'}
                </Button>
                {verifying && (
                  <span className="text-[11.5px] text-content-dim">Assuming role and probing IAM...</span>
                )}
              </div>
            </form>
          </div>

          <div className="hidden lg:flex flex-col border-l border-border bg-surface-deep min-h-0">
            <div className="px-5 py-4 border-b border-border shrink-0">
              <div className="flex items-center gap-2 text-[14px] font-semibold text-content-primary mb-1">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
                  strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 3 5 6v6c0 4 3 7 7 9 4-2 7-5 7-9V6l-7-3Z" />
                </svg>
                Required policy
              </div>
              <p className="text-[12px] text-content-secondary leading-relaxed">
                One read action. Everything Scout reports is computed locally from what this call
                returns — nothing is written, and nothing else is read.
              </p>
            </div>

            <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-3.5 min-h-0">
              <pre className="bg-surface-card border border-border rounded-lg p-3 font-mono text-[10.5px]
                leading-relaxed text-content-secondary overflow-auto max-h-[260px] m-0">
                {AUDIT_POLICY}
              </pre>
              <p className="text-[11.5px] text-content-dim leading-relaxed">
                Already standardised on the AWS managed <span className="font-mono text-content-secondary">SecurityAudit</span> policy?
                That works too — connecting only checks that the role can call
                <span className="font-mono text-content-secondary"> iam:GetAccountAuthorizationDetails</span>, whichever
                policy grants it.
              </p>
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
