/**
 * Connecting, and managing, the read-only Scout audit role.
 *
 * Lives on the Attack Graph page only: this role exists for this feature and
 * nothing else uses it, so it is set up where it is used. Settings lists it
 * read-only alongside the emulation role.
 */

import { useEffect, useState } from 'react'

import { useAuth } from '@/context/AuthContext'
import { fetchProfile } from '@/services/auth.service'

/** arn:aws:iam::<12-digit-account-id>:role/<role-name> */
const ARN_RE = /^arn:aws:iam::\d{12}:role\/.+$/

/** The one read an IAM-only scan needs. */
const IAM_ONLY_POLICY = `{
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

const SECURITY_AUDIT_ARN = 'arn:aws:iam::aws:policy/SecurityAudit'

/**
 * Regions offered for resource collection. Declared by the tenant rather than
 * detected: this is a consented scan, so there is no reason to probe for the
 * account's footprint instead of asking. Commercial partitions only.
 */
const REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'sa-east-1',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1', 'eu-south-1',
  'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
  'ap-northeast-3', 'ap-east-1', 'me-south-1', 'af-south-1',
]

export function ScoutConnectPanel({
  manage = false,
  onDone,
}: {
  /** True when a role is already connected: pre-fills it and offers disconnect. */
  manage?: boolean
  /** Called after a successful connect, save or disconnect. */
  onDone?: () => void
}) {
  const { user, verifyAuditRole, disconnectAuditRole, error, clearError } = useAuth()
  const [roleArn, setRoleArn] = useState('')
  const [regions, setRegions] = useState<string[]>(user?.auditRegions ?? [])
  const [localError, setLocalError] = useState('')
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const [confirmingDisconnect, setConfirmingDisconnect] = useState(false)

  // Managing an existing connection starts from the stored ARN, which the
  // session user object does not carry; the profile endpoint does.
  useEffect(() => {
    if (!manage) return
    let active = true
    fetchProfile()
      .then((profile) => { if (active) setRoleArn(profile.aws_audit_role_arn ?? '') })
      .catch(() => undefined)
    return () => { active = false }
  }, [manage])

  const toggleRegion = (region: string) => {
    setRegions((current) => (current.includes(region) ? current.filter((r) => r !== region) : [...current, region]))
  }

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    clearError()
    setLocalError('')
    const trimmed = roleArn.trim()
    if (!ARN_RE.test(trimmed)) {
      setLocalError('Enter a role ARN like arn:aws:iam::123456789012:role/scout-security-audit.')
      return
    }
    setBusy(true)
    try {
      await verifyAuditRole({ role_arn: trimmed, regions })
      onDone?.()
    } catch {
      // AuthContext holds the message; it renders below.
    } finally {
      setBusy(false)
    }
  }

  const disconnect = async () => {
    clearError()
    setBusy(true)
    try {
      await disconnectAuditRole()
      onDone?.()
    } catch {
      // A 409 (a scan is running) lands in AuthContext's error and renders below.
    } finally {
      setBusy(false)
      setConfirmingDisconnect(false)
    }
  }

  const copyPolicy = async () => {
    try {
      await navigator.clipboard.writeText(regions.length > 0 ? SECURITY_AUDIT_ARN : IAM_ONLY_POLICY)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      setLocalError('Could not copy to the clipboard. Select the policy text and copy it manually.')
    }
  }

  const shownError = localError || error

  return (
    <section>
      <div className="mb-2.5 font-mono text-2xs uppercase tracking-label text-content-dim">
        {manage ? 'Scout audit role' : 'Connect a read-only role'}
      </div>
      <form
        onSubmit={submit}
        className="grid grid-cols-1 gap-7 rounded-card border border-border bg-surface-card px-6 py-5 shadow-ring lg:grid-cols-2"
      >
        <div>
          <label htmlFor="scout-role-arn" className="mb-1.5 block text-xs text-content-dim">Role ARN</label>
          <input
            id="scout-role-arn"
            type="text"
            value={roleArn}
            onChange={(e) => setRoleArn(e.target.value)}
            placeholder="arn:aws:iam::123456789012:role/scout-security-audit"
            autoComplete="off"
            spellCheck={false}
            disabled={busy}
            className="w-full rounded-btn border border-border bg-surface-deep px-3 py-2.5 font-mono text-xs text-content-primary
              placeholder:text-content-dim focus:border-accent-blue focus:outline-none focus:ring-4 focus:ring-accent-blue-glow"
          />

          <div className="mb-1.5 mt-4 text-xs text-content-dim">Regions to include (optional)</div>
          <div className="flex flex-wrap gap-1.5">
            {REGIONS.map((region) => {
              const on = regions.includes(region)
              return (
                <button
                  key={region}
                  type="button"
                  onClick={() => toggleRegion(region)}
                  disabled={busy}
                  aria-pressed={on}
                  className={`rounded-btn border px-2 py-0.5 font-mono text-2xs transition-opacity hover:opacity-60
                    ${on ? 'border-accent-blue bg-accent-blue-glow text-accent-blue' : 'border-border bg-transparent text-content-dim'}`}
                >
                  {region}
                </button>
              )
            })}
          </div>
          <p className="mt-2 text-xs text-content-dim">
            {regions.length > 0
              ? `Resources in ${regions.length} region${regions.length > 1 ? 's' : ''} are read too. Each region adds time.`
              : 'IAM only: fastest, but cannot find paths that go through a Lambda function or an EC2 instance.'}
          </p>

          {shownError && <p className="mt-3 text-xs text-danger">{shownError}</p>}

          <div className="mt-5 flex flex-wrap items-center gap-3">
            <button
              type="submit"
              disabled={busy}
              className="rounded-pill bg-white/80 px-4 py-1.5 text-xs font-semibold text-button-fg transition-opacity hover:opacity-60
                disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? 'Verifying…' : manage ? 'Verify and save' : 'Verify and connect'}
            </button>
            {manage && !confirmingDisconnect && (
              <button
                type="button"
                onClick={() => setConfirmingDisconnect(true)}
                disabled={busy}
                className="rounded-btn border border-border bg-transparent px-3 py-1.5 text-xs text-content-secondary transition-opacity hover:opacity-60"
              >
                Disconnect
              </button>
            )}
            {manage && confirmingDisconnect && (
              <span className="flex items-center gap-2 text-xs text-content-secondary">
                Disconnect the Scout role?
                <button type="button" onClick={disconnect} disabled={busy}
                  className="rounded-btn border border-danger bg-transparent px-3 py-1.5 font-semibold text-danger transition-opacity hover:opacity-60">
                  Disconnect
                </button>
                <button type="button" onClick={() => setConfirmingDisconnect(false)} disabled={busy}
                  className="rounded-btn border border-border bg-transparent px-3 py-1.5 transition-opacity hover:opacity-60">
                  Cancel
                </button>
              </span>
            )}
            {!manage && (
              <span className="text-xs text-content-dim">
                MayaTrail assumes the role once and checks it can read IAM before saving it.
              </span>
            )}
          </div>
        </div>

        <div>
          <div className="mb-1.5 text-xs text-content-dim">
            {regions.length > 0 ? 'The role needs this AWS managed policy' : 'The role needs exactly this permission'}
          </div>
          {regions.length > 0 ? (
            <div className="rounded-btn border border-border bg-surface-deep p-3 font-mono text-xs text-accent-blue">
              {SECURITY_AUDIT_ARN}
            </div>
          ) : (
            <pre className="m-0 overflow-x-auto rounded-btn border border-border bg-surface-deep p-3 font-mono text-2xs leading-relaxed text-content-secondary">
              {IAM_ONLY_POLICY}
            </pre>
          )}
          <div className="mt-2 flex items-center gap-3 text-xs text-content-dim">
            <button type="button" onClick={copyPolicy}
              className="bg-transparent p-0 text-accent-blue transition-opacity hover:opacity-60">
              {regions.length > 0 ? 'Copy policy ARN' : 'Copy policy'}
            </button>
            {copied && <span className="text-safe">Copied</span>}
          </div>
          <p className="mt-3 text-xs leading-relaxed text-content-dim">
            {regions.length > 0
              ? 'Reading resources in the selected regions needs read access across those services, not just IAM. '
              : ''}
            Its trust policy must allow MayaTrail&apos;s account to assume it. Use a separate role from your
            emulation role, so it can be reviewed and revoked on its own.
          </p>
        </div>
      </form>
    </section>
  )
}
