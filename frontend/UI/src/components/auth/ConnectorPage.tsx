import { useState } from 'react'
import { Navigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import mayatrailLogo from '@/assets/mayatrail-logo.png'

const SAMPLE_POLICY = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MayaTrailSimulationAccess",
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

export function ConnectorPage() {
  const [searchParams] = useSearchParams()
  const {
    user, initializing, verifyConnector, activateDemo,
    loading, error, clearError, logout,
  } = useAuth()

  const [roleArn, setRoleArn] = useState('')
  const [localError, setLocalError] = useState('')
  const [verifying, setVerifying] = useState(false)
  const [demoSuccess, setDemoSuccess] = useState(false)

  const isUpgrade = searchParams.get('upgrade') === '1'

  // Wait for the AuthContext to finish hydrating user state from the
  // server before evaluating any redirect conditions. Without this
  // guard, stale JWT claims could cause incorrect redirects.
  if (initializing) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-surface-deep">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-accent-blue border-t-transparent" />
      </div>
    )
  }

  // Auth guard — unauthenticated visitors must log in first.
  if (!user) return <Navigate to="/login" replace />

  // Already verified via AWS connector — nothing to do here.
  if (user.isVerified) return <Navigate to="/" replace />

  // Active (non-expired) demo users should go to the dashboard (unless upgrading).
  // Expired demo users must stay here so they can connect AWS.
  const isDemoExpired = user.isDemo && user.demoExpiresAt && new Date(user.demoExpiresAt) < new Date()
  if (user.isDemo && !isUpgrade && !isDemoExpired) return <Navigate to="/" replace />

  const handleDemo = async () => {
    clearError()
    setLocalError('')
    try {
      await activateDemo()
      setDemoSuccess(true)
    } catch {
      // error surfaced via context
    }
  }

  // After successful demo activation, redirect to the dashboard.
  // Kept separate from the catch-free try above so the Navigate
  // renders in a clean render cycle (no side effects during render).
  if (demoSuccess) return <Navigate to="/" replace />

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    clearError()
    setLocalError('')

    const trimmed = roleArn.trim()
    if (!trimmed) {
      setLocalError('Please enter a Role ARN')
      return
    }

    setVerifying(true)
    try {
      await verifyConnector({ role_arn: trimmed })
      // verifyConnector already calls refreshUser and updates context,
      // so on the next render user.isVerified will be true and the
      // guard above will redirect to /.
    } catch {
      // error is set in context
    } finally {
      setVerifying(false)
    }
  }

  const displayError = localError || error

  // Hide demo option when upgrading or when the user already used it.
  const showDemoOption = !isUpgrade && !user.demoUsed

  return (
    <div className="min-h-screen flex items-center justify-center overflow-x-hidden bg-surface-deep text-content-primary font-display relative">
      {/* Background effects */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage:
              'linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)',
            backgroundSize: '60px 60px',
            maskImage: 'radial-gradient(ellipse at center, black 30%, transparent 70%)',
            WebkitMaskImage: 'radial-gradient(ellipse at center, black 30%, transparent 70%)',
          }}
        />
        <div className="absolute w-[500px] h-[500px] rounded-full blur-[120px] opacity-[0.08] bg-accent-blue -top-[150px] -right-[100px]" />
        <div className="absolute w-[400px] h-[400px] rounded-full blur-[120px] opacity-[0.08] bg-danger -bottom-[100px] -left-[80px]" />
      </div>

      {/* Content */}
      <div className="relative z-[1] flex gap-8 items-start p-6 max-w-[1060px] w-full">

        {/* Left — Connector Card */}
        <div className="bg-surface-card border border-border rounded-card px-9 py-10 w-[480px] shrink-0 relative overflow-hidden">
          {/* Top accent */}
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-accent-blue via-accent-cyan to-green" />

          {/* Header */}
          <div className="mb-8">
            <div className="flex items-center gap-2.5 mb-2">
              <img
                src={mayatrailLogo}
                alt="MayaTrail"
                className="w-9 h-9 rounded-lg object-cover"
              />
              <span className="font-display text-2xl font-extrabold text-content-primary tracking-[-0.5px]">MayaTrail</span>
            </div>
            <p className="font-mono text-[11px] text-content-dim tracking-[1.5px] uppercase">
              {isUpgrade ? 'Upgrade Your Account' : 'Connect Your Cloud'}
            </p>
          </div>

          {/* Demo Expired Banner — only when the demo has genuinely expired */}
          {isUpgrade && isDemoExpired && (
            <div className="mb-6 bg-[#ff8c00]/[0.08] border border-[#ff8c00]/30 rounded-lg px-4 py-4 flex items-start gap-3
              animate-[fadeSlideIn_0.3s_ease-out]">
              <div className="w-10 h-10 rounded-full bg-[#ff8c00]/[0.15] border border-[#ff8c00]/20 flex items-center justify-center text-lg shrink-0">
                ⏱️
              </div>
              <div>
                <p className="text-sm font-bold text-[#ff8c00] mb-1">Demo Session Expired</p>
                <p className="text-xs text-content-secondary leading-relaxed">
                  Your 5-minute demo sandbox has ended. Connect your AWS account to continue using MayaTrail with full access.
                </p>
              </div>
            </div>
          )}

          {/* Demo option — hidden in upgrade mode or if already used */}
          {showDemoOption && (
            <>
              <div className="mb-6">
                <p className="text-sm text-content-secondary mb-3">
                  Not ready to connect your AWS account? Try our sandbox environment first.
                </p>
                <button
                  type="button"
                  onClick={handleDemo}
                  disabled={loading}
                  className="w-full bg-transparent border border-[rgba(255,255,255,0.15)] rounded-btn py-3 text-content-primary font-body text-[13px] font-medium
                    cursor-pointer transition-all hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active
                    flex items-center justify-center gap-2.5 disabled:opacity-70"
                >
                  <span className="text-lg">🧪</span>
                  Try Demo Mode
                </button>
              </div>

              {/* Divider */}
              <div className="flex items-center gap-4 my-6">
                <div className="flex-1 h-px bg-border" />
                <span className="font-mono text-[10px] text-content-dim tracking-[2px]">OR CONNECT AWS</span>
                <div className="flex-1 h-px bg-border" />
              </div>
            </>
          )}

          {/* IAM Role form */}
          <form onSubmit={handleSubmit} className="flex flex-col gap-5">
            <div className="flex flex-col gap-1.5">
              <label className="font-mono text-[10px] tracking-[1px] text-content-dim uppercase">
                IAM Role ARN
              </label>
              <div className="relative">
                <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-sm text-content-dim pointer-events-none">
                  🔑
                </span>
                <input
                  type="text"
                  value={roleArn}
                  onChange={(e) => setRoleArn(e.target.value)}
                  placeholder="arn:aws:iam::123456789012:role/MayaTrailRole"
                  className="w-full bg-surface-elevated border border-border rounded-lg py-3 pl-[42px] pr-3.5
                    text-content-primary font-mono text-[13px] outline-none
                    transition-all focus:border-accent-blue/40 focus:shadow-[0_0_0_3px_rgba(0,180,216,0.08)]
                    placeholder:text-content-dim"
                />
              </div>
            </div>

            {/* Processing indicator */}
            {verifying && (
              <div className="flex items-center gap-3 py-2">
                <div className="w-4 h-4 border-2 border-accent-blue/30 border-t-accent-blue rounded-full animate-spin" />
                <span className="font-mono text-[11px] text-accent-blue">
                  Verifying IAM role via STS AssumeRole...
                </span>
              </div>
            )}

            {/* Error */}
            {displayError && !verifying && (
              <div className="font-mono text-[11px] text-danger bg-danger/[0.08] border border-danger/20 rounded-lg px-3.5 py-2.5">
                {displayError}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || verifying}
              className="w-full bg-accent-blue border-none rounded-btn py-3.5
                text-white font-display text-sm font-bold cursor-pointer
                transition-all hover:-translate-y-[2px] hover:shadow-[0_8px_40px_rgba(0,180,216,0.35)]
                active:translate-y-0 disabled:opacity-70 disabled:cursor-not-allowed disabled:transform-none
                flex items-center justify-center gap-2"
            >
              <span className={verifying ? 'opacity-50' : ''}>Verify & Connect</span>
              {verifying && <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
            </button>
          </form>

          {/* Footer */}
          <div className="mt-6 pt-5 border-t border-border flex items-center justify-between">
            {isUpgrade ? (
              <>
                <button
                  type="button"
                  onClick={() => window.history.back()}
                  className="font-mono text-[11px] text-content-dim no-underline hover:text-content-primary
                    transition-colors cursor-pointer bg-transparent border-none p-0"
                >
                  ← Back to Profile
                </button>
                <div className="flex items-center gap-2">
                  <a
                    href="mailto:admin@mayatrail.tech?subject=MayaTrail%20IAM%20Role%20Setup%20Help"
                    className="font-mono text-[11px] text-accent-blue no-underline hover:text-content-primary transition-colors
                      border border-accent-blue/30 rounded-btn px-4 py-2 hover:bg-accent-blue/[0.08]"
                  >
                    Ask Support
                  </a>
                  <button
                    type="button"
                    onClick={logout}
                    className="font-mono text-[11px] text-content-dim no-underline hover:text-content-primary transition-colors
                      border border-border rounded-btn px-4 py-2 hover:bg-surface-elevated
                      cursor-pointer bg-transparent"
                  >
                    Sign out
                  </button>
                </div>
              </>
            ) : (
              <>
                <span className="text-xs text-content-dim">Need help setting up the role?</span>
                <div className="flex items-center gap-2">
                  <a
                    href="mailto:admin@mayatrail.tech?subject=MayaTrail%20IAM%20Role%20Setup%20Help"
                    className="font-mono text-[11px] text-accent-blue no-underline hover:text-content-primary transition-colors
                      border border-accent-blue/30 rounded-btn px-4 py-2 hover:bg-accent-blue/[0.08]"
                  >
                    Ask Support
                  </a>
                  <button
                    type="button"
                    onClick={logout}
                    className="font-mono text-[11px] text-content-dim no-underline hover:text-content-primary transition-colors
                      border border-border rounded-btn px-4 py-2 hover:bg-surface-elevated
                      cursor-pointer bg-transparent"
                  >
                    Sign out
                  </button>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Right — Sample Policy with explanations */}
        <div className="bg-surface-card border border-border rounded-card flex-1 relative overflow-hidden flex flex-col max-h-[680px]">
          {/* Top accent */}
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-accent-cyan to-transparent" />

          {/* Header */}
          <div className="px-6 pt-6 pb-4 border-b border-border shrink-0">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-base">📋</span>
              <span className="font-display text-sm font-bold text-content-primary">Required IAM Policy</span>
            </div>
            <p className="text-xs text-content-secondary leading-relaxed">
              MayaTrail's Pulumi engine deploys isolated simulation infrastructure in your account.
              The policy below grants only the permissions needed for deployment and emulation —
              here's why each group is required.
            </p>
          </div>

          {/* Scrollable content */}
          <div className="overflow-y-auto flex-1 px-6 py-4 flex flex-col gap-5">

            {/* S3 permissions */}
            <PolicyGroup
              icon="🪣"
              title="S3 — Simulation Storage"
              actions={['s3:CreateBucket', 's3:DeleteBucket', 's3:PutObject', 's3:GetObject', 's3:DeleteObject', 's3:ListBucket']}
              reason="Pulumi creates S3 buckets as target infrastructure for emulations like ransomware (S3 initial access, KMS re-encryption). Buckets and objects are created, populated, and torn down per simulation run."
            />

            {/* IAM permissions */}
            <PolicyGroup
              icon="👤"
              title="IAM — Identity Simulation"
              actions={['iam:CreateRole', 'iam:DeleteRole', 'iam:AttachRolePolicy', 'iam:DetachRolePolicy', 'iam:PutRolePolicy', 'iam:DeleteRolePolicy', 'iam:CreateUser', 'iam:DeleteUser', 'iam:CreateAccessKey', 'iam:DeleteAccessKey', 'iam:ListAccessKeys']}
              reason="Emulations test IAM privilege escalation and policy manipulation. Pulumi provisions short-lived IAM users and roles to simulate real-world attacker behaviour like policy attachment and access key theft."
            />

            {/* STS permissions */}
            <PolicyGroup
              icon="🔐"
              title="STS — Role Assumption"
              actions={['sts:AssumeRole', 'sts:GetCallerIdentity']}
              reason="STS is used to verify this connector (AssumeRole) and for emulations that test cross-account role chaining and eventual consistency exploitation."
            />

            {/* KMS permissions */}
            <PolicyGroup
              icon="🔑"
              title="KMS — Encryption Simulation"
              actions={['kms:CreateKey', 'kms:ScheduleKeyDeletion', 'kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey']}
              reason="KMS ransomware emulations create encryption keys, re-encrypt S3 objects under attacker-controlled keys, then schedule key deletion — simulating real cloud ransomware techniques."
            />

            {/* Raw policy */}
            <div className="mt-2 pt-4 border-t border-border">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs">📄</span>
                <span className="font-mono text-[10px] text-content-dim tracking-wider uppercase">Full Policy JSON</span>
              </div>
              <pre className="font-mono text-[11px] leading-[1.7] text-accent-cyan whitespace-pre bg-surface-deep rounded-lg p-4 border border-border">
                {SAMPLE_POLICY}
              </pre>
            </div>
          </div>

          {/* Footer */}
          <div className="px-6 py-3 border-t border-border shrink-0">
            <p className="font-mono text-[10px] text-content-dim leading-relaxed">
              All resources are created in an isolated Pulumi stack and destroyed after each run.
              The role must trust MayaTrail's AWS account to assume it.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

function PolicyGroup({ icon, title, actions, reason }: {
  icon: string
  title: string
  actions: string[]
  reason: string
}) {
  return (
    <div className="bg-surface-elevated/50 border border-border rounded-lg p-4">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-base">{icon}</span>
        <span className="font-display text-[13px] font-bold text-content-primary">{title}</span>
      </div>
      <p className="text-xs text-content-secondary leading-relaxed mb-3">{reason}</p>
      <div className="flex flex-wrap gap-1.5">
        {actions.map((action) => (
          <span
            key={action}
            className="font-mono text-[10px] text-accent-cyan bg-accent-cyan/[0.08] border border-accent-cyan/20 rounded px-2 py-0.5"
          >
            {action}
          </span>
        ))}
      </div>
    </div>
  )
}
