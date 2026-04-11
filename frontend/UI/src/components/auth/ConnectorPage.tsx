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

  if (initializing) {
    return (
      <div
        className="flex h-screen w-full items-center justify-center"
        style={{ backgroundColor: '#07080a' }}
      >
        <div
          className="animate-spin"
          style={{
            width: '28px',
            height: '28px',
            border: '2px solid rgba(255,255,255,0.08)',
            borderTopColor: '#55b3ff',
            borderRadius: '50%',
          }}
        />
      </div>
    )
  }

  if (!user) return <Navigate to="/login" replace />
  if (user.isVerified) return <Navigate to="/" replace />

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
    } catch {
      // error is set in context
    } finally {
      setVerifying(false)
    }
  }

  const displayError = localError || error
  const showDemoOption = !isUpgrade && !user.demoUsed

  return (
    <div
      className="min-h-screen flex items-center justify-center overflow-x-hidden relative"
      style={{ backgroundColor: '#07080a', color: '#f9f9f9', fontFamily: 'Inter, system-ui, sans-serif' }}
    >
      {/* Background — grid matching LoginPage */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage:
              'linear-gradient(rgba(255,255,255,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.04) 1px, transparent 1px)',
            backgroundSize: '60px 60px',
            maskImage: 'radial-gradient(ellipse at center, black 60%, transparent 90%)',
            WebkitMaskImage: 'radial-gradient(ellipse at center, black 60%, transparent 90%)',
          }}
        />
        <div
          className="absolute w-[700px] h-[700px] rounded-full -top-[200px] -right-[150px]"
          style={{ background: 'radial-gradient(circle, rgba(85,179,255,0.05) 0%, transparent 70%)' }}
        />
        <div
          className="absolute w-[600px] h-[600px] rounded-full -bottom-[150px] -left-[100px]"
          style={{ background: 'radial-gradient(circle, rgba(255,99,99,0.04) 0%, transparent 70%)' }}
        />
      </div>

      {/* Content — clamp-based widths matching LoginPage scaling */}
      <div
        className="relative z-[1] flex gap-6 items-start p-8"
        style={{ width: 'min(1300px, 92vw)' }}
      >
        {/* Left — Connector Card */}
        <div
          className="shrink-0 relative overflow-hidden"
          style={{
            width: 'clamp(440px, 38vw, 560px)',
            backgroundColor: '#101111',
            border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: '16px',
            boxShadow: 'rgb(27, 28, 30) 0px 0px 0px 1px, rgb(7, 8, 10) 0px 0px 0px 1px inset',
            padding: '36px 32px 32px',
          }}
        >
          {/* Top accent hairline */}
          <div
            className="absolute top-0 left-0 right-0"
            style={{ height: '1px', background: 'linear-gradient(90deg, transparent, #55b3ff 40%, transparent)' }}
          />

          {/* Header */}
          <div className="mb-8">
            <div className="flex items-center gap-2.5 mb-3">
              <img src={mayatrailLogo} alt="MayaTrail" className="w-8 h-8 rounded-lg object-cover" />
              <span style={{ fontSize: '20px', fontWeight: 600, letterSpacing: '-0.3px', color: '#f9f9f9' }}>
                MayaTrail
              </span>
            </div>
            <p style={{ fontSize: '11px', fontFamily: 'Geist Mono, monospace', color: '#6a6b6c', letterSpacing: '1.5px', textTransform: 'uppercase' }}>
              {isUpgrade ? 'Upgrade Your Account' : 'Connect Your Cloud'}
            </p>
          </div>

          {/* Demo expired banner */}
          {isUpgrade && isDemoExpired && (
            <div
              className="mb-6 flex items-start gap-3 animate-fadeSlideIn"
              style={{
                background: 'rgba(255,188,51,0.06)',
                border: '1px solid rgba(255,188,51,0.2)',
                borderRadius: '8px',
                padding: '12px 14px',
              }}
            >
              <svg className="w-4 h-4 mt-0.5 shrink-0" style={{ color: '#ffbc33' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 6v6l4 2" />
              </svg>
              <div>
                <p style={{ fontSize: '13px', fontWeight: 600, color: '#ffbc33', marginBottom: '4px' }}>Demo Session Expired</p>
                <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.5 }}>
                  Your demo sandbox has ended. Connect your AWS account to continue with full access.
                </p>
              </div>
            </div>
          )}

          {/* Demo option */}
          {showDemoOption && (
            <>
              <div className="mb-6">
                <p style={{ fontSize: '13px', color: '#9c9c9d', marginBottom: '12px', lineHeight: 1.6 }}>
                  Not ready to connect your AWS account? Try the sandbox environment first.
                </p>
                <button
                  type="button"
                  onClick={handleDemo}
                  disabled={loading}
                  style={{
                    width: '100%',
                    padding: '11px 0',
                    background: 'transparent',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    color: '#f9f9f9',
                    fontSize: '13px',
                    fontWeight: 500,
                    fontFamily: 'Inter, system-ui, sans-serif',
                    letterSpacing: '0.2px',
                    cursor: loading ? 'not-allowed' : 'pointer',
                    opacity: loading ? 0.5 : 1,
                    transition: 'opacity 0.15s, border-color 0.15s',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                  }}
                  onMouseEnter={(e) => { if (!loading) e.currentTarget.style.opacity = '0.6' }}
                  onMouseLeave={(e) => { if (!loading) e.currentTarget.style.opacity = '1' }}
                >
                  <svg className="w-4 h-4" style={{ color: '#55b3ff' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15M14.25 3.104c.251.023.501.05.75.082M19.8 15l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23-.607L5 14.5m14.8.5-1.976.994a11.54 11.54 0 01-8.048.33L5 14.5m0 0l-.149 1.494" />
                  </svg>
                  Try Demo Mode
                </button>
              </div>

              <div className="flex items-center gap-4 my-6">
                <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.06)' }} />
                <span style={{ fontSize: '10px', fontFamily: 'Geist Mono, monospace', color: '#434345', letterSpacing: '2px', textTransform: 'uppercase' }}>
                  or connect aws
                </span>
                <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.06)' }} />
              </div>
            </>
          )}

          {/* IAM Role form */}
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <label style={{ fontSize: '11px', fontWeight: 500, color: '#9c9c9d', letterSpacing: '0.3px' }}>
                IAM Role ARN
              </label>
              <input
                type="text"
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                placeholder="arn:aws:iam::123456789012:role/MayaTrailRole"
                style={{
                  width: '100%',
                  background: '#07080a',
                  border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: '8px',
                  padding: '10px 14px',
                  color: '#f9f9f9',
                  fontSize: '13px',
                  fontWeight: 500,
                  fontFamily: 'Geist Mono, monospace',
                  letterSpacing: '0.2px',
                  outline: 'none',
                  boxSizing: 'border-box',
                  transition: 'border-color 0.15s, box-shadow 0.15s',
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = 'rgba(85,179,255,0.4)'
                  e.target.style.boxShadow = 'hsla(202, 100%, 67%, 0.12) 0px 0px 0px 3px'
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(255,255,255,0.08)'
                  e.target.style.boxShadow = 'none'
                }}
              />
            </div>

            {/* Verifying indicator */}
            {verifying && (
              <div className="flex items-center gap-2.5">
                <div
                  className="animate-spin"
                  style={{ width: '14px', height: '14px', border: '2px solid rgba(85,179,255,0.2)', borderTopColor: '#55b3ff', borderRadius: '50%', flexShrink: 0 }}
                />
                <span style={{ fontSize: '12px', fontFamily: 'Geist Mono, monospace', color: '#55b3ff', letterSpacing: '0.2px' }}>
                  Verifying IAM role via STS AssumeRole...
                </span>
              </div>
            )}

            {/* Error */}
            {displayError && !verifying && (
              <div
                style={{
                  fontSize: '12px',
                  fontFamily: 'Geist Mono, monospace',
                  color: '#FF6363',
                  background: 'rgba(255,99,99,0.06)',
                  border: '1px solid rgba(255,99,99,0.15)',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  letterSpacing: '0.2px',
                }}
              >
                {displayError}
              </div>
            )}

            {/* Primary CTA — pill shape per design system */}
            <button
              type="submit"
              disabled={loading || verifying}
              style={{
                width: '100%',
                padding: '11px 0',
                background: 'hsla(0, 0%, 100%, 0.815)',
                color: '#18191a',
                border: 'none',
                borderRadius: '86px',
                fontSize: '14px',
                fontWeight: 600,
                letterSpacing: '0.3px',
                cursor: loading || verifying ? 'not-allowed' : 'pointer',
                opacity: loading || verifying ? 0.5 : 1,
                transition: 'opacity 0.15s',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                boxShadow: 'rgba(255,255,255,0.05) 0px 1px 0px 0px inset, rgba(255,255,255,0.25) 0px 0px 0px 1px, rgba(0,0,0,0.2) 0px -1px 0px 0px inset',
              }}
              onMouseEnter={(e) => { if (!loading && !verifying) e.currentTarget.style.opacity = '0.6' }}
              onMouseLeave={(e) => { if (!loading && !verifying) e.currentTarget.style.opacity = '1' }}
            >
              <span>Verify &amp; Connect</span>
              {verifying && (
                <div
                  className="animate-spin"
                  style={{ width: '14px', height: '14px', border: '2px solid rgba(24,25,26,0.3)', borderTopColor: '#18191a', borderRadius: '50%' }}
                />
              )}
            </button>
          </form>

          {/* Footer */}
          <div
            className="mt-6 pt-5 flex items-center justify-between"
            style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
          >
            {isUpgrade ? (
              <>
                <button
                  type="button"
                  onClick={() => window.history.back()}
                  style={ghostBtnStyle}
                  onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
                  onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
                >
                  Back to Profile
                </button>
                <div className="flex items-center gap-2">
                  <SupportLink />
                  <SignOutButton onClick={logout} />
                </div>
              </>
            ) : (
              <>
                <span style={{ fontSize: '12px', color: '#6a6b6c' }}>Need help setting up the role?</span>
                <div className="flex items-center gap-2">
                  <SupportLink />
                  <SignOutButton onClick={logout} />
                </div>
              </>
            )}
          </div>
        </div>

        {/* Right — Required IAM Policy panel */}
        <div
          className="flex-1 relative overflow-hidden flex flex-col"
          style={{
            backgroundColor: '#101111',
            border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: '16px',
            boxShadow: 'rgb(27, 28, 30) 0px 0px 0px 1px, rgb(7, 8, 10) 0px 0px 0px 1px inset',
            maxHeight: '80vh',
          }}
        >
          {/* Top accent hairline */}
          <div
            className="absolute top-0 left-0 right-0"
            style={{ height: '1px', background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.12) 40%, transparent)' }}
          />

          {/* Panel header */}
          <div
            className="px-6 pt-6 pb-4 shrink-0"
            style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
          >
            <div className="flex items-center gap-2 mb-2">
              <svg className="w-4 h-4 shrink-0" style={{ color: '#9c9c9d' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z" />
              </svg>
              <span style={{ fontSize: '13px', fontWeight: 600, color: '#f9f9f9' }}>Required IAM Policy</span>
            </div>
            <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.6 }}>
              MayaTrail's Pulumi engine deploys isolated simulation infrastructure in your account.
              The policy below grants only the permissions needed — here's why each group is required.
            </p>
          </div>

          {/* Scrollable content */}
          <div className="overflow-y-auto flex-1 px-6 py-4 flex flex-col gap-4">
            <PolicyGroup
              title="S3 — Simulation Storage"
              accent="#55b3ff"
              actions={['s3:CreateBucket', 's3:DeleteBucket', 's3:PutObject', 's3:GetObject', 's3:DeleteObject', 's3:ListBucket']}
              reason="Pulumi creates S3 buckets as target infrastructure for emulations like ransomware initial access and KMS re-encryption. Buckets and objects are created and torn down per simulation run."
            />
            <PolicyGroup
              title="IAM — Identity Simulation"
              accent="#5fc992"
              actions={['iam:CreateRole', 'iam:DeleteRole', 'iam:AttachRolePolicy', 'iam:DetachRolePolicy', 'iam:PutRolePolicy', 'iam:DeleteRolePolicy', 'iam:CreateUser', 'iam:DeleteUser', 'iam:CreateAccessKey', 'iam:DeleteAccessKey', 'iam:ListAccessKeys']}
              reason="Emulations test IAM privilege escalation and policy manipulation. Short-lived IAM users and roles are provisioned to simulate attacker behavior like policy attachment and access key theft."
            />
            <PolicyGroup
              title="STS — Role Assumption"
              accent="#ffbc33"
              actions={['sts:AssumeRole', 'sts:GetCallerIdentity']}
              reason="STS is used to verify this connector and for emulations that test cross-account role chaining and eventual consistency exploitation."
            />
            <PolicyGroup
              title="KMS — Encryption Simulation"
              accent="#FF6363"
              actions={['kms:CreateKey', 'kms:ScheduleKeyDeletion', 'kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey']}
              reason="KMS ransomware emulations create encryption keys, re-encrypt S3 objects under attacker-controlled keys, then schedule key deletion — simulating real cloud ransomware techniques."
            />

            {/* Full policy JSON */}
            <div className="pt-4" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
              <p style={{ fontSize: '10px', fontFamily: 'Geist Mono, monospace', color: '#6a6b6c', letterSpacing: '1px', textTransform: 'uppercase', marginBottom: '8px' }}>
                Full Policy JSON
              </p>
              <pre
                style={{
                  fontFamily: 'Geist Mono, monospace',
                  fontSize: '11px',
                  lineHeight: 1.7,
                  color: '#55b3ff',
                  whiteSpace: 'pre',
                  background: '#07080a',
                  borderRadius: '8px',
                  padding: '16px',
                  border: '1px solid rgba(255,255,255,0.06)',
                  overflowX: 'auto',
                }}
              >
                {SAMPLE_POLICY}
              </pre>
            </div>
          </div>

          {/* Panel footer */}
          <div
            className="px-6 py-3 shrink-0"
            style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
          >
            <p style={{ fontSize: '11px', fontFamily: 'Geist Mono, monospace', color: '#434345', lineHeight: 1.6 }}>
              All resources are created in an isolated Pulumi stack and destroyed after each run.
              The role must trust MayaTrail's AWS account to assume it.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Policy Group ── */
function PolicyGroup({
  title, accent, actions, reason,
}: {
  title: string
  accent: string
  actions: string[]
  reason: string
}) {
  return (
    <div
      style={{
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '10px',
        padding: '14px 16px',
      }}
    >
      <div className="flex items-center gap-2 mb-2">
        <div
          className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{ background: accent, boxShadow: `0 0 6px ${accent}66` }}
        />
        <span style={{ fontSize: '13px', fontWeight: 600, color: '#f9f9f9' }}>{title}</span>
      </div>
      <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.6, marginBottom: '10px' }}>{reason}</p>
      <div className="flex flex-wrap gap-1.5">
        {actions.map((action) => (
          <span
            key={action}
            style={{
              fontFamily: 'Geist Mono, monospace',
              fontSize: '10px',
              color: accent,
              background: `${accent}12`,
              border: `1px solid ${accent}25`,
              borderRadius: '4px',
              padding: '2px 7px',
              letterSpacing: '0.2px',
            }}
          >
            {action}
          </span>
        ))}
      </div>
    </div>
  )
}

/* ── Shared small components ── */

const ghostBtnStyle: React.CSSProperties = {
  fontSize: '11px',
  fontFamily: 'Geist Mono, monospace',
  color: '#6a6b6c',
  background: 'none',
  border: 'none',
  cursor: 'pointer',
  padding: 0,
  letterSpacing: '0.2px',
  transition: 'opacity 0.15s',
}

const outlineBtnStyle: React.CSSProperties = {
  fontSize: '11px',
  fontFamily: 'Geist Mono, monospace',
  color: '#9c9c9d',
  background: 'transparent',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '6px',
  padding: '6px 14px',
  cursor: 'pointer',
  letterSpacing: '0.2px',
  transition: 'opacity 0.15s',
}

function SupportLink() {
  return (
    <a
      href="mailto:admin@mayatrail.tech?subject=MayaTrail%20IAM%20Role%20Setup%20Help"
      style={{
        ...outlineBtnStyle,
        color: '#55b3ff',
        borderColor: 'rgba(85,179,255,0.2)',
        textDecoration: 'none',
        display: 'inline-block',
      }}
      onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
      onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
    >
      Ask Support
    </a>
  )
}

function SignOutButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={outlineBtnStyle}
      onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
      onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
    >
      Sign out
    </button>
  )
}
