import { useState, useEffect, useRef } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import mayatrailLogo from '@/assets/mayatrail-logo.png'
// AuthBackground animations removed — SaaS layout uses clean static design

/*
 * Full IAM policy JSON displayed in the right-panel reference section.
 * Kept as a constant so the connector card stays purely presentational.
 */
const SAMPLE_POLICY = `{
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

/** ARN format: arn:aws:iam::<12-digit-account-id>:role/<role-name> */
const ARN_RE = /^arn:aws:iam::\d{12}:role\/.+$/

export function ConnectorPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const {
    user, initializing, verifyConnector, activateDemo,
    loading, error, clearError, logout,
  } = useAuth()

  const [roleArn, setRoleArn] = useState('')
  const [localError, setLocalError] = useState('')
  const [verifying, setVerifying] = useState(false)
  const [demoSuccess, setDemoSuccess] = useState(false)
  const [verifySuccess, setVerifySuccess] = useState(false)
  const [provider, setProvider] = useState<ProviderId>('aws')
  const [providerOpen, setProviderOpen] = useState(false)
  const providerRef = useRef<HTMLDivElement>(null)

  /* Close dropdown when clicking outside. */
  useEffect(() => {
    if (!providerOpen) return
    const handler = (e: MouseEvent) => {
      if (providerRef.current && !providerRef.current.contains(e.target as Node)) {
        setProviderOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [providerOpen])

  const isUpgrade = searchParams.get('upgrade') === '1'

  /*
   * Auto-navigate after a brief success banner so the user sees confirmation
   * before the redirect. Hook must be declared unconditionally (Rules of Hooks).
   */
  useEffect(() => {
    if (!verifySuccess) return
    const t = setTimeout(() => navigate('/', { replace: true }), 1500)
    return () => clearTimeout(t)
  }, [verifySuccess, navigate])

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

  const isDemoExpired =
    user.isDemo && user.demoExpiresAt && new Date(user.demoExpiresAt) < new Date()
  if (user.isDemo && !isUpgrade && !isDemoExpired) return <Navigate to="/" replace />

  const handleDemo = async () => {
    clearError()
    setLocalError('')
    try {
      await activateDemo()
      setDemoSuccess(true)
    } catch {
      // error surfaced via AuthContext
    }
  }

  if (demoSuccess) return <Navigate to="/" replace />

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
      await verifyConnector({ role_arn: trimmed })
      setVerifySuccess(true)
    } catch {
      // error surfaced via AuthContext
    } finally {
      setVerifying(false)
    }
  }

  const displayError = localError || error
  const showDemoOption = !isUpgrade && !user.demoUsed

  return (
    <div
      className="min-h-screen flex items-center justify-center py-10 px-4"
      style={{ backgroundColor: '#07080a', color: '#f9f9f9', fontFamily: 'Inter, system-ui, sans-serif' }}
    >
      {/* Static subtle grid — matches LoginPage */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage:
            'linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />

      {/* ── Outer card — same double-ring shadow as LoginPage ── */}
      <div
        className="relative z-10 w-full flex flex-col"
        style={{
          maxWidth: 'min(1100px, 94vw)',
          border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: '16px',
          overflow: 'hidden',
          boxShadow: 'rgb(7,8,10) 0px 0px 0px 1px inset, rgba(0,0,0,0.45) 0px 24px 48px',
        }}
      >
        {/* ── Brand bar ── */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '14px 28px',
            background: '#101111',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
            flexShrink: 0,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <img src={mayatrailLogo} alt="MayaTrail" style={{ width: '22px', height: '22px', borderRadius: '5px', objectFit: 'cover' }} />
            <span style={{ fontSize: '14px', fontWeight: 600, color: '#f9f9f9', letterSpacing: '-0.1px' }}>MayaTrail</span>
            <span style={{ fontSize: '12px', color: '#434345', marginLeft: '2px' }}>/ Cloud Connectors</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <SupportLink />
            <SignOutButton onClick={logout} />
          </div>
        </div>

        {/* ── Content area ── */}
        <div style={{ background: '#07080a', padding: '28px' }}>
        {/* Wrapper: position:relative so right column can use top:0;bottom:0 to match left column height */}
        <div className="w-full hidden lg:block" style={{ position: 'relative' }}>

          {/* ── Left column — normal flow, sizes the wrapper ── */}
          <div className="flex flex-col gap-4" style={{ width: '34%' }}>

            {/* Page heading */}
            <div>
              <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: '6px' }}>
                <h1
                  style={{
                    fontSize: '26px',
                    fontWeight: 600,
                    color: '#f9f9f9',
                    letterSpacing: '-0.4px',
                    lineHeight: 1.2,
                  }}
                >
                  {isUpgrade ? 'Upgrade Account' : 'Cloud Connectors'}
                </h1>
                {showDemoOption && (
                  <button
                    type="button"
                    onClick={handleDemo}
                    disabled={loading}
                    style={{
                      fontSize: '12px',
                      fontWeight: 500,
                      color: '#FF6363',
                      background: 'none',
                      border: 'none',
                      cursor: loading ? 'not-allowed' : 'pointer',
                      opacity: loading ? 0.4 : 1,
                      padding: 0,
                      letterSpacing: '0.2px',
                      transition: 'opacity 0.15s',
                      flexShrink: 0,
                      marginBottom: '2px',
                    }}
                    onMouseEnter={(e) => { if (!loading) e.currentTarget.style.opacity = '0.6' }}
                    onMouseLeave={(e) => { if (!loading) e.currentTarget.style.opacity = '1' }}
                  >
                    Try demo mode →
                  </button>
                )}
              </div>
              <p style={{ fontSize: '13px', color: '#6a6b6c', lineHeight: 1.6, letterSpacing: '0.2px' }}>
                {isUpgrade
                  ? 'Link your AWS account to unlock full APT emulation access.'
                  : 'Connect your AWS account to start running APT emulations.'}
              </p>
            </div>

            {/* Main connector card */}
            <div
              style={{
                backgroundColor: '#101111',
                border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: '12px',
                boxShadow: 'rgb(27, 28, 30) 0px 0px 0px 1px, rgb(7, 8, 10) 0px 0px 0px 1px inset',
                padding: '20px',
                position: 'relative',
                overflow: 'hidden',
              }}
            >
              {/* Card header — compact divider only */}
              <div style={{ marginBottom: '18px', paddingBottom: '14px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <p style={{ fontSize: '11px', fontWeight: 500, color: '#6a6b6c', letterSpacing: '0.3px', textTransform: 'uppercase' }}>
                  IAM Role Setup
                </p>
              </div>

              {/* Demo-expired upgrade banner */}
              {isUpgrade && isDemoExpired && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    background: 'rgba(255,188,51,0.06)',
                    border: '1px solid rgba(255,188,51,0.2)',
                    borderRadius: '8px',
                    padding: '12px 14px',
                    marginBottom: '20px',
                  }}
                >
                  <ClockIcon color="#ffbc33" />
                  <div>
                    <p style={{ fontSize: '13px', fontWeight: 600, color: '#ffbc33', marginBottom: '4px' }}>
                      Demo Session Expired
                    </p>
                    <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.5 }}>
                      Your demo sandbox has ended. Connect your AWS account to continue with full access.
                    </p>
                  </div>
                </div>
              )}

              {/* IAM role verified success banner */}
              {verifySuccess && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    background: 'rgba(95,201,146,0.06)',
                    border: '1px solid rgba(95,201,146,0.2)',
                    borderRadius: '8px',
                    padding: '12px 14px',
                    marginBottom: '20px',
                  }}
                >
                  <CheckCircleIcon color="#5fc992" />
                  <div>
                    <p style={{ fontSize: '13px', fontWeight: 600, color: '#5fc992', marginBottom: '4px' }}>
                      IAM Role Verified
                    </p>
                    <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.5 }}>
                      Your AWS account is connected. Redirecting to dashboard...
                    </p>
                  </div>
                </div>
              )}

              {/* Cloud provider dropdown */}
              <div ref={providerRef} style={{ marginBottom: '16px', position: 'relative' }}>
                <label
                  style={{
                    display: 'block',
                    fontSize: '11px',
                    fontWeight: 500,
                    color: '#9c9c9d',
                    marginBottom: '6px',
                    letterSpacing: '0.3px',
                    textTransform: 'uppercase',
                  }}
                >
                  Provider
                </label>
                <button
                  type="button"
                  onClick={() => setProviderOpen((o) => !o)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    width: '100%',
                  padding: '9px 10px',
                    background: '#1b1c1e',
                    border: '1px solid rgba(255,255,255,0.06)',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'border-color 0.15s',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'rgba(85,179,255,0.3)')}
                  onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)')}
                >
                  <ProviderIcon id={provider} />
                  <span
                    style={{
                      flex: 1,
                      textAlign: 'left',
                      fontSize: '13px',
                      fontWeight: 500,
                      color: '#f9f9f9',
                      letterSpacing: '0.2px',
                    }}
                  >
                    {PROVIDERS.find((p) => p.id === provider)?.label}
                  </span>
                  <span
                    style={{
                      display: 'inline-block',
                      transform: providerOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: 'transform 0.2s',
                    }}
                  >
                    <ChevronDownIcon />
                  </span>
                </button>

                {/* Dropdown list */}
                {providerOpen && (
                  <div
                    style={{
                      position: 'absolute',
                      top: 'calc(100% + 4px)',
                      left: 0,
                      right: 0,
                      background: '#101111',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                      boxShadow: 'rgb(27, 28, 30) 0px 0px 0px 1px, rgba(0,0,0,0.5) 0px 8px 24px',
                      zIndex: 50,
                      overflow: 'hidden',
                    }}
                  >
                    {PROVIDERS.map((p) => (
                      <button
                        key={p.id}
                        type="button"
                        onClick={() => { setProvider(p.id); setProviderOpen(false) }}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                          width: '100%',
                          padding: '9px 12px',
                          background: provider === p.id ? 'rgba(255,255,255,0.04)' : 'transparent',
                          border: 'none',
                          borderBottom: '1px solid rgba(255,255,255,0.04)',
                          cursor: 'pointer',
                          transition: 'background 0.1s',
                          textAlign: 'left',
                        }}
                        onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255,255,255,0.06)')}
                        onMouseLeave={(e) => (e.currentTarget.style.background = provider === p.id ? 'rgba(255,255,255,0.04)' : 'transparent')}
                      >
                        <ProviderIcon id={p.id} />
                        <span style={{ fontSize: '13px', fontWeight: 500, color: '#f9f9f9', letterSpacing: '0.2px' }}>
                          {p.label}
                        </span>
                        {provider === p.id && (
                          <span style={{ marginLeft: 'auto', color: '#5fc992', display: 'flex' }}>
                            <CheckmarkIcon />
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* IAM Role ARN form */}
              <form onSubmit={handleSubmit}>
                {/* ARN label row */}
                <div style={{ marginBottom: '6px', display: 'flex', justifyContent: 'space-between' }}>
                  <label
                    htmlFor="arn-input"
                    style={{ fontSize: '11px', fontWeight: 500, color: '#9c9c9d', letterSpacing: '0.3px', textTransform: 'uppercase' }}
                  >
                    IAM Role ARN
                  </label>
                  <span style={{ fontSize: '11px', color: '#434345', letterSpacing: '0.2px' }}>Required</span>
                </div>

                {/* ARN input with leading link icon */}
                <div style={{ position: 'relative', marginBottom: '16px' }}>
                  <div
                    style={{
                      position: 'absolute',
                      top: 0,
                      bottom: 0,
                      left: 0,
                      paddingLeft: '10px',
                      display: 'flex',
                      alignItems: 'center',
                      pointerEvents: 'none',
                    }}
                  >
                    <LinkIcon />
                  </div>
                  <input
                    id="arn-input"
                    type="text"
                    value={roleArn}
                    onChange={(e) => {
                      setRoleArn(e.target.value)
                      setLocalError('')
                    }}
                    placeholder="arn:aws:iam::123456789012:role/MayaTrailRole"
                    className="auth-input-solid"
                    style={{
                      display: 'block',
                      width: '100%',
                      paddingTop: '10px',
                      paddingBottom: '10px',
                      paddingLeft: '32px',
                      paddingRight: '12px',
                      background: '#1b1c1e',
                      border: '1px solid rgba(255,255,255,0.06)',
                      borderRadius: '6px',
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
                      e.target.style.borderColor = 'rgba(255,255,255,0.06)'
                      e.target.style.boxShadow = 'none'
                    }}
                  />
                </div>

                {/* Verifying progress */}
                {verifying && (
                  <div
                    className="flex items-center gap-2.5"
                    style={{ marginBottom: '12px' }}
                  >
                    <div
                      className="animate-spin"
                      style={{
                        width: '14px',
                        height: '14px',
                        border: '2px solid rgba(85,179,255,0.2)',
                        borderTopColor: '#55b3ff',
                        borderRadius: '50%',
                        flexShrink: 0,
                      }}
                    />
                    <span
                      style={{
                        fontSize: '12px',
                        fontFamily: 'Geist Mono, monospace',
                        color: '#55b3ff',
                        letterSpacing: '0.2px',
                      }}
                    >
                      Verifying IAM role via STS AssumeRole...
                    </span>
                  </div>
                )}

                {/* Validation / API error */}
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
                      marginBottom: '12px',
                    }}
                  >
                    {displayError}
                  </div>
                )}

                {/* Divider + primary CTA */}
                <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '16px' }}>
                  <button
                    type="submit"
                    disabled={loading || verifying}
                    style={{
                      width: '100%',
                      padding: '10px 20px',
                      background: '#FF6363',
                      color: '#fff',
                      border: 'none',
                      borderRadius: '6px',
                      fontSize: '13px',
                      fontWeight: 600,
                      letterSpacing: '0.3px',
                      cursor: loading || verifying ? 'not-allowed' : 'pointer',
                      opacity: loading || verifying ? 0.5 : 1,
                      transition: 'opacity 0.15s',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '8px',
                      boxShadow: 'rgba(255,99,99,0.25) 0px 1px 0px 0px inset, rgba(0,0,0,0.2) 0px -1px 0px 0px inset',
                    }}
                    onMouseEnter={(e) => { if (!loading && !verifying) e.currentTarget.style.opacity = '0.8' }}
                    onMouseLeave={(e) => { if (!loading && !verifying) e.currentTarget.style.opacity = '1' }}
                  >
                    <ShieldCheckIcon />
                    Verify &amp; Connect
                  </button>
                </div>
              </form>

              {/* Card footer — back link for upgrade flow */}
              {isUpgrade && (
                <div style={{ marginTop: '16px', paddingTop: '14px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                  <button
                    type="button"
                    onClick={() => window.history.back()}
                    style={ghostBtnStyle}
                    onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
                    onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
                  >
                    ← Back to Profile
                  </button>
                </div>
              )}
              {!isUpgrade && (
                <p style={{ marginTop: '14px', fontSize: '12px', color: '#434345', letterSpacing: '0.2px' }}>
                  Need help? <a href="mailto:admin@mayatrail.tech?subject=MayaTrail%20IAM%20Role%20Setup%20Help" style={{ color: '#55b3ff', textDecoration: 'none' }}>Contact support</a>
                </p>
              )}
            </div>

            {/* Helper note — inline, no card */}
            <p style={{ fontSize: '11px', color: '#434345', lineHeight: 1.6, letterSpacing: '0.2px', paddingLeft: '2px' }}>
              Ensure the IAM role has an inline policy matching the permissions listed on the right.
            </p>
          </div>

          {/* ── Right column (8 cols) — hidden on mobile ── */}
          <div
            className="flex flex-col"
            style={{
              position: 'absolute',
              top: 0,
              bottom: 0,
              left: 'calc(34% + 24px)',
              right: 0,
              backgroundColor: '#101111',
              border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: '12px',
              boxShadow: 'rgb(27, 28, 30) 0px 0px 0px 1px, rgb(7, 8, 10) 0px 0px 0px 1px inset',
              overflow: 'hidden',
            }}
          >
            {/* Panel header */}
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid rgba(255,255,255,0.06)',
                flexShrink: 0,
              }}
            >
              <div className="flex items-center gap-2" style={{ marginBottom: '4px' }}>
                <PolicyIcon />
                <span style={{ fontSize: '15px', fontWeight: 600, color: '#f9f9f9', letterSpacing: '0.2px' }}>
                  Required IAM Policy
                </span>
              </div>
              <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.6, letterSpacing: '0.2px' }}>
                Minimum permissions required for MayaTrail to function.
              </p>
            </div>

            {/* Scrollable policy list */}
            <div
              className="flex-1 overflow-y-auto flex flex-col gap-4"
              style={{ padding: '16px 20px', minHeight: 0 }}
            >
              <PolicyGroup
                title="S3 — Emulation Target Storage"
                accent="#55b3ff"
                actions={[
                  's3:CreateBucket', 's3:DeleteBucket', 's3:PutObject',
                  's3:GetObject', 's3:DeleteObject', 's3:ListBucket',
                ]}
                reason="Pulumi provisions S3 buckets as target infrastructure for emulations. Buckets and objects are created and torn down per emulation run."
              />
              <PolicyGroup
                title="IAM — Identity Emulation"
                accent="#5fc992"
                actions={[
                  'iam:CreateRole', 'iam:DeleteRole', 'iam:AttachRolePolicy',
                  'iam:DetachRolePolicy', 'iam:PutRolePolicy', 'iam:DeleteRolePolicy',
                  'iam:CreateUser', 'iam:DeleteUser', 'iam:CreateAccessKey',
                  'iam:DeleteAccessKey', 'iam:ListAccessKeys',
                ]}
                reason="Emulations test IAM privilege escalation and policy manipulation. Short-lived IAM users and roles are provisioned to simulate attacker behavior like policy attachment and access key theft."
              />
              <PolicyGroup
                title="STS — Role Assumption"
                accent="#ffbc33"
                actions={['sts:AssumeRole', 'sts:GetCallerIdentity']}
                reason="STS is used to verify this connector and for emulations that test cross-account role chaining and eventual consistency exploitation."
              />
              <PolicyGroup
                title="KMS — Encryption Emulation"
                accent="#FF6363"
                actions={[
                  'kms:CreateKey', 'kms:ScheduleKeyDeletion',
                  'kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey',
                ]}
                reason="KMS ransomware emulations create encryption keys, re-encrypt S3 objects under attacker-controlled keys, then schedule key deletion — simulating real cloud ransomware techniques."
              />

              {/* Full policy JSON reference */}
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '16px' }}>
                <p
                  style={{
                    fontSize: '10px',
                    fontFamily: 'Geist Mono, monospace',
                    color: '#6a6b6c',
                    letterSpacing: '1px',
                    textTransform: 'uppercase',
                    marginBottom: '8px',
                  }}
                >
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
                    margin: 0,
                  }}
                >
                  {SAMPLE_POLICY}
                </pre>
              </div>
            </div>

            {/* Panel footer */}
            <div
              style={{
                padding: '10px 20px',
                borderTop: '1px solid rgba(255,255,255,0.06)',
                flexShrink: 0,
              }}
            >
              <p
                style={{
                  fontSize: '11px',
                  fontFamily: 'Geist Mono, monospace',
                  color: '#434345',
                  lineHeight: 1.6,
                }}
              >
                All resources are created in an isolated Pulumi stack and destroyed after each run.
                The role must trust MayaTrail's AWS account to assume it.
              </p>
            </div>
          </div>

        </div>
        </div>{/* end content area */}
      </div>{/* end outer card */}
    </div>
  )
}

/* ── Policy Group ── */

/**
 * Renders a single IAM permission group with a colored dot accent, a reason
 * paragraph, and a row of action chips styled in the group's accent color.
 */
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
      className="relative overflow-hidden group shrink-0"
      style={{
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '10px',
        padding: '14px 16px',
        transition: 'border-color 0.3s',
        cursor: 'default',
      }}
      onMouseEnter={(e) => { e.currentTarget.style.borderColor = `${accent}33` }}
      onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)' }}
    >
      {/* Accent hairline revealed on hover */}
      <div
        className="absolute top-0 left-0 right-0 opacity-0 group-hover:opacity-100"
        style={{ height: '1px', background: `linear-gradient(90deg, transparent, ${accent}, transparent)`, transition: 'opacity 0.3s' }}
      />
      {/* Corner ambient glow revealed on hover */}
      <div
        className="absolute -top-8 -right-8 w-28 h-28 rounded-full opacity-0 group-hover:opacity-100 pointer-events-none"
        style={{ background: `${accent}18`, filter: 'blur(24px)', transition: 'opacity 0.3s' }}
      />

      <div className="relative">
        <div className="flex items-center gap-2" style={{ marginBottom: '8px' }}>
          <div
            style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: accent,
              boxShadow: `0 0 6px ${accent}66`,
              flexShrink: 0,
            }}
          />
          <span style={{ fontSize: '13px', fontWeight: 600, color: '#f9f9f9' }}>{title}</span>
        </div>
        <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.6, marginBottom: '10px' }}>
          {reason}
        </p>
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
    </div>
  )
}

/* ── Shared button components ── */

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

/* ── Inline SVG icon components ── */


function ClockIcon({ color }: { color: string }) {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth="1.5"
      style={{ marginTop: '1px', flexShrink: 0 }}
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 6v6l4 2" />
    </svg>
  )
}

function CheckCircleIcon({ color }: { color: string }) {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 20 20"
      fill={color}
      style={{ marginTop: '1px', flexShrink: 0 }}
    >
      <path
        fillRule="evenodd"
        d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
        clipRule="evenodd"
      />
    </svg>
  )
}


function ChevronDownIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6a6b6c" strokeWidth="2">
      <path d="M6 9l6 6 6-6" />
    </svg>
  )
}

function LinkIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6a6b6c" strokeWidth="1.5">
      <path d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
    </svg>
  )
}

function ShieldCheckIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  )
}


function PolicyIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#9c9c9d" strokeWidth="1.5">
      <path d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z" />
    </svg>
  )
}

function CheckmarkIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
      <path d="M5 13l4 4L19 7" />
    </svg>
  )
}

/* ── Provider dropdown data ── */

type ProviderId = 'aws' | 'azure' | 'gcp'

const PROVIDERS: { id: ProviderId; label: string }[] = [
  { id: 'aws', label: 'Amazon Web Services' },
  { id: 'azure', label: 'Microsoft Azure' },
  { id: 'gcp', label: 'Google Cloud' },
]

/** Renders the colored icon swatch for a given cloud provider. */
function ProviderIcon({ id }: { id: ProviderId }) {
  if (id === 'aws') {
    return (
      <div
        style={{
          width: '24px', height: '24px', borderRadius: '4px',
          background: 'rgba(255,153,0,0.15)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}
      >
        <svg width="14" height="14" viewBox="0 0 48 48" fill="none">
          <path
            d="M14.6 27.6c0 .5.1.9.2 1.2.2.4.4.7.7 1 .1.1.1.3 0 .4l-.9.6c-.1.1-.3.1-.4-.1-.2-.3-.4-.6-.6-.9-.4-.7-.6-1.5-.6-2.4 0-1.7.7-3.1 2-4.3l.8 1c.1.2.1.3 0 .4-.8.7-1.2 1.8-1.2 3.1zm4.9-1.1c-.1.1-.2.1-.3 0l-.7-.7c-.1-.1-.1-.3.1-.4.9-.7 2-1 3.1-1 1.8 0 3.3.7 4.4 1.9l-.8.8c-.1.1-.3.1-.4 0-.8-.8-1.8-1.3-3.2-1.3-.8 0-1.6.2-2.2.7zm3.8 5.4c-.8 0-1.5-.1-2.1-.4l-.3 1.2c.8.3 1.6.5 2.4.5 1.5 0 2.8-.5 3.8-1.3l-.7-1c-.1-.1-.3-.1-.4 0-.6.6-1.5 1-2.7 1z"
            fill="#FF9900"
          />
          <path d="M34.2 28.5c-.9.7-2.3 1-3.6 1-1.8 0-3.4-.7-4.6-1.8l.8-.9c.2-.2.3-.2.5 0 .9.8 2.1 1.3 3.3 1.3.9 0 1.8-.2 2.5-.7l1.1 1.1z" fill="#FF9900" />
        </svg>
      </div>
    )
  }

  if (id === 'azure') {
    return (
      <div
        style={{
          width: '24px', height: '24px', borderRadius: '4px',
          background: 'rgba(0,120,212,0.15)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
          <path d="M13.05 2L7 13.5l4.5 1.5L6 22h12L13.05 2z" fill="#0078D4" />
          <path d="M7 13.5L2 22h4l5.5-8.5L7 13.5z" fill="#50a0ef" />
        </svg>
      </div>
    )
  }

  /* gcp */
  return (
    <div
      style={{
        width: '24px', height: '24px', borderRadius: '4px',
        background: 'rgba(66,133,244,0.12)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0,
      }}
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
        <path d="M12 6.5l2.5 2.5H9.5L12 6.5z" fill="#EA4335" />
        <path d="M16 9l2 2h-3.5L16 9z" fill="#FBBC04" />
        <path d="M17.5 17.5H6.5L4 11h16l-2.5 6.5z" fill="#4285F4" />
        <path d="M6.5 17.5l-2-2.5h15l-2 2.5H6.5z" fill="#34A853" />
      </svg>
    </div>
  )
}
