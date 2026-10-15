import { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import mayatrailLogo from '@/assets/mayatrail-logo.svg'
import { forgotPassword, resetPassword } from '@/services/auth.service'
// AuthBackground animations removed — SaaS layout uses clean static design

/*
 * Google Identity Services type declaration.
 * GIS is loaded via <script> in index.html — no npm package needed.
 * Declaring a minimal API subset keeps TypeScript happy.
 */
declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: {
            client_id: string
            callback: (response: { credential: string }) => void
            auto_select?: boolean
          }) => void
          renderButton: (
            parent: HTMLElement,
            options: {
              theme?: string
              size?: string
              width?: number
              text?: string
              shape?: string
              logo_alignment?: string
            }
          ) => void
        }
      }
    }
  }
}

type AuthTab = 'signin' | 'signup'

/**
 * Brand-panel step track: how a MayaTrail run works, left to right. Each step
 * takes one design-system accent; the connecting line blends between them.
 */
const STEPS = [
  { title: 'Deploy a lab', desc: 'Spin up a vulnerable stack in your test account.', color: '#FF6363', ring: 'rgba(255,99,99,0.5)' },
  { title: 'Run the attack', desc: 'Replay a real adversary technique, step by step.', color: '#55b3ff', ring: 'rgba(85,179,255,0.5)' },
  { title: 'Check detections', desc: 'See which of your detections fired, and which missed.', color: '#5fc992', ring: 'rgba(95,201,146,0.5)' },
  { title: 'Close the gap', desc: 'Apply the guardrail and the playbook, then tear it down.', color: '#ffbc33', ring: 'rgba(255,188,51,0.5)' },
] as const

const COVERAGE = ['AWS', 'Azure', 'GCP', 'Kubernetes'] as const

/** Root login page — full-screen two-column split layout. */
export function LoginPage() {
  const [activeTab, setActiveTab] = useState<AuthTab>('signin')
  const [signupSuccess, setSignupSuccess] = useState(false)
  const [formVisible, setFormVisible] = useState(true)
  const { clearError, googleSSO } = useAuth()
  const navigate = useNavigate()

  /** Fades out the form, swaps the active tab, then fades back in. */
  const switchTab = (tab: AuthTab) => {
    if (tab === activeTab) return
    setFormVisible(false)
    setTimeout(() => {
      clearError()
      setSignupSuccess(false)
      setActiveTab(tab)
      setFormVisible(true)
    }, 120)
  }

  /** Called when sign-up OTP verification completes successfully. */
  const handleSignupComplete = () => {
    setSignupSuccess(true)
    setTimeout(() => {
      setActiveTab('signin')
      setSignupSuccess(false)
    }, 4000)
  }

  /*
   * googleSSO handler lives in the parent so GoogleSignInButton is mounted
   * once — lifting it out of SignInForm/SignUpForm prevents GIS from tearing
   * down and re-initialising its iframe on every tab switch.
   */
  const handleGoogleCredential = useCallback(async (idToken: string) => {
    clearError()
    try {
      await googleSSO(idToken)
      // Every signed-in user lands on the dashboard, connected or not. An
      // unconnected user ("Explorer") browses read-only and connects from their
      // profile when they choose to; the backend refuses every mutating request
      // meanwhile. See product-design-requirements/connector-access-design/.
      navigate('/', { replace: true })
    } catch {
      // error is set in AuthContext
    }
  }, [googleSSO, clearError, navigate])

  return (
    <div
      className="min-h-screen flex items-center justify-center"
      style={{ backgroundColor: '#07080a', fontFamily: 'Inter, system-ui, sans-serif' }}
    >
      {/* Subtle grid — static, no animation */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          backgroundImage:
            'linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />

      {/* ── Full-screen two-column split ── */}
      <div className="relative z-10 flex w-full" style={{ minHeight: '100vh' }}>
        {/* ── Left: Brand panel (hidden on small screens) ── */}
        <div
          className="hidden lg:flex flex-col justify-between"
          style={{
            width: '62%',
            background: 'radial-gradient(120% 90% at 15% 0%, #0c0e12 0%, #07080a 55%)',
            borderRight: '1px solid rgba(255,255,255,0.06)',
            padding: '56px 64px 56px 80px',
            flexShrink: 0,
          }}
        >
          {/* Logo + wordmark (top-left) */}
          <div className="flex items-center" style={{ gap: '9px' }}>
            <img src={mayatrailLogo} alt="MayaTrail" style={{ width: '27px', height: '27px', objectFit: 'contain' }} />
            <span style={{ fontSize: '16px', fontWeight: 600, letterSpacing: '0.3px', color: '#f9f9f9' }}>MayaTrail</span>
          </div>

          {/* Middle group: headline, step track, coverage — vertically centred */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '38px' }}>
            <div>
              <h1 style={{ fontSize: '38px', fontWeight: 600, lineHeight: 1.12, letterSpacing: '-0.3px', color: '#f9f9f9', maxWidth: '760px' }}>
                Attack your cloud <span style={{ color: '#9a9b9c' }}>before someone else does.</span>
              </h1>
              <p style={{ fontSize: '15px', color: '#9a9b9c', lineHeight: 1.6, letterSpacing: '0.2px', marginTop: '16px', maxWidth: '480px' }}>
                Provision intentionally vulnerable AWS environments, run real adversary emulations, and prove your detections actually fire.
              </p>
            </div>

            {/* Step track: how a run works, left to right */}
            <div style={{ position: 'relative', display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '18px', maxWidth: '780px' }}>
              <div
                style={{
                  position: 'absolute', left: '14px', right: '14px', top: '14px', height: '1px',
                  background: 'linear-gradient(90deg, rgba(255,99,99,0.6), rgba(85,179,255,0.5), rgba(95,201,146,0.5), rgba(255,188,51,0.5))',
                }}
              />
              {STEPS.map((s, i) => (
                <div key={s.title} style={{ position: 'relative' }}>
                  <div
                    style={{
                      position: 'relative', width: '29px', height: '29px', borderRadius: '50%',
                      display: 'grid', placeItems: 'center', fontSize: '12px', fontWeight: 600,
                      background: '#07080a', color: s.color, border: `1px solid ${s.ring}`,
                    }}
                  >
                    {i + 1}
                  </div>
                  <p style={{ marginTop: '14px', fontSize: '14px', fontWeight: 600, color: '#f9f9f9' }}>{s.title}</p>
                  <p style={{ marginTop: '5px', fontSize: '12.5px', color: '#9a9b9c', lineHeight: 1.45 }}>{s.desc}</p>
                </div>
              ))}
            </div>

            {/* Coverage */}
            <div className="flex items-center flex-wrap" style={{ gap: '20px' }}>
              <span style={{ fontSize: '11px', letterSpacing: '0.7px', textTransform: 'uppercase', color: '#6a6b6c' }}>Coverage</span>
              <div className="flex flex-wrap" style={{ gap: '8px' }}>
                {COVERAGE.map((c) => (
                  <span key={c} style={{ fontSize: '12px', fontWeight: 600, color: '#f9f9f9', background: '#1b1c1e', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '6px', padding: '5px 10px' }}>{c}</span>
                ))}
              </div>
            </div>
          </div>

          {/* Bottom disclaimer */}
          <p style={{ fontSize: '10px', fontFamily: 'Geist Mono, monospace', color: '#434345', letterSpacing: '0.8px' }}>
            USE ONLY IN ISOLATED TEST ACCOUNTS
          </p>
        </div>

        {/* ── Right: Auth card ── */}
        <div className="flex-1 flex items-center justify-center" style={{ background: '#07080a', padding: '40px 24px' }}>
          <div
            style={{
              width: '100%', maxWidth: '400px', background: '#101111',
              border: '1px solid rgba(255,255,255,0.06)', borderRadius: '16px',
              boxShadow: 'rgb(27,28,30) 0 0 0 1px, rgb(7,8,10) 0 0 0 1px inset',
              padding: '32px 30px',
            }}
          >
            {/* Heading */}
            <h2 style={{ fontSize: '22px', fontWeight: 600, letterSpacing: '-0.1px', color: '#f9f9f9' }}>
              {activeTab === 'signin' ? 'Welcome back' : 'Create your account'}
            </h2>
            <p style={{ marginTop: '6px', fontSize: '13.5px', color: '#9a9b9c', marginBottom: '22px' }}>
              {activeTab === 'signin' ? 'Sign in to your MayaTrail workspace.' : 'Start emulating in minutes.'}
            </p>

            {/* Tabs */}
            <div style={{ display: 'flex', gap: '4px', background: '#07080a', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '10px', padding: '4px', marginBottom: '22px' }}>
              {(['signin', 'signup'] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => switchTab(t)}
                  style={{
                    flex: 1, border: 0, cursor: 'pointer', fontFamily: 'inherit', fontWeight: 600, fontSize: '13px',
                    padding: '8px 0', borderRadius: '7px',
                    background: activeTab === t ? '#101111' : 'transparent',
                    color: activeTab === t ? '#f9f9f9' : '#9a9b9c',
                    boxShadow: activeTab === t ? 'rgb(27,28,30) 0 0 0 1px, rgb(7,8,10) 0 0 0 1px inset' : 'none',
                  }}
                >
                  {t === 'signin' ? 'Sign in' : 'Create account'}
                </button>
              ))}
            </div>

            {/* Google — prominent, above the divider */}
            <GoogleSignInButton onCredential={handleGoogleCredential} />

            {/* OR divider */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: '18px 0', color: '#6a6b6c', fontSize: '11.5px', letterSpacing: '0.6px' }}>
              <span style={{ height: '1px', flex: 1, background: 'rgba(255,255,255,0.06)' }} />
              OR
              <span style={{ height: '1px', flex: 1, background: 'rgba(255,255,255,0.06)' }} />
            </div>

            {/* Account verified banner */}
            {signupSuccess && (
              <div
                className="mb-5 flex items-start gap-3"
                style={{ background: 'rgba(95,201,146,0.07)', border: '1px solid rgba(95,201,146,0.18)', borderRadius: '8px', padding: '11px 14px' }}
              >
                <svg style={{ width: '14px', height: '14px', color: '#5fc992', marginTop: '1px', flexShrink: 0 }} viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <div>
                  <p style={{ fontSize: '13px', fontWeight: 600, color: '#5fc992', marginBottom: '2px' }}>Account Verified</p>
                  <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.5 }}>Your email has been verified. Sign in below.</p>
                </div>
              </div>
            )}

            {/* Form */}
            <div style={{ opacity: formVisible ? 1 : 0, transition: 'opacity 0.12s ease' }}>
              {activeTab === 'signin'
                ? <SignInForm />
                : <SignUpForm onComplete={handleSignupComplete} />
              }
            </div>

            {/* Switch tab link */}
            <div style={{ marginTop: '18px', textAlign: 'center', color: '#9a9b9c', fontSize: '13px' }}>
              {activeTab === 'signin'
                ? <>No account? <button type="button" onClick={() => switchTab('signup')} style={{ color: '#55b3ff', fontWeight: 500, background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', padding: 0, fontFamily: 'inherit' }}>Create one &rarr;</button></>
                : <>Already have one? <button type="button" onClick={() => switchTab('signin')} style={{ color: '#55b3ff', fontWeight: 500, background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', padding: 0, fontFamily: 'inherit' }}>Sign in &rarr;</button></>
              }
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Sign In Form ── */

/** Sign-in form with error-state input styling and inline forgot-password flow. */
function SignInForm() {
  const navigate = useNavigate()
  const { login, loading, error, clearError } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const [forgotStep, setForgotStep] = useState<'none' | 'email' | 'otp' | 'done'>('none')
  const [resetEmail, setResetEmail] = useState('')

  /** True when AuthContext holds a credential error from a failed login attempt. */
  const hasError = Boolean(error)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    clearError()
    try {
      await login({ username, password })
      // Every signed-in user lands on the dashboard, connected or not. An
      // unconnected user ("Explorer") browses read-only and connects from their
      // profile when they choose to; the backend refuses every mutating request
      // meanwhile. See product-design-requirements/connector-access-design/.
      navigate('/', { replace: true })
    } catch {
      // error is set in AuthContext
    }
  }

  if (forgotStep === 'email') {
    return (
      <ForgotPasswordForm
        onCodeSent={(email) => { setResetEmail(email); setForgotStep('otp') }}
        onBack={() => { clearError(); setForgotStep('none') }}
      />
    )
  }

  if (forgotStep === 'otp') {
    return (
      <ResetPasswordOTPForm
        email={resetEmail}
        onSuccess={() => setForgotStep('done')}
        onBack={() => { clearError(); setForgotStep('email') }}
      />
    )
  }

  return (
    <form className="flex flex-col gap-4" onSubmit={handleSubmit}>

      {/* Password reset success banner */}
      {forgotStep === 'done' && (
        <div
          className="flex items-start gap-3 animate-fadeSlideIn"
          style={{
            background: 'rgba(95, 201, 146, 0.08)',
            border: '1px solid rgba(95, 201, 146, 0.2)',
            borderRadius: '8px',
            padding: '12px 14px',
          }}
        >
          <svg className="w-4 h-4 mt-0.5 shrink-0" style={{ color: '#5fc992' }} viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
          </svg>
          <div>
            <p style={{ fontSize: '13px', fontWeight: 600, color: '#5fc992', marginBottom: '2px' }}>Password Reset</p>
            <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.5 }}>
              Your password has been changed. Sign in with your new credentials.
            </p>
          </div>
        </div>
      )}

      {/* Username / Email */}
      <FormField label="Username or Email">
        <div className="relative">
          <input
            type="text"
            value={username}
            onChange={(e) => { setUsername(e.target.value); if (hasError) clearError() }}
            placeholder="you@company.com"
            required
            autoComplete="username"
            className={`auth-input-solid${hasError ? ' auth-input-error' : ''}`}
            style={hasError ? { ...inputStyle, paddingRight: '36px' } : inputStyle}
          />
          {hasError && <InputErrorIcon />}
        </div>
      </FormField>

      {/* Password — label row includes "Forgot password?" link */}
      <div className="flex flex-col gap-1.5">
        <div className="flex items-center justify-between">
          <label style={{ fontSize: '11px', fontWeight: 500, color: '#9c9c9d', letterSpacing: '0.3px' }}>
            Password
          </label>
          <button
            type="button"
            onClick={() => { clearError(); setForgotStep('email') }}
            style={{ fontSize: '12px', fontFamily: 'inherit', fontWeight: 500, color: '#55b3ff', letterSpacing: '0.2px', background: 'none', border: 'none', cursor: 'pointer', padding: 0, transition: 'opacity 0.15s' }}
            onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
            onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
          >
            Forgot password?
          </button>
        </div>
        <PasswordInput
          value={password}
          onChange={(e) => { setPassword(e.target.value); if (hasError) clearError() }}
          placeholder="Enter your password"
          autoComplete="current-password"
          hasError={hasError}
        />
      </div>

      {/* Remember me */}
      <div className="flex items-center">
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" style={{ accentColor: '#55b3ff', width: '13px', height: '13px' }} />
          <span style={{ fontSize: '12px', color: '#9c9c9d' }}>Remember me</span>
        </label>
      </div>

      {error && <ErrorBanner message={error} />}

      <PrimaryButton type="submit" loading={loading}>
        <span className="flex items-center gap-1">
          Authenticate
          {!loading && (
            <svg style={{ width: '16px', height: '16px' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M5 12h14M12 5l7 7-7 7" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          )}
        </span>
      </PrimaryButton>
    </form>
  )
}

/* ── Forgot Password — Email Form ── */

/** Step 1 of forgot-password: collect the user's email and send a reset code. */
function ForgotPasswordForm({ onCodeSent, onBack }: {
  onCodeSent: (email: string) => void
  onBack: () => void
}) {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await forgotPassword({ email })
      onCodeSent(email)
    } catch (err: any) {
      setError(err.message ?? 'Failed to send reset code.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form className="flex flex-col gap-5" onSubmit={handleSubmit}>
      <div className="text-center">
        <div
          className="w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-3"
          style={{ background: 'rgba(255,99,99,0.08)', border: '1px solid rgba(255,99,99,0.15)' }}
        >
          <svg className="w-5 h-5" style={{ color: '#FF6363' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" />
            <path d="M7 11V7a5 5 0 0110 0v4" />
          </svg>
        </div>
        <p style={{ fontSize: '14px', fontWeight: 600, color: '#f9f9f9', marginBottom: '4px' }}>Reset your password</p>
        <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.5 }}>
          Enter your email and we'll send you a 6-digit reset code.
        </p>
      </div>

      <FormField label="Email Address">
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          required
          autoComplete="email"
          className="auth-input-solid"
          style={inputStyle}
        />
      </FormField>

      {error && <ErrorBanner message={error} />}

      <PrimaryButton type="submit" loading={loading}>Send Reset Code</PrimaryButton>

      <div className="text-center">
        <button
          type="button"
          onClick={onBack}
          style={{ fontSize: '12.5px', fontFamily: 'inherit', color: '#9a9b9c', background: 'none', border: 'none', cursor: 'pointer', padding: 0, transition: 'opacity 0.15s' }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          ← Back to Sign In
        </button>
      </div>
    </form>
  )
}

/* ── Forgot Password — OTP + New Password Form ── */

/** Step 2 of forgot-password: enter the OTP and choose a new password. */
function ResetPasswordOTPForm({ email, onSuccess, onBack }: {
  email: string
  onSuccess: () => void
  onBack: () => void
}) {
  const [digits, setDigits] = useState<string[]>(['', '', '', '', '', ''])
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [resendCooldown, setResendCooldown] = useState(0)
  const [resendMsg, setResendMsg] = useState('')
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])

  useEffect(() => { inputRefs.current[0]?.focus() }, [])

  useEffect(() => {
    if (resendCooldown <= 0) return
    const timer = setInterval(() => setResendCooldown((c) => c - 1), 1000)
    return () => clearInterval(timer)
  }, [resendCooldown])

  const handleDigitChange = useCallback((index: number, value: string) => {
    const digit = value.replace(/\D/g, '').slice(-1)
    setDigits((prev) => {
      const next = [...prev]
      next[index] = digit
      return next
    })
    setError('')
    if (digit && index < 5) inputRefs.current[index + 1]?.focus()
  }, [])

  const handleKeyDown = useCallback((index: number, e: React.KeyboardEvent) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      inputRefs.current[index - 1]?.focus()
    }
  }, [digits])

  const handlePaste = useCallback((e: React.ClipboardEvent) => {
    e.preventDefault()
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    if (!pasted) return
    const newDigits = [...digits]
    for (let i = 0; i < 6; i++) newDigits[i] = pasted[i] ?? ''
    setDigits(newDigits)
    inputRefs.current[Math.min(pasted.length, 5)]?.focus()
  }, [digits])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    const otp = digits.join('')
    if (otp.length !== 6) return

    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters.')
      return
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.')
      return
    }

    setLoading(true)
    try {
      await resetPassword({ email, otp, new_password: newPassword })
      onSuccess()
    } catch (err: any) {
      setError(err.message ?? 'Failed to reset password.')
    } finally {
      setLoading(false)
    }
  }

  const handleResend = async () => {
    if (resendCooldown > 0) return
    setError('')
    setResendMsg('')
    try {
      await forgotPassword({ email })
      setResendMsg('A new reset code has been sent.')
      setResendCooldown(60)
      setDigits(['', '', '', '', '', ''])
      inputRefs.current[0]?.focus()
    } catch {
      setError('Failed to resend code.')
    }
  }

  const isOTPComplete = digits.every((d) => d !== '')
  const maskedEmail = email.replace(/(.{2})(.*)(@.*)/, '$1***$3')

  return (
    <form className="flex flex-col gap-5" onSubmit={handleSubmit}>
      <div className="text-center">
        <div
          className="w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-3"
          style={{ background: 'rgba(255,99,99,0.08)', border: '1px solid rgba(255,99,99,0.15)' }}
        >
          <svg className="w-5 h-5" style={{ color: '#FF6363' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="2" y="4" width="20" height="16" rx="3" />
            <path d="M2 7l10 6 10-6" />
          </svg>
        </div>
        <p style={{ fontSize: '14px', fontWeight: 600, color: '#f9f9f9', marginBottom: '4px' }}>Check your email</p>
        <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.5 }}>
          We sent a 6-digit reset code to{' '}
          <span style={{ fontFamily: 'Geist Mono, monospace', color: '#cecece' }}>{maskedEmail}</span>
        </p>
      </div>

      {/* OTP digit inputs */}
      <div className="flex justify-center gap-2" onPaste={handlePaste}>
        {digits.map((digit, i) => (
          <input
            key={i}
            ref={(el) => { inputRefs.current[i] = el }}
            type="text"
            inputMode="numeric"
            maxLength={1}
            value={digit}
            onChange={(e) => handleDigitChange(i, e.target.value)}
            onKeyDown={(e) => handleKeyDown(i, e)}
            aria-label={`Digit ${i + 1}`}
            style={{
              width: '42px',
              height: '52px',
              textAlign: 'center',
              fontFamily: 'Geist Mono, monospace',
              fontSize: '20px',
              fontWeight: 600,
              borderRadius: '8px',
              border: digit ? '1px solid rgba(255,99,99,0.3)' : '1px solid rgba(255,255,255,0.06)',
              background: '#07080a',
              color: '#f9f9f9',
              outline: 'none',
              boxShadow: digit ? 'rgba(255,99,99,0.08) 0px 0px 0px 3px' : 'none',
              transition: 'border-color 0.15s, box-shadow 0.15s',
            }}
          />
        ))}
      </div>

      <FormField label="New Password">
        <PasswordInput
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          placeholder="Min. 8 characters"
          minLength={8}
          autoComplete="new-password"
        />
      </FormField>

      <FormField label="Confirm New Password">
        <PasswordInput
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          placeholder="Re-enter new password"
          autoComplete="new-password"
        />
      </FormField>

      {error && <ErrorBanner message={error} />}

      {resendMsg && !error && (
        <div
          style={{
            fontSize: '11px',
            fontFamily: 'Geist Mono, monospace',
            color: '#5fc992',
            background: 'rgba(95,201,146,0.06)',
            border: '1px solid rgba(95,201,146,0.2)',
            borderRadius: '6px',
            padding: '8px 12px',
            textAlign: 'center',
          }}
        >
          {resendMsg}
        </div>
      )}

      <PrimaryButton type="submit" loading={loading} disabled={!isOTPComplete || newPassword.length < 8}>
        Reset Password
      </PrimaryButton>

      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={onBack}
          style={{ fontSize: '12.5px', fontFamily: 'inherit', color: '#9a9b9c', background: 'none', border: 'none', cursor: 'pointer', padding: 0, transition: 'opacity 0.15s' }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          ← Back
        </button>
        <button
          type="button"
          onClick={handleResend}
          disabled={resendCooldown > 0 || loading}
          style={{ fontSize: '12.5px', fontFamily: 'inherit', fontWeight: 500, color: resendCooldown > 0 ? '#6a6b6c' : '#55b3ff', background: 'none', border: 'none', cursor: resendCooldown > 0 ? 'not-allowed' : 'pointer', padding: 0, transition: 'opacity 0.15s' }}
          onMouseEnter={(e) => { if (resendCooldown <= 0) e.currentTarget.style.opacity = '0.6' }}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend code'}
        </button>
      </div>

      <p style={{ fontSize: '11.5px', fontFamily: 'inherit', color: '#6a6b6c', textAlign: 'center', letterSpacing: '0.2px' }}>
        Expires in 10 minutes — up to 5 attempts
      </p>
    </form>
  )
}

/* ── Sign Up Form (multi-step: details → OTP → success) ── */

type SignUpStep = 'details' | 'otp'

/** Sign-up flow: collects name, email, password, then OTP verify. */
function SignUpForm({ onComplete }: { onComplete: () => void }) {
  const { signup, verifyOTP, resendOTP, loading, error, clearError } = useAuth()
  const [step, setStep] = useState<SignUpStep>('details')
  const [pendingEmail, setPendingEmail] = useState('')

  const [name, setName] = useState('')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [localError, setLocalError] = useState('')

  const handleDetailsSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    clearError()
    setLocalError('')
    // Keep this a subset of Django's username rule so anything accepted here
    // also passes server-side validation (no frontend-accepts / backend-rejects).
    if (!/^[a-zA-Z0-9_.-]{3,30}$/.test(username)) {
      setLocalError('Username must be 3-30 characters using letters, numbers, and . _ - only (no spaces).')
      return
    }
    if (password !== confirm) {
      setLocalError('Passwords do not match')
      return
    }
    try {
      const res = await signup({ name, username, email, password })
      setPendingEmail(res.email)
      setStep('otp')
    } catch {
      // error is set in AuthContext
    }
  }

  const displayError = localError || error

  if (step === 'otp') {
    return (
      <OTPVerificationForm
        email={pendingEmail}
        loading={loading}
        error={error}
        clearError={clearError}
        verifyOTP={verifyOTP}
        resendOTP={resendOTP}
        onVerified={onComplete}
        onBack={() => { clearError(); setStep('details') }}
      />
    )
  }

  return (
    <form className="flex flex-col gap-4" onSubmit={handleDetailsSubmit}>
      <FormField label="Full Name">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Jane Doe"
          required
          autoComplete="name"
          className="auth-input-solid"
          style={inputStyle}
        />
      </FormField>

      <FormField label="Username">
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="jane_doe"
          required
          maxLength={30}
          autoComplete="username"
          className="auth-input-solid"
          style={inputStyle}
        />
        <p className="mt-1.5 text-[11px] text-content-dim">
          3-30 characters. Letters, numbers, and . _ - only.
        </p>
      </FormField>

      <FormField label="Email">
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          required
          autoComplete="email"
          className="auth-input-solid"
          style={inputStyle}
        />
      </FormField>

      <FormField label="Password">
        <PasswordInput
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Min. 8 characters"
          minLength={8}
          autoComplete="new-password"
        />
      </FormField>

      <FormField label="Confirm Password">
        <PasswordInput
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          placeholder="Re-enter password"
          autoComplete="new-password"
        />
      </FormField>

      {displayError && <ErrorBanner message={displayError} />}

      <PrimaryButton type="submit" loading={loading}>Create Account</PrimaryButton>
    </form>
  )
}

/* ── OTP Verification Form ── */

/** Email OTP verification step used during sign-up. */
function OTPVerificationForm({
  email, loading, error, clearError, verifyOTP, resendOTP, onVerified, onBack,
}: {
  email: string
  loading: boolean
  error: string | null
  clearError: () => void
  verifyOTP: (req: { email: string; otp: string }) => Promise<any>
  resendOTP: (req: { email: string }) => Promise<any>
  onVerified: () => void
  onBack: () => void
}) {
  const [digits, setDigits] = useState<string[]>(['', '', '', '', '', ''])
  const [resendCooldown, setResendCooldown] = useState(0)
  const [resendMsg, setResendMsg] = useState('')
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])

  useEffect(() => { inputRefs.current[0]?.focus() }, [])

  useEffect(() => {
    if (resendCooldown <= 0) return
    const timer = setInterval(() => setResendCooldown((c) => c - 1), 1000)
    return () => clearInterval(timer)
  }, [resendCooldown])

  const handleDigitChange = useCallback((index: number, value: string) => {
    const digit = value.replace(/\D/g, '').slice(-1)
    setDigits((prev) => {
      const next = [...prev]
      next[index] = digit
      return next
    })
    clearError()
    if (digit && index < 5) inputRefs.current[index + 1]?.focus()
  }, [clearError])

  const handleKeyDown = useCallback((index: number, e: React.KeyboardEvent) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      inputRefs.current[index - 1]?.focus()
    }
  }, [digits])

  const handlePaste = useCallback((e: React.ClipboardEvent) => {
    e.preventDefault()
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    if (!pasted) return
    const newDigits = [...digits]
    for (let i = 0; i < 6; i++) newDigits[i] = pasted[i] ?? ''
    setDigits(newDigits)
    inputRefs.current[Math.min(pasted.length, 5)]?.focus()
  }, [digits])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const otp = digits.join('')
    if (otp.length !== 6) return
    try {
      await verifyOTP({ email, otp })
      onVerified()
    } catch {
      // error is set in AuthContext
    }
  }

  const handleResend = async () => {
    if (resendCooldown > 0) return
    clearError()
    setResendMsg('')
    try {
      const res = await resendOTP({ email })
      setResendMsg(res.message)
      setResendCooldown(60)
      setDigits(['', '', '', '', '', ''])
      inputRefs.current[0]?.focus()
    } catch {
      // error is set in AuthContext
    }
  }

  const isComplete = digits.every((d) => d !== '')
  const maskedEmail = email.replace(/(.{2})(.*)(@.*)/, '$1***$3')

  return (
    <form className="flex flex-col gap-5" onSubmit={handleSubmit}>
      <div className="text-center">
        <div
          className="w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-3"
          style={{ background: 'rgba(255,99,99,0.08)', border: '1px solid rgba(255,99,99,0.15)' }}
        >
          <svg className="w-5 h-5" style={{ color: '#FF6363' }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="2" y="4" width="20" height="16" rx="3" />
            <path d="M2 7l10 6 10-6" />
          </svg>
        </div>
        <p style={{ fontSize: '14px', fontWeight: 600, color: '#f9f9f9', marginBottom: '4px' }}>Check your email</p>
        <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.5 }}>
          We sent a 6-digit code to{' '}
          <span style={{ fontFamily: 'Geist Mono, monospace', color: '#cecece' }}>{maskedEmail}</span>
        </p>
      </div>

      <div className="flex justify-center gap-2" onPaste={handlePaste}>
        {digits.map((digit, i) => (
          <input
            key={i}
            ref={(el) => { inputRefs.current[i] = el }}
            type="text"
            inputMode="numeric"
            maxLength={1}
            value={digit}
            onChange={(e) => handleDigitChange(i, e.target.value)}
            onKeyDown={(e) => handleKeyDown(i, e)}
            aria-label={`Digit ${i + 1}`}
            style={{
              width: '42px',
              height: '52px',
              textAlign: 'center',
              fontFamily: 'Geist Mono, monospace',
              fontSize: '20px',
              fontWeight: 600,
              borderRadius: '8px',
              border: digit ? '1px solid rgba(255,99,99,0.3)' : '1px solid rgba(255,255,255,0.06)',
              background: '#07080a',
              color: '#f9f9f9',
              outline: 'none',
              boxShadow: digit ? 'rgba(255,99,99,0.08) 0px 0px 0px 3px' : 'none',
              transition: 'border-color 0.15s, box-shadow 0.15s',
            }}
          />
        ))}
      </div>

      {error && <ErrorBanner message={error} />}

      {resendMsg && !error && (
        <div
          style={{
            fontSize: '11px',
            fontFamily: 'Geist Mono, monospace',
            color: '#5fc992',
            background: 'rgba(95,201,146,0.06)',
            border: '1px solid rgba(95,201,146,0.2)',
            borderRadius: '6px',
            padding: '8px 12px',
            textAlign: 'center',
          }}
        >
          {resendMsg}
        </div>
      )}

      <PrimaryButton type="submit" loading={loading} disabled={!isComplete}>Verify Email</PrimaryButton>

      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={onBack}
          style={{ fontSize: '12.5px', fontFamily: 'inherit', color: '#9a9b9c', background: 'none', border: 'none', cursor: 'pointer', padding: 0, transition: 'opacity 0.15s' }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          Back
        </button>
        <button
          type="button"
          onClick={handleResend}
          disabled={resendCooldown > 0 || loading}
          style={{ fontSize: '12.5px', fontFamily: 'inherit', fontWeight: 500, color: resendCooldown > 0 ? '#6a6b6c' : '#55b3ff', background: 'none', border: 'none', cursor: resendCooldown > 0 ? 'not-allowed' : 'pointer', padding: 0, transition: 'opacity 0.15s' }}
          onMouseEnter={(e) => { if (resendCooldown <= 0) e.currentTarget.style.opacity = '0.6' }}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend code'}
        </button>
      </div>

      <p style={{ fontSize: '11.5px', fontFamily: 'inherit', color: '#6a6b6c', textAlign: 'center', letterSpacing: '0.2px' }}>
        Expires in 10 minutes — up to 5 attempts
      </p>
    </form>
  )
}

/* ── Google Sign-In Button ──
 *
 * Renders a GIS button using renderButton() into a ref div.
 * Polls for the GIS script to load (up to 3 seconds) before initializing.
 * Listens to window resize to re-render the button at the correct width when
 * the card changes size — prevents the Google logo from being clipped on
 * narrow screens. GIS accepts widths between 200px and 400px.
 * Returns null when VITE_GOOGLE_CLIENT_ID is not set.
 */
function GoogleSignInButton({ onCredential }: { onCredential: (idToken: string) => void }) {
  const wrapperRef = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const initializedRef = useRef(false)
  const renderedRef = useRef(false)
  const lastWidthRef = useRef<number>(0)
  const onCredentialRef = useRef(onCredential)
  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined

  useEffect(() => { onCredentialRef.current = onCredential })

  /*
   * Re-render the GIS button only when the window width actually changes.
   *
   * ResizeObserver was the original approach, but it watches ANY dimension
   * change on the wrapper — including the height change caused by GIS loading
   * its iframe. That triggered a clear→re-render which changed the height
   * again, creating an infinite loop (flicker). A plain window "resize"
   * listener fires only when the user resizes the browser window.
   */
  const renderBtn = useCallback(() => {
    if (!containerRef.current || !wrapperRef.current) return
    if (!window.google?.accounts?.id) return
    const width = Math.min(400, Math.max(200, wrapperRef.current.offsetWidth))
    if (width === lastWidthRef.current) return
    lastWidthRef.current = width
    containerRef.current.innerHTML = ''
    window.google.accounts.id.renderButton(containerRef.current, {
      // Light pill with the Google mark, to match the mockup's CTA. GIS renders
      // its own button, so this is as close to the design as Google's theming
      // allows; a fully custom button would require the OAuth code flow.
      theme: 'outline',
      size: 'large',
      width,
      text: 'continue_with',
      shape: 'pill',
      logo_alignment: 'left',
    })
  }, [])

  useEffect(() => {
    if (!clientId || !wrapperRef.current) return

    let attempts = 0
    const MAX_ATTEMPTS = 30
    let pollingDone = false

    const tryInit = () => {
      /*
       * Idempotent, because two things race to call this: the 100ms poll and
       * the script's load event. `pollingDone` only stopped the poll from
       * scheduling the NEXT attempt; an attempt already queued still ran after
       * the load event had rendered the button, cleared the container and drew
       * it again. That second draw is the flicker on this page: the button
       * appears, blanks for a frame, and reappears.
       */
      if (renderedRef.current) return
      if (!containerRef.current || !wrapperRef.current) return
      if (!window.google?.accounts?.id) {
        if (!pollingDone) {
          attempts += 1
          if (attempts < MAX_ATTEMPTS) setTimeout(tryInit, 100)
          else pollingDone = true
        }
        return
      }
      pollingDone = true
      if (!initializedRef.current) {
        window.google.accounts.id.initialize({
          client_id: clientId,
          callback: (response) => onCredentialRef.current(response.credential),
          auto_select: false,
        })
        initializedRef.current = true
      }
      lastWidthRef.current = 0
      renderBtn()
      renderedRef.current = true
    }

    tryInit()

    const gisScript = document.querySelector<HTMLScriptElement>(
      'script[src*="accounts.google.com/gsi/client"]',
    )
    const onScriptLoad = () => tryInit()
    gisScript?.addEventListener('load', onScriptLoad)

    let resizeTimer: ReturnType<typeof setTimeout>
    const handleResize = () => {
      clearTimeout(resizeTimer)
      resizeTimer = setTimeout(renderBtn, 60)
    }
    window.addEventListener('resize', handleResize)

    return () => {
      window.removeEventListener('resize', handleResize)
      gisScript?.removeEventListener('load', onScriptLoad)
      clearTimeout(resizeTimer)
    }
  }, [clientId, renderBtn])

  if (!clientId) return null

  // The GIS button cannot be restyled (it renders in a sandboxed iframe and
  // ignores the pill shape). To match the mockup we draw our own pill and lay
  // the real Google button over it, invisible but still clickable, so the
  // ID-token sign-in flow is unchanged.
  return (
    <div ref={wrapperRef} style={{ position: 'relative', width: '100%', height: '44px' }}>
      <div
        style={{
          position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px',
          background: 'hsla(0,0%,100%,0.815)', color: '#18191a', borderRadius: '86px',
          fontWeight: 600, fontSize: '14px', letterSpacing: '0.2px', pointerEvents: 'none',
          boxShadow: 'rgba(255,255,255,0.1) 0px 1px 0px 0px inset',
        }}
      >
        <svg width="17" height="17" viewBox="0 0 48 48" aria-hidden="true">
          <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9.1 3.6l6.8-6.8C35.9 2.4 30.3 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.2C12.4 13.6 17.7 9.5 24 9.5z" />
          <path fill="#4285F4" d="M46.1 24.6c0-1.6-.1-3.1-.4-4.6H24v9.3h12.4c-.5 2.9-2.1 5.4-4.6 7.1l7.1 5.5C43.3 38 46.1 31.9 46.1 24.6z" />
          <path fill="#FBBC05" d="M10.5 28.6c-.5-1.4-.7-2.9-.7-4.6s.3-3.2.7-4.6l-7.9-6.2C1 16.5 0 20.1 0 24s1 7.5 2.6 10.8l7.9-6.2z" />
          <path fill="#34A853" d="M24 48c6.3 0 11.6-2.1 15.5-5.7l-7.1-5.5c-2 1.3-4.6 2.1-8.4 2.1-6.3 0-11.6-4.1-13.5-9.8l-7.9 6.2C6.5 42.6 14.6 48 24 48z" />
        </svg>
        Continue with Google
      </div>
      <div ref={containerRef} style={{ position: 'absolute', inset: 0, opacity: 0.001, overflow: 'hidden' }} />
    </div>
  )
}

/* ── Shared Components ── */

/** Label + child input wrapper used throughout all form sub-components. */
function FormField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label style={{ fontSize: '11px', fontWeight: 500, color: '#9c9c9d', letterSpacing: '0.3px' }}>
        {label}
      </label>
      {children}
    </div>
  )
}

/** Password input with a show/hide toggle so users can verify what they typed. */
function PasswordInput({
  value, onChange, placeholder, autoComplete, minLength, hasError = false,
}: {
  value: string
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void
  placeholder?: string
  autoComplete?: string
  minLength?: number
  hasError?: boolean
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        required
        minLength={minLength}
        autoComplete={autoComplete}
        className={`auth-input-solid${hasError ? ' auth-input-error' : ''}`}
        style={{ ...inputStyle, paddingRight: '40px' }}
      />
      <button
        type="button"
        onClick={() => setShow((s) => !s)}
        aria-label={show ? 'Hide password' : 'Show password'}
        tabIndex={-1}
        style={{
          position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)',
          background: 'none', border: 'none', cursor: 'pointer', color: '#6a6b6c',
          padding: '2px', display: 'flex', alignItems: 'center', transition: 'color 0.15s',
        }}
        onMouseEnter={(e) => (e.currentTarget.style.color = '#f9f9f9')}
        onMouseLeave={(e) => (e.currentTarget.style.color = '#6a6b6c')}
      >
        {show ? (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" />
            <line x1="1" y1="1" x2="23" y2="23" />
          </svg>
        ) : (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
            <circle cx="12" cy="12" r="3" />
          </svg>
        )}
      </button>
    </div>
  )
}

/** Primary CTA button — solid Raycast Red, rectangular (6px radius), SaaS-style. */
function PrimaryButton({
  children, type = 'button', loading = false, disabled = false,
}: {
  children: React.ReactNode
  type?: 'button' | 'submit'
  loading?: boolean
  disabled?: boolean
}) {
  return (
    <button
      type={type}
      disabled={loading || disabled}
      style={{
        width: '100%',
        padding: '11px 20px',
        background: 'hsla(0,0%,100%,0.815)',
        color: '#18191a',
        border: 'none',
        borderRadius: '86px',
        fontSize: '14px',
        fontWeight: 600,
        letterSpacing: '0.2px',
        cursor: loading || disabled ? 'not-allowed' : 'pointer',
        opacity: loading || disabled ? 0.55 : 1,
        transition: 'background 0.15s, opacity 0.15s',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        boxShadow: 'rgba(255,255,255,0.1) 0px 1px 0px 0px inset',
      }}
      onMouseEnter={(e) => { if (!loading && !disabled) e.currentTarget.style.background = '#fff' }}
      onMouseLeave={(e) => { if (!loading && !disabled) e.currentTarget.style.background = 'hsla(0,0%,100%,0.815)' }}
    >
      <span>{children}</span>
      {loading && (
        <div
          className="animate-spin"
          style={{ width: '13px', height: '13px', border: '2px solid rgba(24,25,26,0.25)', borderTopColor: '#18191a', borderRadius: '50%' }}
        />
      )}
    </button>
  )
}

/** Error banner displayed below form fields on authentication failure. */
function ErrorBanner({ message }: { message: string }) {
  return (
    <div
      style={{
        fontSize: '12px',
        fontFamily: 'inherit',
        color: '#FF6363',
        background: 'rgba(255,99,99,0.06)',
        border: '1px solid rgba(255,99,99,0.15)',
        borderRadius: '6px',
        padding: '8px 12px',
        letterSpacing: '0.2px',
      }}
    >
      {message}
    </div>
  )
}

/** Small circular error icon positioned absolutely inside an input wrapper. */
function InputErrorIcon() {
  return (
    <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none">
      <svg
        style={{ width: '16px', height: '16px', color: '#FF6363' }}
        viewBox="0 0 24 24"
        fill="currentColor"
      >
        <path
          fillRule="evenodd"
          d="M2.25 12c0-5.385 4.365-9.75 9.75-9.75s9.75 4.365 9.75 9.75-4.365 9.75-9.75 9.75S2.25 17.385 2.25 12zM12 8.25a.75.75 0 01.75.75v3.75a.75.75 0 01-1.5 0V9a.75.75 0 01.75-.75zm0 8.25a.75.75 0 100-1.5.75.75 0 000 1.5z"
          clipRule="evenodd"
        />
      </svg>
    </div>
  )
}

/* ── Input style helpers ── */

/*
 * Solid surface is painted via a layered inset box-shadow (1000px inset of
 * SURFACE) on top of the explicit backgroundColor. The shadow technique is
 * the same one used to defeat Chrome's autofill background injection — it
 * also defeats Dark Reader and any low-specificity stylesheet that tries to
 * force the input transparent. SURFACE matches the design system's
 * Surface 100 (#101111) so inputs read as elevated cards on the #07080a page.
 */
const SURFACE = '#1b1c1e'
const SURFACE_SHADOW = `${SURFACE} 0px 0px 0px 1000px inset`

const inputStyle: React.CSSProperties = {
  width: '100%',
  backgroundColor: SURFACE,
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '8px',
  padding: '10px 14px',
  color: 'rgb(249, 249, 249)',
  fontSize: '13px',
  fontWeight: 500,
  fontFamily: 'Inter, system-ui, sans-serif',
  letterSpacing: '0.2px',
  outline: 'none',
  transition: 'border-color 0.15s, box-shadow 0.15s',
  boxSizing: 'border-box',
  boxShadow: SURFACE_SHADOW,
  WebkitAppearance: 'none',
  appearance: 'none',
}

