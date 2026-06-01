import { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import mayatrailLogo from '@/assets/mayatrail-logo.png'
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
            }
          ) => void
        }
      }
    }
  }
}

type AuthTab = 'signin' | 'signup'

/** Root login page — full-screen two-column split layout. */
export function LoginPage() {
  const [activeTab, setActiveTab] = useState<AuthTab>('signin')
  const [signupSuccess, setSignupSuccess] = useState(false)
  const [formVisible, setFormVisible] = useState(true)
  const { clearError, googleSSO, error: authError } = useAuth()
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
      const user = await googleSSO(idToken)
      if (!user.isVerified && !user.isDemo) {
        navigate('/connector', { replace: true })
      } else {
        navigate('/', { replace: true })
      }
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

      {/* ── Two-column card ── */}
      <div
        className="relative z-10 flex w-full"
        style={{
          maxWidth: 'min(960px, 92vw)',
          minHeight: '580px',
          border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: '16px',
          overflow: 'hidden',
          boxShadow: 'rgb(7,8,10) 0px 0px 0px 1px inset, rgba(0,0,0,0.45) 0px 24px 48px',
        }}
      >
        {/* ── Left: Brand panel ── */}
        <div
          className="flex flex-col justify-between"
          style={{
            width: '42%',
            minWidth: '280px',
            background: '#101111',
            borderRight: '1px solid rgba(255,255,255,0.06)',
            padding: '48px 40px',
            flexShrink: 0,
          }}
        >
          {/* Logo + wordmark */}
          <div>
            <div className="flex items-center gap-2.5 mb-10">
              <img src={mayatrailLogo} alt="MayaTrail" style={{ width: '28px', height: '28px', borderRadius: '6px', objectFit: 'cover' }} />
              <span style={{ fontSize: '16px', fontWeight: 600, letterSpacing: '-0.2px', color: '#f9f9f9' }}>MayaTrail</span>
            </div>

            <h2 style={{ fontSize: '22px', fontWeight: 600, color: '#f9f9f9', lineHeight: 1.3, marginBottom: '10px', letterSpacing: '-0.2px' }}>
              Adversary emulation,<br />built for security teams.
            </h2>
            <p style={{ fontSize: '13px', color: '#6a6b6c', lineHeight: 1.7, letterSpacing: '0.2px', marginBottom: '36px' }}>
              Simulate real-world APT activity and validate your detection coverage — all in one platform.
            </p>

            {/* Feature list */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {([
                { icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z', text: 'Guided APT scenario playbooks' },
                { icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z', text: 'SIEM telemetry & alert correlation' },
                { icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2', text: 'Full audit trail & compliance logs' },
              ] as const).map(({ icon, text }) => (
                <div key={text} className="flex items-start gap-3">
                  <svg style={{ width: '15px', height: '15px', color: '#FF6363', marginTop: '1px', flexShrink: 0 }} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d={icon} strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  <span style={{ fontSize: '13px', color: '#9c9c9d', letterSpacing: '0.2px', lineHeight: 1.5 }}>{text}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Bottom disclaimer */}
          <p style={{ fontSize: '10px', fontFamily: 'Geist Mono, monospace', color: '#434345', letterSpacing: '0.8px', marginTop: '40px' }}>
            USE ONLY IN ISOLATED TEST ACCOUNTS
          </p>
        </div>

        {/* ── Right: Form panel ── */}
        <div
          className="flex flex-col justify-center"
          style={{ flex: 1, background: '#07080a', padding: '48px 44px' }}
        >
          {/* Heading */}
          <h1 style={{ fontSize: '26px', fontWeight: 600, letterSpacing: '-0.3px', color: '#f9f9f9', marginBottom: '4px' }}>
            {activeTab === 'signin' ? 'Sign in to your account' : 'Create your account'}
          </h1>
          <p style={{ fontSize: '13px', color: '#6a6b6c', letterSpacing: '0.2px', marginBottom: '28px' }}>
            {activeTab === 'signin'
              ? <>No account? <button type="button" onClick={() => switchTab('signup')} style={{ color: '#FF6363', background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', padding: 0, fontFamily: 'inherit' }}>Create one →</button></>
              : <>Already have an account? <button type="button" onClick={() => switchTab('signin')} style={{ color: '#FF6363', background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', padding: 0, fontFamily: 'inherit' }}>Sign in →</button></>
            }
          </p>

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

          {/* Form area */}
          <div style={{ opacity: formVisible ? 1 : 0, transition: 'opacity 0.12s ease' }}>
            {activeTab === 'signin'
              ? <SignInForm />
              : <SignUpForm onComplete={handleSignupComplete} />
            }

            {authError && (
              <div className="mt-4 mb-2">
                <ErrorBanner message={authError} />
              </div>
            )}

            <GoogleSignInButton onCredential={handleGoogleCredential} />
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
      const user = await login({ username, password })
      if (!user.isVerified && !user.isDemo) {
        navigate('/connector', { replace: true })
      } else {
        navigate('/', { replace: true })
      }
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
            style={{ fontSize: '11px', fontFamily: 'Geist Mono, monospace', color: '#FF6363', letterSpacing: '0.3px', background: 'none', border: 'none', cursor: 'pointer', padding: 0, transition: 'opacity 0.15s' }}
            onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
            onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
          >
            Forgot password?
          </button>
        </div>
        <div className="relative">
          <input
            type="password"
            value={password}
            onChange={(e) => { setPassword(e.target.value); if (hasError) clearError() }}
            placeholder="Enter your password"
            required
            autoComplete="current-password"
            className={`auth-input-solid${hasError ? ' auth-input-error' : ''}`}
            style={hasError ? { ...inputStyle, paddingRight: '36px' } : inputStyle}
          />
          {hasError && <InputErrorIcon />}
        </div>
      </div>

      {/* Remember me */}
      <div className="flex items-center">
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" style={{ accentColor: '#FF6363', width: '13px', height: '13px' }} />
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
          style={{ fontSize: '11px', fontFamily: 'Geist Mono, monospace', color: '#6a6b6c', background: 'none', border: 'none', cursor: 'pointer', padding: 0, transition: 'opacity 0.15s' }}
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
        <input
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          placeholder="Min. 8 characters"
          required
          minLength={8}
          autoComplete="new-password"
          className="auth-input-solid"
          style={inputStyle}
        />
      </FormField>

      <FormField label="Confirm New Password">
        <input
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          placeholder="Re-enter new password"
          required
          autoComplete="new-password"
          className="auth-input-solid"
          style={inputStyle}
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
          style={{ fontSize: '11px', fontFamily: 'Geist Mono, monospace', color: '#6a6b6c', background: 'none', border: 'none', cursor: 'pointer', padding: 0, transition: 'opacity 0.15s' }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          ← Back
        </button>
        <button
          type="button"
          onClick={handleResend}
          disabled={resendCooldown > 0 || loading}
          style={{ fontSize: '11px', fontFamily: 'Geist Mono, monospace', color: resendCooldown > 0 ? '#434345' : '#FF6363', background: 'none', border: 'none', cursor: resendCooldown > 0 ? 'not-allowed' : 'pointer', padding: 0, transition: 'opacity 0.15s' }}
          onMouseEnter={(e) => { if (resendCooldown <= 0) e.currentTarget.style.opacity = '0.6' }}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend code'}
        </button>
      </div>

      <p style={{ fontSize: '10px', fontFamily: 'Geist Mono, monospace', color: '#434345', textAlign: 'center', letterSpacing: '0.3px' }}>
        Expires in 10 minutes — up to 5 attempts
      </p>
    </form>
  )
}

/* ── Sign Up Form (multi-step: details → OTP → success) ── */

type SignUpStep = 'details' | 'otp'

/** Sign-up flow: collects invite code, name, email, password, then OTP verify. */
function SignUpForm({ onComplete }: { onComplete: () => void }) {
  const { signup, verifyOTP, resendOTP, loading, error, clearError } = useAuth()
  const [step, setStep] = useState<SignUpStep>('details')
  const [pendingEmail, setPendingEmail] = useState('')

  const [inviteCode, setInviteCode] = useState('')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [localError, setLocalError] = useState('')

  const handleDetailsSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    clearError()
    setLocalError('')
    if (password !== confirm) {
      setLocalError('Passwords do not match')
      return
    }
    try {
      const res = await signup({ name, email, password, inviteCode })
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
      <FormField label="Invite Code">
        <input
          type="text"
          value={inviteCode}
          onChange={(e) => setInviteCode(e.target.value)}
          placeholder="Enter your invite code"
          required
          autoComplete="off"
          className="auth-input-solid"
          style={inputStyle}
        />
      </FormField>

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
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Min. 8 characters"
          required
          minLength={8}
          autoComplete="new-password"
          className="auth-input-solid"
          style={inputStyle}
        />
      </FormField>

      <FormField label="Confirm Password">
        <input
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          placeholder="Re-enter password"
          required
          autoComplete="new-password"
          className="auth-input-solid"
          style={inputStyle}
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
          style={{ fontSize: '11px', fontFamily: 'Geist Mono, monospace', color: '#6a6b6c', background: 'none', border: 'none', cursor: 'pointer', padding: 0, transition: 'opacity 0.15s' }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          Back
        </button>
        <button
          type="button"
          onClick={handleResend}
          disabled={resendCooldown > 0 || loading}
          style={{ fontSize: '11px', fontFamily: 'Geist Mono, monospace', color: resendCooldown > 0 ? '#434345' : '#FF6363', background: 'none', border: 'none', cursor: resendCooldown > 0 ? 'not-allowed' : 'pointer', padding: 0, transition: 'opacity 0.15s' }}
          onMouseEnter={(e) => { if (resendCooldown <= 0) e.currentTarget.style.opacity = '0.6' }}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend code'}
        </button>
      </div>

      <p style={{ fontSize: '10px', fontFamily: 'Geist Mono, monospace', color: '#434345', textAlign: 'center', letterSpacing: '0.3px' }}>
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
      theme: 'filled_black',
      size: 'large',
      width,
      text: 'continue_with',
    })
  }, [])

  useEffect(() => {
    if (!clientId || !wrapperRef.current) return

    let attempts = 0
    const MAX_ATTEMPTS = 30
    let pollingDone = false

    const tryInit = () => {
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

  return (
    <div className="flex flex-col gap-3 mt-1">
      <div className="flex items-center gap-3">
        <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.06)' }} />
        <span style={{ fontSize: '10px', fontFamily: 'Geist Mono, monospace', color: '#434345', letterSpacing: '1px', textTransform: 'uppercase' }}>or</span>
        <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.06)' }} />
      </div>
      <div ref={wrapperRef} style={{ width: '100%', minHeight: '44px' }}>
        <div ref={containerRef} className="flex justify-center" />
      </div>
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
        padding: '10px 20px',
        background: '#FF6363',
        color: '#fff',
        border: 'none',
        borderRadius: '6px',
        fontSize: '13px',
        fontWeight: 600,
        letterSpacing: '0.3px',
        cursor: loading || disabled ? 'not-allowed' : 'pointer',
        opacity: loading || disabled ? 0.5 : 1,
        transition: 'opacity 0.15s',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        boxShadow: 'rgba(255,99,99,0.25) 0px 1px 0px 0px inset, rgba(0,0,0,0.2) 0px -1px 0px 0px inset',
      }}
      onMouseEnter={(e) => { if (!loading && !disabled) e.currentTarget.style.opacity = '0.8' }}
      onMouseLeave={(e) => { if (!loading && !disabled) e.currentTarget.style.opacity = '1' }}
    >
      <span>{children}</span>
      {loading && (
        <div
          className="animate-spin"
          style={{ width: '13px', height: '13px', border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%' }}
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
        fontFamily: 'Geist Mono, monospace',
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

