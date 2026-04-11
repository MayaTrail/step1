import { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import mayatrailLogo from '@/assets/mayatrail-logo.png'
import { forgotPassword, resetPassword } from '@/services/auth.service'

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

export function LoginPage() {
  const [activeTab, setActiveTab] = useState<AuthTab>('signin')
  const [signupSuccess, setSignupSuccess] = useState(false)
  const [formVisible, setFormVisible] = useState(true)
  const { clearError, googleSSO } = useAuth()
  const navigate = useNavigate()

  const switchTab = (tab: AuthTab) => {
    if (tab === activeTab) return
    // Fade out → swap → fade in to avoid the abrupt height jump on tab switch
    setFormVisible(false)
    setTimeout(() => {
      clearError()
      setSignupSuccess(false)
      setActiveTab(tab)
      setFormVisible(true)
    }, 120)
  }

  const handleSignupComplete = () => {
    setSignupSuccess(true)
    setTimeout(() => {
      setActiveTab('signin')
      setSignupSuccess(false)
    }, 4000)
  }

  /*
   * googleSSO handler lives here (parent) so GoogleSignInButton is only ever
   * mounted once — lifting it out of SignInForm/SignUpForm prevents GIS from
   * tearing down and re-initialising its iframe on every tab switch, which
   * was the source of the flicker.
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
      className="min-h-screen flex items-center justify-center overflow-x-hidden relative"
      style={{ backgroundColor: '#07080a', color: '#f9f9f9', fontFamily: 'Inter, system-ui, sans-serif' }}
    >
      {/* Background — grid and ambient glows */}
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
        {/* Raycast Red ambient glow — punctuation, not dominant */}
        <div
          className="absolute w-[700px] h-[700px] rounded-full -top-[200px] -right-[150px]"
          style={{ background: 'radial-gradient(circle, rgba(255,99,99,0.06) 0%, transparent 70%)' }}
        />
        <div
          className="absolute w-[600px] h-[600px] rounded-full -bottom-[150px] -left-[100px]"
          style={{ background: 'radial-gradient(circle, rgba(85,179,255,0.04) 0%, transparent 70%)' }}
        />
      </div>

      {/* Content — clamp-based widths so the layout scales from 14-inch to 24-inch */}
      <div className="relative z-[1] flex gap-16 items-center p-8" style={{ width: 'min(1200px, 90vw)' }}>

        {/* Login Card */}
        <div
          className="shrink-0 relative overflow-hidden"
          style={{
            width: 'clamp(400px, 38vw, 520px)',
            backgroundColor: '#101111',
            border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: '16px',
            boxShadow: 'rgb(27, 28, 30) 0px 0px 0px 1px, rgb(7, 8, 10) 0px 0px 0px 1px inset',
            padding: '36px 32px 32px',
          }}
        >
          {/* Top accent line — Raycast Red, hairline */}
          <div
            className="absolute top-0 left-0 right-0"
            style={{ height: '1px', background: 'linear-gradient(90deg, transparent, #FF6363 40%, transparent)' }}
          />

          {/* Header */}
          <div className="text-center mb-8">
            <div className="flex items-center justify-center gap-2.5 mb-3">
              <img
                src={mayatrailLogo}
                alt="MayaTrail"
                className="w-8 h-8 rounded-lg object-cover"
              />
              <span style={{ fontSize: '20px', fontWeight: 600, letterSpacing: '-0.3px', color: '#f9f9f9' }}>
                MayaTrail
              </span>
            </div>
            <p style={{ fontSize: '11px', fontFamily: 'Geist Mono, monospace', color: '#6a6b6c', letterSpacing: '1.5px', textTransform: 'uppercase' }}>
              APT Emulation Platform
            </p>
          </div>

          {/* Success Banner */}
          {signupSuccess && (
            <div
              className="mb-6 flex items-start gap-3 animate-fadeSlideIn"
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
                <p style={{ fontSize: '13px', fontWeight: 600, color: '#5fc992', marginBottom: '2px' }}>Account Verified</p>
                <p style={{ fontSize: '12px', color: '#9c9c9d', lineHeight: 1.5 }}>
                  Your email has been verified. You can now sign in.
                </p>
              </div>
            </div>
          )}

          {/* Auth Tabs */}
          <div
            className="flex mb-7"
            style={{ border: '1px solid rgba(255,255,255,0.06)', borderRadius: '8px', overflow: 'hidden' }}
          >
            <TabButton active={activeTab === 'signin'} onClick={() => switchTab('signin')}>Sign In</TabButton>
            <TabButton active={activeTab === 'signup'} onClick={() => switchTab('signup')}>Sign Up</TabButton>
          </div>

          {/* Form area — fade transition on tab switch */}
          <div style={{ opacity: formVisible ? 1 : 0, transition: 'opacity 0.12s ease' }}>
            {activeTab === 'signin'
              ? <SignInForm />
              : <SignUpForm onComplete={handleSignupComplete} />
            }
            {/*
              GoogleSignInButton lives here, outside both forms, so GIS is
              initialised once and its iframe never re-mounts on tab switch.
            */}
            <GoogleSignInButton onCredential={handleGoogleCredential} />
          </div>

          {/* Footer */}
          <div
            className="text-center mt-7 pt-5"
            style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}
          >
            <p style={{ fontSize: '10px', fontFamily: 'Geist Mono, monospace', color: '#434345', letterSpacing: '1px' }}>
              MayaTrail — Use only in isolated test accounts
            </p>
          </div>
        </div>

        {/* Info Panel */}
        <div className="flex flex-col gap-3 flex-1">
          <InfoCard
            title="Adversary Emulation"
            body="Real-world APT techniques across AWS, GCP, Azure, AI and Kubernetes environments."
            accent="#FF6363"
          />
          <InfoCard
            title="IR Playbooks"
            body="Step-by-step incident response guides mapped to each threat actor's behavior."
            accent="#55b3ff"
          />
          <InfoCard
            title="Detection Engineering"
            body="SIGMA, KQL, and YARA rules auto-generated from every emulation run."
            accent="#5fc992"
          />
        </div>
      </div>
    </div>
  )
}

/* ── Sign In Form ── */
function SignInForm() {
  const navigate = useNavigate()
  const { login, loading, error, clearError } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  // Forgot-password inline flow state
  const [forgotStep, setForgotStep] = useState<'none' | 'email' | 'otp' | 'done'>('none')
  const [resetEmail, setResetEmail] = useState('')

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

  // Forgot password → enter email
  if (forgotStep === 'email') {
    return (
      <ForgotPasswordForm
        onCodeSent={(email) => { setResetEmail(email); setForgotStep('otp') }}
        onBack={() => { clearError(); setForgotStep('none') }}
      />
    )
  }

  // Forgot password → enter OTP + new password
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

      <FormField label="Username or Email">
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="you@company.com"
          required
          autoComplete="username"
          style={inputStyle}
          onFocus={(e) => applyFocusStyle(e.target)}
          onBlur={(e) => removeFocusStyle(e.target)}
        />
      </FormField>

      <FormField label="Password">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter your password"
          required
          autoComplete="current-password"
          style={inputStyle}
          onFocus={(e) => applyFocusStyle(e.target)}
          onBlur={(e) => removeFocusStyle(e.target)}
        />
      </FormField>

      <div className="flex items-center justify-between">
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" style={{ accentColor: '#FF6363', width: '13px', height: '13px' }} />
          <span style={{ fontSize: '12px', color: '#9c9c9d' }}>Remember me</span>
        </label>
        <button
          type="button"
          onClick={() => { clearError(); setForgotStep('email') }}
          style={{ fontSize: '11px', fontFamily: 'Geist Mono, monospace', color: '#FF6363', textDecoration: 'none', letterSpacing: '0.3px', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = '0.6')}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
        >
          Forgot password?
        </button>
      </div>

      {error && <ErrorBanner message={error} />}

      <PrimaryButton type="submit" loading={loading}>Sign In</PrimaryButton>
    </form>
  )
}

/* ── Forgot Password — Email Form ── */
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
          style={inputStyle}
          onFocus={(e) => applyFocusStyle(e.target)}
          onBlur={(e) => removeFocusStyle(e.target)}
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

      {/* OTP digits */}
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

      {/* New password fields */}
      <FormField label="New Password">
        <input
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          placeholder="Min. 8 characters"
          required
          minLength={8}
          autoComplete="new-password"
          style={inputStyle}
          onFocus={(e) => applyFocusStyle(e.target)}
          onBlur={(e) => removeFocusStyle(e.target)}
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
          style={inputStyle}
          onFocus={(e) => applyFocusStyle(e.target)}
          onBlur={(e) => removeFocusStyle(e.target)}
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
          style={inputStyle}
          onFocus={(e) => applyFocusStyle(e.target)}
          onBlur={(e) => removeFocusStyle(e.target)}
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
          style={inputStyle}
          onFocus={(e) => applyFocusStyle(e.target)}
          onBlur={(e) => removeFocusStyle(e.target)}
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
          style={inputStyle}
          onFocus={(e) => applyFocusStyle(e.target)}
          onBlur={(e) => removeFocusStyle(e.target)}
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
          style={inputStyle}
          onFocus={(e) => applyFocusStyle(e.target)}
          onBlur={(e) => removeFocusStyle(e.target)}
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
          style={inputStyle}
          onFocus={(e) => applyFocusStyle(e.target)}
          onBlur={(e) => removeFocusStyle(e.target)}
        />
      </FormField>

      {displayError && <ErrorBanner message={displayError} />}

      <PrimaryButton type="submit" loading={loading}>Create Account</PrimaryButton>
    </form>
  )
}

/* ── OTP Verification Form ── */
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
 * Returns null when VITE_GOOGLE_CLIENT_ID is not set.
 */
function GoogleSignInButton({ onCredential }: { onCredential: (idToken: string) => void }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined

  useEffect(() => {
    if (!clientId || !containerRef.current) return

    let attempts = 0
    const MAX_ATTEMPTS = 30

    const tryInit = () => {
      if (!containerRef.current) return
      if (!window.google?.accounts?.id) {
        attempts += 1
        if (attempts < MAX_ATTEMPTS) setTimeout(tryInit, 100)
        return
      }
      window.google.accounts.id.initialize({
        client_id: clientId,
        callback: (response) => onCredential(response.credential),
        auto_select: false,
      })
      window.google.accounts.id.renderButton(containerRef.current, {
        theme: 'filled_black',
        size: 'large',
        width: 336,
        text: 'continue_with',
      })
    }

    tryInit()
  }, [clientId]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!clientId) return null

  return (
    <div className="flex flex-col gap-3 mt-1">
      <div className="flex items-center gap-3">
        <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.06)' }} />
        <span style={{ fontSize: '10px', fontFamily: 'Geist Mono, monospace', color: '#434345', letterSpacing: '1px', textTransform: 'uppercase' }}>or</span>
        <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.06)' }} />
      </div>
      <div ref={containerRef} className="flex justify-center" />
    </div>
  )
}

/* ── Shared Components ── */

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        flex: 1,
        padding: '9px 0',
        border: 'none',
        borderRight: active ? 'none' : '1px solid rgba(255,255,255,0.06)',
        fontFamily: 'Geist Mono, monospace',
        fontSize: '11px',
        fontWeight: 600,
        letterSpacing: '0.8px',
        textTransform: 'uppercase',
        cursor: 'pointer',
        transition: 'opacity 0.15s',
        background: active ? 'rgba(255,99,99,0.06)' : 'transparent',
        color: active ? '#FF6363' : '#6a6b6c',
      }}
      onMouseEnter={(e) => { if (!active) e.currentTarget.style.opacity = '0.7' }}
      onMouseLeave={(e) => (e.currentTarget.style.opacity = '1')}
    >
      {children}
    </button>
  )
}

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
        padding: '11px 0',
        background: 'hsla(0, 0%, 100%, 0.815)',
        color: '#18191a',
        border: 'none',
        borderRadius: '86px',
        fontSize: '14px',
        fontWeight: 600,
        letterSpacing: '0.3px',
        cursor: loading || disabled ? 'not-allowed' : 'pointer',
        opacity: loading || disabled ? 0.5 : 1,
        transition: 'opacity 0.15s',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        boxShadow: 'rgba(255,255,255,0.05) 0px 1px 0px 0px inset, rgba(255,255,255,0.25) 0px 0px 0px 1px, rgba(0,0,0,0.2) 0px -1px 0px 0px inset',
      }}
      onMouseEnter={(e) => { if (!loading && !disabled) e.currentTarget.style.opacity = '0.6' }}
      onMouseLeave={(e) => { if (!loading && !disabled) e.currentTarget.style.opacity = '1' }}
    >
      <span>{children}</span>
      {loading && (
        <div
          className="animate-spin"
          style={{ width: '14px', height: '14px', border: '2px solid rgba(24,25,26,0.3)', borderTopColor: '#18191a', borderRadius: '50%' }}
        />
      )}
    </button>
  )
}

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

function InfoCard({ title, body, accent }: { title: string; body: string; accent: string }) {
  return (
    <div
      className="relative overflow-hidden group"
      style={{
        backgroundColor: '#101111',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '12px',
        padding: '20px 22px',
        boxShadow: 'rgb(27, 28, 30) 0px 0px 0px 1px, rgb(7, 8, 10) 0px 0px 0px 1px inset',
        transition: 'border-color 0.3s',
        cursor: 'default',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = `${accent}22`
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'
      }}
    >
      {/* Hover accent hairline */}
      <div
        className="absolute top-0 left-0 right-0 opacity-0 group-hover:opacity-100"
        style={{ height: '1px', background: `linear-gradient(90deg, transparent, ${accent}, transparent)`, transition: 'opacity 0.3s' }}
      />
      {/* Accent dot */}
      <div
        className="w-1.5 h-1.5 rounded-full mb-3"
        style={{ background: accent, boxShadow: `0 0 8px ${accent}66` }}
      />
      <p style={{ fontSize: '13px', fontWeight: 600, color: '#f9f9f9', marginBottom: '6px', letterSpacing: '-0.1px' }}>
        {title}
      </p>
      <p style={{ fontSize: '13px', fontWeight: 400, color: '#9c9c9d', lineHeight: 1.6, letterSpacing: '0.2px' }}>
        {body}
      </p>
    </div>
  )
}

/* ── Input style helpers ── */

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: '#07080a',
  border: '1px solid rgba(255,255,255,0.08)',
  borderRadius: '8px',
  padding: '10px 14px',
  color: '#f9f9f9',
  fontSize: '13px',
  fontWeight: 500,
  fontFamily: 'Inter, system-ui, sans-serif',
  letterSpacing: '0.2px',
  outline: 'none',
  transition: 'border-color 0.15s, box-shadow 0.15s',
  boxSizing: 'border-box',
}

function applyFocusStyle(el: HTMLInputElement) {
  el.style.borderColor = 'rgba(85, 179, 255, 0.4)'
  el.style.boxShadow = 'hsla(202, 100%, 67%, 0.12) 0px 0px 0px 3px'
}

function removeFocusStyle(el: HTMLInputElement) {
  el.style.borderColor = 'rgba(255,255,255,0.08)'
  el.style.boxShadow = 'none'
}
