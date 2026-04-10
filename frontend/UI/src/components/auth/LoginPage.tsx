import { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import mayatrailLogo from '@/assets/mayatrail-logo.png'

// GIS is loaded via a <script> tag in index.html.
// Declaring a minimal subset of the API keeps TypeScript happy without a
// separate @types package.
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
  const { clearError } = useAuth()

  const switchTab = (tab: AuthTab) => {
    clearError()
    setSignupSuccess(false)
    setActiveTab(tab)
  }

  const handleSignupComplete = () => {
    setSignupSuccess(true)
    // Auto-switch to sign-in tab after a short delay
    setTimeout(() => {
      setActiveTab('signin')
      setSignupSuccess(false)
    }, 4000)
  }

  return (
    <div className="min-h-screen flex items-center justify-center overflow-x-hidden bg-surface-deep text-content-primary font-display relative">
      {/* Background effects — matched to frontend hero grid */}
      <div className="fixed inset-0 pointer-events-none z-0">
        {/* Grid */}
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
        {/* Glow 1 — danger red */}
        <div className="absolute w-[500px] h-[500px] rounded-full blur-[120px] opacity-[0.08] bg-danger -top-[150px] -right-[100px]" />
        {/* Glow 2 — accent blue */}
        <div className="absolute w-[400px] h-[400px] rounded-full blur-[120px] opacity-[0.08] bg-accent-blue -bottom-[100px] -left-[80px]" />
      </div>

      {/* Content */}
      <div className="relative z-[1] flex gap-12 items-center p-6 max-w-[960px] w-full">
        {/* Login Card */}
        <div className="bg-surface-card border border-border rounded-card px-9 py-10 w-[420px] shrink-0 relative overflow-hidden">
          {/* Top gradient border — danger to accent-blue */}
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-danger via-[#ff6644] to-accent-blue" />

          {/* Header */}
          <div className="text-center mb-8">
            <div className="flex items-center justify-center gap-2.5 mb-2">
              <img
                src={mayatrailLogo}
                alt="MayaTrail"
                className="w-9 h-9 rounded-lg object-cover"
              />
              <span className="font-display text-2xl font-extrabold text-content-primary tracking-[-0.5px]">MayaTrail</span>
            </div>
            <p className="font-mono text-[11px] text-content-dim tracking-[1.5px] uppercase">
              APT Emulation Platform
            </p>
          </div>

          {/* Success Banner */}
          {signupSuccess && (
            <div className="mb-6 bg-green/[0.08] border border-green/30 rounded-lg px-4 py-3.5 flex items-start gap-3
              animate-[fadeSlideIn_0.3s_ease-out]">
              <svg className="w-5 h-5 mt-0.5 shrink-0 text-green" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" /></svg>
              <div>
                <p className="text-sm font-bold text-green mb-0.5">Account Verified!</p>
                <p className="text-xs text-content-secondary leading-relaxed">
                  Your email has been verified successfully. You can now sign in with your credentials.
                </p>
              </div>
            </div>
          )}

          {/* Auth Tabs */}
          <div className="flex mb-6 border border-border rounded-lg overflow-hidden">
            <TabButton active={activeTab === 'signin'} onClick={() => switchTab('signin')}>Sign In</TabButton>
            <TabButton active={activeTab === 'signup'} onClick={() => switchTab('signup')}>Sign Up</TabButton>
          </div>

          {/* Forms */}
          {activeTab === 'signin' ? <SignInForm /> : <SignUpForm onComplete={handleSignupComplete} />}

          {/* Footer */}
          <div className="text-center mt-7 pt-5 border-t border-border">
            <p className="font-mono text-[10px] text-content-dim tracking-wide">MayaTrail</p>
          </div>
        </div>

        {/* Info Panel */}
        <div className="flex flex-col gap-4 flex-1">
          <InfoCard
            icon="&#127919;"
            title="Adversary Emulation"
            body="Real-world APT techniques across AWS, GCP, Azure, AI and Kubernetes environments."
          />
          <InfoCard
            icon="&#128203;"
            title="IR Playbooks"
            body="Step-by-step incident response guides mapped to each threat actor's behavior."
          />
          <InfoCard
            icon="&#128737;"
            title="Detection Engineering"
            body="SIGMA, KQL, and YARA rules auto-generated from every emulation run."
          />
        </div>
      </div>
    </div>
  )
}

/* ── Sign In Form ── */
function SignInForm() {
  const navigate = useNavigate()
  const { login, googleSSO, loading, error, clearError } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const redirectAfterAuth = (user: { isVerified: boolean; isDemo: boolean }) => {
    if (!user.isVerified && !user.isDemo) {
      navigate('/connector', { replace: true })
    } else {
      navigate('/', { replace: true })
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    clearError()
    try {
      const loggedInUser = await login({ username, password })
      redirectAfterAuth(loggedInUser)
    } catch {
      // error is set in AuthContext
    }
  }

  const handleGoogleCredential = useCallback(async (idToken: string) => {
    clearError()
    try {
      const user = await googleSSO(idToken)
      redirectAfterAuth(user)
    } catch {
      // error is set in AuthContext
    }
  }, [googleSSO, clearError]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <form className="flex flex-col gap-5" onSubmit={handleSubmit}>
      <FormField label="Username or Email" icon="&#9993;">
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="you@company.com"
          required
          autoComplete="username"
          className="w-full bg-surface-elevated border border-border rounded-lg py-3 pl-[42px] pr-3.5
            text-content-primary font-mono text-[13px] outline-none
            transition-all focus:border-danger/40 focus:shadow-[0_0_0_3px_rgba(255,34,68,0.08)]
            placeholder:text-content-dim"
        />
      </FormField>

      <FormField label="Password" icon="&#128274;">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter your password"
          required
          autoComplete="current-password"
          className="w-full bg-surface-elevated border border-border rounded-lg py-3 pl-[42px] pr-3.5
            text-content-primary font-mono text-[13px] outline-none
            transition-all focus:border-danger/40 focus:shadow-[0_0_0_3px_rgba(255,34,68,0.08)]
            placeholder:text-content-dim"
        />
      </FormField>

      <div className="flex items-center justify-between">
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" className="w-3.5 h-3.5 accent-danger cursor-pointer" />
          <span className="text-xs text-content-secondary">Remember me</span>
        </label>
        <a href="#" className="font-mono text-[11px] text-danger no-underline hover:text-content-primary transition-colors">
          Forgot password?
        </a>
      </div>

      {error && (
        <div className="font-mono text-[11px] text-danger bg-danger/[0.06] border border-danger/20 rounded-lg px-3.5 py-2.5 animate-fadeSlideIn">
          {error}
        </div>
      )}

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-danger border-none rounded-btn py-3.5
          text-white font-display text-sm font-bold cursor-pointer
          transition-all hover:-translate-y-[2px] hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]
          active:translate-y-0 disabled:opacity-70 disabled:cursor-not-allowed disabled:transform-none
          flex items-center justify-center gap-2"
      >
        <span className={loading ? 'opacity-50' : ''}>Sign In</span>
        {loading && <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
      </button>

      <GoogleSignInButton onCredential={handleGoogleCredential} />
    </form>
  )
}

/* ── Sign Up Form (multi-step: fields → OTP → success) ── */
type SignUpStep = 'details' | 'otp'

function SignUpForm({ onComplete }: { onComplete: () => void }) {
  const navigate = useNavigate()
  const { signup, googleSSO, verifyOTP, resendOTP, loading, error, clearError } = useAuth()
  const [step, setStep] = useState<SignUpStep>('details')
  const [pendingEmail, setPendingEmail] = useState('')

  // Details fields
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

  const handleOTPVerified = () => {
    onComplete()
  }

  // Google SSO on the sign-up tab creates or links the account and
  // navigates directly — no OTP step required.
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
        onVerified={handleOTPVerified}
        onBack={() => { clearError(); setStep('details') }}
      />
    )
  }

  return (
    <form className="flex flex-col gap-5" onSubmit={handleDetailsSubmit}>
      <FormField label="Invite Code" icon="&#128273;">
        <input
          type="text"
          value={inviteCode}
          onChange={(e) => setInviteCode(e.target.value)}
          placeholder="Enter your invite code"
          required
          autoComplete="off"
          className="w-full bg-surface-elevated border border-border rounded-lg py-3 pl-[42px] pr-3.5
            text-content-primary font-mono text-[13px] outline-none
            transition-all focus:border-danger/40 focus:shadow-[0_0_0_3px_rgba(255,34,68,0.08)]
            placeholder:text-content-dim"
        />
      </FormField>

      <FormField label="Full Name" icon="&#128100;">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Jane Doe"
          required
          autoComplete="name"
          className="w-full bg-surface-elevated border border-border rounded-lg py-3 pl-[42px] pr-3.5
            text-content-primary font-mono text-[13px] outline-none
            transition-all focus:border-danger/40 focus:shadow-[0_0_0_3px_rgba(255,34,68,0.08)]
            placeholder:text-content-dim"
        />
      </FormField>

      <FormField label="Email" icon="&#9993;">
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          required
          autoComplete="email"
          className="w-full bg-surface-elevated border border-border rounded-lg py-3 pl-[42px] pr-3.5
            text-content-primary font-mono text-[13px] outline-none
            transition-all focus:border-danger/40 focus:shadow-[0_0_0_3px_rgba(255,34,68,0.08)]
            placeholder:text-content-dim"
        />
      </FormField>

      <FormField label="Password" icon="&#128274;">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Min. 8 characters"
          required
          minLength={8}
          autoComplete="new-password"
          className="w-full bg-surface-elevated border border-border rounded-lg py-3 pl-[42px] pr-3.5
            text-content-primary font-mono text-[13px] outline-none
            transition-all focus:border-danger/40 focus:shadow-[0_0_0_3px_rgba(255,34,68,0.08)]
            placeholder:text-content-dim"
        />
      </FormField>

      <FormField label="Confirm Password" icon="&#128274;">
        <input
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          placeholder="Re-enter password"
          required
          autoComplete="new-password"
          className="w-full bg-surface-elevated border border-border rounded-lg py-3 pl-[42px] pr-3.5
            text-content-primary font-mono text-[13px] outline-none
            transition-all focus:border-danger/40 focus:shadow-[0_0_0_3px_rgba(255,34,68,0.08)]
            placeholder:text-content-dim"
        />
      </FormField>

      {displayError && (
        <div className="font-mono text-[11px] text-danger">{displayError}</div>
      )}

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-danger border-none rounded-btn py-3.5
          text-white font-display text-sm font-bold cursor-pointer
          transition-all hover:-translate-y-[2px] hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]
          active:translate-y-0 disabled:opacity-70 disabled:cursor-not-allowed disabled:transform-none
          flex items-center justify-center gap-2"
      >
        <span className={loading ? 'opacity-50' : ''}>Create Account</span>
        {loading && <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
      </button>

      <GoogleSignInButton onCredential={handleGoogleCredential} />
    </form>
  )
}

/* ── OTP Verification Form ── */
function OTPVerificationForm({
  email,
  loading,
  error,
  clearError,
  verifyOTP,
  resendOTP,
  onVerified,
  onBack,
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

  // Auto-focus first input on mount
  useEffect(() => {
    inputRefs.current[0]?.focus()
  }, [])

  // Countdown timer for resend cooldown
  useEffect(() => {
    if (resendCooldown <= 0) return
    const timer = setInterval(() => {
      setResendCooldown((c) => c - 1)
    }, 1000)
    return () => clearInterval(timer)
  }, [resendCooldown])

  const handleDigitChange = useCallback((index: number, value: string) => {
    // Only allow single digit
    const digit = value.replace(/\D/g, '').slice(-1)
    setDigits((prev) => {
      const next = [...prev]
      next[index] = digit
      return next
    })
    clearError()

    // Auto-advance to next input
    if (digit && index < 5) {
      inputRefs.current[index + 1]?.focus()
    }
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
    for (let i = 0; i < 6; i++) {
      newDigits[i] = pasted[i] ?? ''
    }
    setDigits(newDigits)
    // Focus the last filled or the next empty input
    const focusIdx = Math.min(pasted.length, 5)
    inputRefs.current[focusIdx]?.focus()
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
      setResendCooldown(60) // 60-second cooldown
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
      {/* Header */}
      <div className="text-center">
        <div className="w-14 h-14 rounded-full bg-danger/[0.12] border border-danger/20 flex items-center justify-center mx-auto mb-3">
          <svg className="w-7 h-7 text-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="4" width="20" height="16" rx="3" /><path d="M2 7l10 6 10-6" /></svg>
        </div>
        <p className="text-sm font-bold text-content-primary mb-1">
          Check your email
        </p>
        <p className="text-xs text-content-secondary leading-relaxed">
          We sent a 6-digit code to{' '}
          <span className="font-mono text-content-primary">{maskedEmail}</span>
        </p>
      </div>

      {/* OTP Inputs */}
      <div className="flex justify-center gap-2.5" onPaste={handlePaste}>
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
            className={`w-11 h-14 text-center font-mono text-xl font-bold rounded-lg border outline-none
              transition-all bg-surface-elevated text-content-primary
              ${digit
                ? 'border-danger/40 shadow-[0_0_0_2px_rgba(255,34,68,0.08)]'
                : 'border-border'
              }
              focus:border-danger/60 focus:shadow-[0_0_0_3px_rgba(255,34,68,0.12)]`}
            aria-label={`Digit ${i + 1}`}
          />
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="font-mono text-[11px] text-danger bg-danger/[0.06] border border-danger/20 rounded-lg px-3.5 py-2.5 text-center">
          {error}
        </div>
      )}

      {/* Resend message */}
      {resendMsg && !error && (
        <div className="font-mono text-[11px] text-green bg-green/[0.06] border border-green/20 rounded-lg px-3.5 py-2.5 text-center">
          {resendMsg}
        </div>
      )}

      {/* Verify button */}
      <button
        type="submit"
        disabled={loading || !isComplete}
        className="w-full bg-danger border-none rounded-btn py-3.5
          text-white font-display text-sm font-bold cursor-pointer
          transition-all hover:-translate-y-[2px] hover:shadow-[0_8px_40px_rgba(255,34,68,0.4)]
          active:translate-y-0 disabled:opacity-70 disabled:cursor-not-allowed disabled:transform-none
          flex items-center justify-center gap-2"
      >
        <span className={loading ? 'opacity-50' : ''}>Verify Email</span>
        {loading && <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
      </button>

      {/* Resend + Back */}
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={onBack}
          className="font-mono text-[11px] text-content-dim no-underline hover:text-content-primary
            transition-colors cursor-pointer bg-transparent border-none p-0"
        >
          ← Back
        </button>

        <button
          type="button"
          onClick={handleResend}
          disabled={resendCooldown > 0 || loading}
          className="font-mono text-[11px] text-danger no-underline hover:text-content-primary
            transition-colors cursor-pointer bg-transparent border-none p-0
            disabled:text-content-dim disabled:cursor-not-allowed"
        >
          {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend code'}
        </button>
      </div>

      {/* Expiry note */}
      <p className="font-mono text-[10px] text-content-dim text-center">
        Code expires in 10 minutes · Up to 5 attempts
      </p>
    </form>
  )
}

/**
 * Renders a Google Identity Services sign-in button.
 *
 * GIS is initialized once per mount using the client ID from the Vite env
 * var VITE_GOOGLE_CLIENT_ID.  On a successful Google sign-in, the provided
 * onCredential callback receives the raw Google ID token string.
 *
 * Renders nothing when VITE_GOOGLE_CLIENT_ID is empty or when the GIS
 * library has not yet loaded (defensive against slow networks).
 */
function GoogleSignInButton({ onCredential }: { onCredential: (idToken: string) => void }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined

  useEffect(() => {
    if (!clientId || !containerRef.current) return

    // GIS may not be available yet if the <script> is still loading.
    // Poll up to ~3 seconds before giving up.
    let attempts = 0
    const MAX_ATTEMPTS = 30

    const tryInit = () => {
      if (!containerRef.current) return

      if (!window.google?.accounts?.id) {
        attempts += 1
        if (attempts < MAX_ATTEMPTS) {
          setTimeout(tryInit, 100)
        }
        return
      }

      window.google.accounts.id.initialize({
        client_id: clientId,
        callback: (response) => {
          onCredential(response.credential)
        },
        auto_select: false,
      })

      window.google.accounts.id.renderButton(containerRef.current, {
        theme: 'filled_black',
        size: 'large',
        width: 342,
        text: 'continue_with',
      })
    }

    tryInit()
    // onCredential is stable (wrapped in useCallback by callers) — safe to omit.
  }, [clientId]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!clientId) return null

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <div className="flex-1 h-px bg-border" />
        <span className="font-mono text-[10px] text-content-dim tracking-[1px] uppercase">or</span>
        <div className="flex-1 h-px bg-border" />
      </div>
      {/* GIS injects an iframe-based button into this div */}
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
      className={`flex-1 py-2.5 border-none font-mono text-xs font-bold tracking-wide cursor-pointer transition-all
        ${active
          ? 'bg-danger/[0.08] text-danger'
          : 'bg-surface-elevated text-content-dim hover:text-content-secondary'
        }
        first:border-r first:border-r-border`}
    >
      {children}
    </button>
  )
}

function FormField({ label, icon, children }: { label: string; icon: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label className="font-mono text-[10px] tracking-[1px] text-content-dim uppercase">{label}</label>
      <div className="relative">
        <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-sm text-content-dim pointer-events-none">
          {icon}
        </span>
        {children}
      </div>
    </div>
  )
}

function InfoCard({ icon, title, body }: { icon: string; title: string; body: string }) {
  return (
    <div className="bg-surface-card border border-border rounded-card px-6 py-5 transition-all duration-[400ms]
      hover:border-[rgba(255,34,68,0.2)] hover:-translate-y-1 hover:shadow-[0_20px_60px_rgba(0,0,0,0.3)]
      relative overflow-hidden group">
      <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-danger to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-[400ms]" />
      <div className="w-12 h-12 rounded-btn bg-danger/[0.15] flex items-center justify-center text-[22px] mb-4">{icon}</div>
      <div className="text-sm font-bold font-display text-content-primary mb-1.5 tracking-[-0.3px]">{title}</div>
      <div className="text-[0.9rem] text-content-secondary leading-[1.65]">{body}</div>
    </div>
  )
}
