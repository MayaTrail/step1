import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'

type AuthTab = 'signin' | 'signup'

export function LoginPage() {
  const [activeTab, setActiveTab] = useState<AuthTab>('signin')
  const { clearError } = useAuth()

  const switchTab = (tab: AuthTab) => {
    clearError()
    setActiveTab(tab)
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
              <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-danger to-[#ff6644] flex items-center justify-center text-sm font-extrabold text-white">
                M
              </div>
              <span className="font-display text-2xl font-extrabold text-content-primary tracking-[-0.5px]">MayaTrail</span>
            </div>
            <p className="font-mono text-[11px] text-content-dim tracking-[1.5px] uppercase">
              APT Emulation Platform
            </p>
          </div>

          {/* Auth Tabs */}
          <div className="flex mb-6 border border-border rounded-lg overflow-hidden">
            <TabButton active={activeTab === 'signin'} onClick={() => switchTab('signin')}>Sign In</TabButton>
            <TabButton active={activeTab === 'signup'} onClick={() => switchTab('signup')}>Sign Up</TabButton>
          </div>

          {/* Forms */}
          {activeTab === 'signin' ? <SignInForm /> : <SignUpForm />}

          {/* Divider */}
          <div className="flex items-center gap-4 my-6">
            <div className="flex-1 h-px bg-border" />
            <span className="font-mono text-[10px] text-content-dim tracking-[2px]">OR</span>
            <div className="flex-1 h-px bg-border" />
          </div>

          {/* Google SSO */}
          <GoogleSSOButton />

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
  const { login, loading, error, clearError } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    clearError()
    try {
      await login({ username, password })
      navigate('/', { replace: true })
    } catch {
      // error is set in AuthContext
    }
  }

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
        <div className="font-mono text-[11px] text-danger">{error}</div>
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
    </form>
  )
}

/* ── Sign Up Form ── */
function SignUpForm() {
  const navigate = useNavigate()
  const { signup, loading, error, clearError } = useAuth()
  const [inviteCode, setInviteCode] = useState('')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [localError, setLocalError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    clearError()
    setLocalError('')

    if (password !== confirm) {
      setLocalError('Passwords do not match')
      return
    }

    try {
      await signup({ name, email, password, inviteCode })
      navigate('/', { replace: true })
    } catch {
      // error is set in AuthContext
    }
  }

  const displayError = localError || error

  return (
    <form className="flex flex-col gap-5" onSubmit={handleSubmit}>
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
    </form>
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

function GoogleSSOButton() {
  const navigate = useNavigate()
  const { googleSSO, loading } = useAuth()

  const handleClick = async () => {
    try {
      await googleSSO()
      navigate('/', { replace: true })
    } catch {
      // error handled in AuthContext
    }
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={loading}
      className="w-full bg-transparent border border-[rgba(255,255,255,0.15)] rounded-btn py-3 text-content-primary font-body text-[13px] font-medium
        cursor-pointer transition-all hover:bg-[rgba(255,255,255,0.05)] hover:border-border-active
        flex items-center justify-center gap-2.5 disabled:opacity-70"
    >
      <svg viewBox="0 0 24 24" width="18" height="18" className="shrink-0">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4" />
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
      </svg>
      Continue with Google
    </button>
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
