import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { fetchProfile, type UserProfile } from '@/services/auth.service'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { ConnectCloudDialog } from './ConnectCloudDialog'
import { IconGear, IconCloud, IconCopy, IconLogout, IconAlert } from '@/components/ui/Icons'

/**
 * ProfilePage: the signed-in user's identity and the AWS account MayaTrail
 * works in. Uses the platform page header (eyebrow, title, subtitle) with the
 * Settings and Sign out actions on the right, an identity card beside the
 * account details, and the AWS connection below. Data comes from
 * fetchProfile and useAuth.
 */
export function ProfilePage() {
    const { user, logout } = useAuth()
    const navigate = useNavigate()
    const [profile, setProfile] = useState<UserProfile | null>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string | null>(null)
    const [connectOpen, setConnectOpen] = useState(false)

    const loadProfile = useCallback(async () => {
        setLoading(true)
        setError(null)
        try {
            const data = await fetchProfile()
            setProfile(data)
        } catch {
            setError('Failed to load profile. Please try again.')
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => {
        loadProfile()
    }, [loadProfile])

    if (loading) {
        return (
            <div className="flex items-center justify-center h-full">
                <div className="flex flex-col items-center gap-4">
                    <div className="w-10 h-10 border-2 border-accent-blue/30 border-t-accent-blue rounded-full animate-spin" />
                    <span className="font-mono text-2xs text-content-dim tracking-label uppercase">
                        Loading profile
                    </span>
                </div>
            </div>
        )
    }

    if (error) {
        return (
            <div className="flex items-center justify-center h-full">
                <Card className="p-8 max-w-md text-center">
                    <div className="w-14 h-14 rounded-full bg-danger-dim text-danger flex items-center justify-center mx-auto mb-4">
                        <IconAlert size={26} />
                    </div>
                    <h2 className="font-display text-lg font-semibold text-content-primary mb-2">
                        Something went wrong
                    </h2>
                    <p className="text-sm text-content-secondary mb-5">{error}</p>
                    <Button variant="secondary" onClick={loadProfile}>
                        Retry
                    </Button>
                </Card>
            </div>
        )
    }

    const displayName = profile
        ? [profile.first_name, profile.last_name].filter(Boolean).join(' ') || profile.username
        : user?.name ?? 'User'
    const username = profile?.username ?? user?.username ?? '—'
    const memberSince = profile?.date_joined
        ? new Date(profile.date_joined).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
        })
        : '—'
    const initials =
        user?.initials ??
        displayName
            .split(' ')
            .map((w) => w[0])
            .join('')
            .toUpperCase()
            .slice(0, 2)
    const authMethod = profile?.auth_method === 'google_sso' ? 'Google SSO' : 'Email & password'

    return (
        <>
            {/* Page header: same pattern as the Security Content hubs */}
            <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
                <div>
                    <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
                        Account
                    </div>
                    <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
                        Profile
                    </div>
                    <div className="text-[0.9rem] text-content-secondary mt-1.5">
                        Your identity and the AWS account MayaTrail works in.
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <Button variant="secondary" icon={<IconGear size={15} />} onClick={() => navigate('/settings')}>
                        Settings
                    </Button>
                    <Button variant="danger" icon={<IconLogout size={15} />} onClick={logout}>
                        Sign out
                    </Button>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-5">
                <IdentityCard
                    initials={initials}
                    displayName={displayName}
                    username={username}
                    memberSince={memberSince}
                    authMethod={authMethod}
                    user={user}
                />

                <Card className="p-6">
                    <CardEyebrow>Account overview</CardEyebrow>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-5">
                        <Field label="Email address" value={profile?.email ?? '—'} />
                        <Field label="Username" value={username} />
                        <Field label="Sign-in method" value={authMethod} />
                        <Field label="Member since" value={memberSince} />
                        {profile?.id && (
                            <div className="sm:col-span-2">
                                <AccountId id={String(profile.id)} />
                            </div>
                        )}
                    </div>
                </Card>
            </div>

            <div className="mt-5 pb-12">
                <ConnectionCard user={user} profile={profile} onConnect={() => setConnectOpen(true)} />
            </div>

            {/* Reloading on close picks up a newly verified ARN without a page refresh. */}
            {connectOpen && (
                <ConnectCloudDialog
                    onClose={() => {
                        setConnectOpen(false)
                        loadProfile()
                    }}
                />
            )}
        </>
    )
}

/* ── Identity card ── */
function IdentityCard({
    initials,
    displayName,
    username,
    memberSince,
    authMethod,
    user,
}: {
    initials: string
    displayName: string
    username: string
    memberSince: string
    authMethod: string
    user: ReturnType<typeof useAuth>['user']
}) {
    return (
        <Card className="p-6">
            <div className="flex items-center gap-4">
                <div className="w-16 h-16 shrink-0 rounded-full bg-key shadow-button flex items-center justify-center font-display text-xl font-semibold text-content-primary">
                    {initials}
                </div>
                <div className="min-w-0">
                    <h1 className="font-display text-lg font-semibold text-content-primary leading-tight truncate">
                        {displayName}
                    </h1>
                    <p className="font-mono text-xs text-content-dim mt-1 truncate">@{username}</p>
                </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 mt-5">
                {user && (
                    <Badge tone={user.isVerified ? 'green' : 'red'} mono dot>
                        {user.isVerified ? 'AWS connected' : 'Not connected'}
                    </Badge>
                )}
                <Badge tone="neutral" mono>
                    {authMethod}
                </Badge>
            </div>

            <p className="text-xs text-content-dim mt-5 pt-4 border-t border-border">
                Member since {memberSince}
            </p>
        </Card>
    )
}

/* ── Account ID block with copy feedback ── */
function AccountId({ id }: { id: string }) {
    const [copied, setCopied] = useState(false)

    const copy = () => {
        navigator.clipboard.writeText(id)
        setCopied(true)
        setTimeout(() => setCopied(false), 1600)
    }

    return (
        <div className="flex flex-col gap-1.5">
            <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
                Account ID
            </span>
            <div className="flex items-center justify-between gap-2 rounded-btn border border-border bg-surface-deep px-3 py-2">
                <span className="font-mono text-xs text-content-secondary truncate">{id}</span>
                <button
                    type="button"
                    onClick={copy}
                    aria-label="Copy account ID"
                    className="shrink-0 flex items-center justify-center w-7 h-7 rounded-btn text-content-dim transition-opacity hover:opacity-60"
                >
                    {copied ? <span className="font-mono text-2xs text-safe">Copied</span> : <IconCopy size={15} />}
                </button>
            </div>
        </div>
    )
}

/* ── Card eyebrow label ── */
function CardEyebrow({ children }: { children: React.ReactNode }) {
    return (
        <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-4">
            {children}
        </div>
    )
}

/* ── Definition-grid field ── */
function Field({ label, value }: { label: string; value: string }) {
    return (
        <div className="flex flex-col gap-1 min-w-0">
            <span className="font-mono text-2xs uppercase tracking-label text-content-dim">
                {label}
            </span>
            <span className="text-sm text-content-primary font-medium break-words">{value}</span>
        </div>
    )
}

/* ── AWS connection ── */

/**
 * The AWS account MayaTrail emulates in. A connected user sees the masked role
 * ARN and can manage it; an unconnected user gets a launcher for the connect
 * dialog. It is a launcher rather than a form because connecting means
 * creating an IAM role and choosing a policy, which needs the explanation and
 * the policy JSON the dialog carries.
 */
function ConnectionCard({
    user,
    profile,
    onConnect,
}: {
    user: ReturnType<typeof useAuth>['user']
    profile: UserProfile | null
    onConnect: () => void
}) {
    if (!user) return null
    const connected = user.isVerified
    const maskedArn = profile?.aws_role_arn?.replace(
        /^(arn:aws:iam::\d{4})\d+(:role\/.{4}).*$/,
        '$1****$2****',
    )

    return (
        <Card className="p-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                    <span className="w-10 h-10 rounded-btn flex items-center justify-center bg-accent-blue/10 border border-accent-blue/20 text-accent-blue">
                        <IconCloud size={20} />
                    </span>
                    <div>
                        <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-0.5">
                            AWS connection
                        </div>
                        <div className="font-display text-sm font-semibold text-content-primary">
                            {connected ? 'Emulation role connected' : 'No AWS account connected'}
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <Badge tone={connected ? 'green' : 'red'} mono dot>
                        {connected ? 'Verified' : 'Unverified'}
                    </Badge>
                    {connected ? (
                        <Button variant="secondary" onClick={onConnect}>Manage connection</Button>
                    ) : (
                        <Button icon={<IconCloud size={14} />} onClick={onConnect}>Connect cloud account</Button>
                    )}
                </div>
            </div>

            {connected && maskedArn && (
                <div className="mt-5 rounded-btn border border-border bg-surface-deep px-4 py-3">
                    <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-1">
                        Role ARN
                    </div>
                    <div className="font-mono text-xs text-accent-blue break-all">{maskedArn}</div>
                </div>
            )}

            {!connected && (
                <p className="mt-5 text-[0.9rem] leading-relaxed text-content-secondary">
                    You can browse the full catalogue, detection rules and playbooks without connecting.
                    Deploying infrastructure and running emulations needs a verified IAM role, because
                    those actions change resources in your own AWS account.
                </p>
            )}
        </Card>
    )
}
