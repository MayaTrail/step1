import { Link } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { Card } from '@/components/ui/Card'
import { IconCloud } from '@/components/ui/Icons'

/**
 * Whether the signed-in user has a verified AWS connection.
 *
 * The single place the frontend asks this question, so the answer cannot drift
 * between the several surfaces that gate on it. Mirrors the backend's
 * HasAWSConnection: reads are open to everyone, changing anything is not.
 */
export function useAWSConnection(): { connected: boolean } {
  const { user } = useAuth()
  return { connected: Boolean(user?.isVerified || user?.isDemo) }
}

/**
 * Replaces a page whose content requires an AWS connection.
 *
 * Shown instead of an error or an unexplained empty grid. An unconnected user
 * reaching Stacks has done nothing wrong, so the page states what is missing and
 * links to the fix rather than looking broken.
 */
export function ConnectPrompt({
  title,
  body,
}: {
  title: string
  body: string
}) {
  return (
    <Card accent="red" className="p-8 text-center">
      <span className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-btn border border-danger/20 bg-danger/10 text-danger">
        <IconCloud size={24} />
      </span>
      <div className="font-display text-lg font-semibold text-content-primary">{title}</div>
      <p className="mx-auto mt-2 max-w-md text-[0.9rem] leading-relaxed text-content-secondary">
        {body}
      </p>
      <Link
        to="/me"
        className="mt-5 inline-block rounded-btn border border-danger/30 bg-danger/10 px-4 py-2 text-[13px] font-semibold text-danger no-underline transition-opacity hover:opacity-60"
      >
        Connect AWS account
      </Link>
    </Card>
  )
}

/**
 * Wraps an action that mutates AWS, disabling it when no account is connected.
 *
 * Renders the action untouched for a connected user. Otherwise it renders a
 * disabled look-alike with the reason attached, so the user learns why before
 * clicking rather than from a 403 afterwards.
 *
 * The backend refuses the request either way; this only decides whether the
 * refusal is a surprise.
 */
export function ConnectGate({
  children,
  label = 'Connect your AWS account to run this',
}: {
  children: React.ReactNode
  label?: string
}) {
  const { connected } = useAWSConnection()
  if (connected) return <>{children}</>

  return (
    <span
      title={label}
      aria-disabled="true"
      className="inline-flex cursor-not-allowed opacity-40 [&_a]:pointer-events-none [&_button]:pointer-events-none"
    >
      {children}
    </span>
  )
}
