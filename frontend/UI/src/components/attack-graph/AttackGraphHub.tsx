/**
 * The Attack Graph overview.
 *
 * What the feature is, how it fits with the rest of the platform, and the
 * read-only Scout role it needs. Once connected, one card says where the
 * latest scan stands and links to it; running scans and reading paths happen
 * on the Scans page.
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'

import { useScoutConnection } from '@/components/common/ConnectGate'
import { useAuth } from '@/context/AuthContext'

import { AboutAttackGraph, PlatformFit } from './AboutAttackGraph'
import { LatestScanCard } from './LatestScanCard'
import { ScoutConnectPanel } from './ScoutConnectPanel'
import { TwoWaysSection } from './TwoWays'
import { scanUrl, useScanList } from './useScans'

export function AttackGraphHub() {
  const { connected } = useScoutConnection()
  const { user } = useAuth()
  const [managing, setManaging] = useState(false)
  const scans = useScanList(connected)
  const regions = user?.auditRegions ?? []

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-2 font-mono text-2xs uppercase tracking-label text-accent-blue">Security content</div>
          <h1 className="font-display text-2xl font-semibold leading-tight text-content-primary">Attack Graph</h1>
          <p className="mt-1.5 max-w-3xl text-sm text-content-secondary">
            Every way an identity in your AWS account could end up with more access than it was given, found by
            reading your IAM configuration. Nothing runs in your account.
          </p>
        </div>
        {connected && (
          <div className="flex flex-col items-end gap-1.5">
            <Link
              to={scanUrl()}
              className="rounded-pill bg-white/80 px-4 py-1.5 text-xs font-semibold text-button-fg no-underline transition-opacity hover:opacity-60"
            >
              Open scans
            </Link>
            <button
              type="button"
              onClick={() => setManaging((open) => !open)}
              className="bg-transparent p-0 text-xs text-content-dim transition-opacity hover:opacity-60"
            >
              Scout role connected · {regions.length ? `${regions.length} region${regions.length > 1 ? 's' : ''}` : 'IAM only'} ·{' '}
              <span className="text-accent-blue">{managing ? 'Close' : 'Manage'}</span>
            </button>
          </div>
        )}
      </div>

      {connected ? (
        <div className="space-y-5">
          {managing && <ScoutConnectPanel manage onDone={() => setManaging(false)} />}
          <LatestScanCard scans={scans} />
          <AboutAttackGraph step={2} />
          <TwoWaysSection />
          <PlatformFit />
        </div>
      ) : (
        <div className="space-y-7">
          <AboutAttackGraph step={1} />
          <TwoWaysSection />
          <PlatformFit />
          <ScoutConnectPanel />
        </div>
      )}
    </div>
  )
}
