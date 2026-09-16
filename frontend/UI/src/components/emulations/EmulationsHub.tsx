import { useEffect, useMemo, useState } from 'react'
import { useEmulations } from '@/hooks/usePlatformData'
import type { Emulation } from '@/types'
import { LibraryCard } from '@/components/common/LibraryCard'
import { LibraryToolbar } from '@/components/common/LibraryToolbar'
import { useLibraryFilter, emulationTactics } from '@/components/common/useLibraryFilter'
import { platformShortLabel } from '@/data'
import { listStacks } from '@/services/stack.service'
import { RunEmulationModal } from '@/components/modals/RunEmulationModal'
import { IconLaunch } from '@/components/ui/Icons'
import { useAWSConnection } from '@/components/common/ConnectGate'

/**
 * Emulations content hub — a cross-platform card library of every emulation
 * the platform supports. Each card runs its emulation via the existing modal.
 *
 * The backend catalogue is AWS-only today (fetchEmulations returns the whole
 * list regardless of platform), so the Platform filter shows real content for
 * AWS and an empty result for the others.
 */
export function EmulationsHub() {
  const { connected } = useAWSConnection()
  const { data: emulations, loading } = useEmulations('aws')
  const { filtered, toolbar } = useLibraryFilter(emulations ?? [])
  const [runTarget, setRunTarget] = useState<Emulation | null>(null)

  // Set of emulation_types the user has a stack for. Lets the "Has stack"
  // toggle answer "which emulation did I just deploy?" without the user needing
  // to remember its name. A stack's emulation_type is the same slug as the
  // emulation id, so membership is a direct id lookup.
  const [deployedTypes, setDeployedTypes] = useState<Set<string>>(new Set())
  const [hasStackOnly, setHasStackOnly] = useState(false)

  useEffect(() => {
    let cancelled = false
    listStacks()
      .then((stacks) => {
        if (cancelled) return
        setDeployedTypes(
          new Set(stacks.map((s) => s.emulation_type).filter((t): t is string => !!t)),
        )
      })
      .catch(() => {
        // Non-fatal: if stacks fail to load the toggle simply yields no matches.
      })
    return () => { cancelled = true }
  }, [])

  const visible = useMemo(
    () => (hasStackOnly ? filtered.filter((em) => deployedTypes.has(em.id)) : filtered),
    [filtered, hasStackOnly, deployedTypes],
  )

  return (
    <div>
      {/* Page header */}
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Security Content
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Emulations
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          {(emulations?.length ?? 0)} emulations available &middot; Browse the full library across platforms
        </div>
      </div>

      <LibraryToolbar
        {...toolbar}
        searchPlaceholder="Search emulations..."
        showType
        extra={
          <StackToggleChip
            active={hasStackOnly}
            count={deployedTypes.size}
            onClick={() => setHasStackOnly((v) => !v)}
          />
        }
      />

      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading emulations...</div>
      ) : visible.length === 0 ? (
        <LibraryEmpty noun="emulations" />
      ) : (
        <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
          {visible.map((em) => (
            <LibraryCard
              key={em.id}
              name={em.name}
              eyebrow={`${em.originLabel || 'Emulation'} · ${platformShortLabel(em.platform)}`}
              severity={em.severity}
              description={em.description}
              tactics={emulationTactics(em)}
              actions={[
                { label: 'View Emulation', to: `/aws/emulations/${em.id}`, variant: 'secondary' },
                {
                  label: 'Run',
                  icon: <IconLaunch size={14} />,
                  onClick: () => setRunTarget(em),
                  variant: 'primary',
                  disabled: !connected,
                  disabledReason: 'Connect your AWS account to run this',
                },
              ]}
            />
          ))}
        </div>
      )}

      {runTarget && (
        <RunEmulationModal
          emulationId={runTarget.id}
          emulationName={runTarget.name}
          onClose={() => setRunTarget(null)}
        />
      )}
    </div>
  )
}

/**
 * Toggle chip that narrows the library to emulations the user has a stack for.
 * A binary filter reads more clearly as a pill that shows its own on/off state
 * than as another dropdown. `count` surfaces how many stacks back the filter so
 * an empty toggle result is self-explanatory (0 = nothing deployed yet).
 */
function StackToggleChip({ active, count, onClick }: { active: boolean; count: number; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      aria-pressed={active}
      title="Show only emulations you have deployed a stack for"
      className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm cursor-pointer transition-colors
        ${active
          ? 'bg-accent-blue/[0.08] border-accent-blue/40 text-accent-blue'
          : 'bg-surface-elevated border-border text-content-secondary hover:border-border-active hover:text-content-primary'
        }`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${active ? 'bg-accent-blue' : 'bg-content-dim'}`} />
      Has stack
      {count > 0 && <span className="font-mono text-[10px] text-content-dim">{count}</span>}
    </button>
  )
}

/** Shared "no results" state for the library hubs. */
export function LibraryEmpty({ noun }: { noun: string }) {
  return (
    <div className="text-center py-16">
      <div className="font-display text-base text-content-primary mb-1.5">No {noun} match your filters</div>
      <div className="text-[0.9rem] text-content-secondary">Try clearing the search or filters.</div>
    </div>
  )
}
