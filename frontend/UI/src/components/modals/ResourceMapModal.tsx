/**
 * ResourceMapModal — shows a stack's resource topology in a focused dialog.
 *
 * The inline graph tab scaled the whole map to fit the card, which made nodes
 * unreadable for resource-heavy emulations (e.g. DangerDev, 65 resources). This
 * dialog gives the map a large viewport and renders it at natural node size, so
 * the user scrolls left-right / up-down through a readable topology instead of
 * squinting at a shrunk-to-fit single page.
 *
 * InfraGraphView is lazy-loaded (it pulls in the dagre layout library) so the
 * chunk is only fetched when the user actually opens the map.
 */

import { Suspense, lazy } from 'react'
import type { Stack } from '@/types'

const InfraGraphView = lazy(() =>
  import('@/components/stacks/InfraGraphView').then((m) => ({ default: m.InfraGraphView })),
)

interface ResourceMapModalProps {
  stack: Stack
  onClose: () => void
}

export function ResourceMapModal({ stack, onClose }: ResourceMapModalProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="bg-surface-card border border-border rounded-card shadow-2xl flex flex-col"
        style={{ width: 'min(1100px, 94vw)', maxHeight: '90vh' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border shrink-0">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[1.5px] text-content-dim mb-1">
              Resource Map
            </div>
            <div className="font-display text-[1.1rem] font-bold text-content-primary leading-tight">
              {stack.name}
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-content-dim hover:text-content-primary transition-colors text-xl leading-none cursor-pointer bg-transparent border-none p-1"
          >
            &#10005;
          </button>
        </div>

        {/* Body — InfraGraphView owns the scrollable canvas inside */}
        <div className="px-6 py-5 overflow-hidden flex-1">
          <Suspense
            fallback={
              <div className="flex items-center gap-2 text-content-dim font-mono text-xs py-8 justify-center">
                <span className="inline-block w-3 h-3 border-2 border-accent-blue border-t-transparent rounded-full animate-spin" />
                Loading map…
              </div>
            }
          >
            <InfraGraphView stack={stack} />
          </Suspense>
        </div>
      </div>
    </div>
  )
}
