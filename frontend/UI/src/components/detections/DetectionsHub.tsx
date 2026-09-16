import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { useEmulations } from '@/hooks/usePlatformData'
import { LibraryCard } from '@/components/common/LibraryCard'
import { LibraryToolbar } from '@/components/common/LibraryToolbar'
import { useLibraryFilter, emulationTactics } from '@/components/common/useLibraryFilter'
import { LibraryEmpty } from '@/components/emulations/EmulationsHub'
import { IconSearch } from '@/components/ui/Icons'
import { listAuthoredDetections } from '@/services/authoredDetection.service'
import type { AuthoredDetectionListItem } from '@/types'

/**
 * Detections content hub — detection-engineering discovery library.
 *
 * Detection rules (SIGMA + KQL) are authored per emulation, so each card
 * represents an emulation and links into its existing scoped detections page.
 * No rule data is duplicated here.
 */
export function DetectionsHub() {
  const { data: emulations, loading } = useEmulations('aws')
  const { filtered, toolbar } = useLibraryFilter(emulations ?? [])

  const [mine, setMine] = useState<AuthoredDetectionListItem[] | null>(null)
  useEffect(() => {
    let cancelled = false
    listAuthoredDetections({ mine: true })
      .then((rows) => !cancelled && setMine(rows))
      .catch(() => !cancelled && setMine([]))
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
        <div>
          <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
            Security Content
          </div>
          <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
            Detections
          </div>
          <div className="text-[0.9rem] text-content-secondary mt-1.5">
            Browse SIGMA and KQL detection coverage by emulation
          </div>
        </div>
        <Link
          to="/detections/studio/new"
          className="bg-accent-blue text-button-fg rounded-btn px-4 py-2 text-[0.85rem] font-medium"
        >
          New rule
        </Link>
      </div>

      {/* ── Rules this user authored or generated ─────────────────────── */}
      {mine !== null && mine.length > 0 && (
        <section className="mb-8">
          <h2 className="font-mono text-[0.7rem] uppercase tracking-[2px] text-content-dim mb-3">
            Your detections
          </h2>
          <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(300px,1fr))]">
            {mine.map((d) => (
              <Link
                key={d.id}
                to={`/detections/studio/${d.id}`}
                className="block border border-border-subtle rounded-card bg-surface-card p-4 hover:border-border-active transition-colors"
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="font-mono text-[0.6rem] uppercase tracking-[1px] text-content-dim">
                    {d.is_generated ? 'AI-drafted' : 'Authored'}
                  </span>
                  {d.technique_id && (
                    <span className="font-mono text-[0.6rem] text-accent-blue">{d.technique_id}</span>
                  )}
                  {d.last_fidelity != null && (
                    <span className="font-mono text-[0.6rem] text-content-dim ml-auto">
                      fidelity {Math.round(d.last_fidelity * 100)}%
                    </span>
                  )}
                </div>
                <div className="text-[0.95rem] font-medium text-content-primary leading-snug">
                  {d.title}
                </div>
                {d.summary && (
                  <div className="text-[0.82rem] text-content-secondary mt-1 line-clamp-2">
                    {d.summary}
                  </div>
                )}
              </Link>
            ))}
          </div>
        </section>
      )}

      <h2 className="font-mono text-[0.7rem] uppercase tracking-[2px] text-content-dim mb-3">
        Shipped detections
      </h2>

      {/* Announce the converter at the section level. Its controls live one
          click in, on each emulation's detections page and on a run's coverage
          page, but the capability itself was invisible from here - a user had
          no way to know the product converts detections at all. */}
      <div className="mb-6 flex items-start gap-3 rounded-card border border-accent-blue/30 bg-accent-blue/[0.06] px-4 py-3">
        <IconSearch size={18} className="mt-0.5 shrink-0 text-accent-blue" />
        <div className="text-[0.85rem] text-content-secondary leading-relaxed">
          <span className="font-semibold text-content-primary">
            Export any detection to your SIEM.
          </span>{' '}
          Open an emulation below and compile its rules into Splunk SPL or
          OpenSearch/Wazuh Lucene &mdash; or, after a run, export only the rules
          that stayed silent from its coverage report.
        </div>
      </div>

      <LibraryToolbar {...toolbar} searchPlaceholder="Search detections..." />

      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading detections...</div>
      ) : filtered.length === 0 ? (
        <LibraryEmpty noun="detections" />
      ) : (
        <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
          {filtered.map((em) => (
            <LibraryCard
              key={em.id}
              name={em.name}
              eyebrow="SIGMA + KQL · Detections"
              severity={em.severity}
              description={em.description}
              tactics={emulationTactics(em)}
              actions={[
                {
                  label: 'View & export detections',
                  icon: <IconSearch size={14} />,
                  to: `/aws/emulations/${em.id}/detections`,
                  variant: 'secondary',
                },
              ]}
            />
          ))}
        </div>
      )}
    </div>
  )
}
