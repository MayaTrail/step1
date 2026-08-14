import { useMemo, useState } from 'react'
import { useGuardrails } from '@/hooks/usePlatformData'
import type { GuardrailPolicy, GuardrailType } from '@/types'
import { LibraryCard } from '@/components/common/LibraryCard'
import { LibraryEmpty } from '@/components/emulations/EmulationsHub'
import { SearchInput } from '@/components/ui/SearchInput'
import { FilterDropdown, type DropdownOption } from '@/components/ui/FilterDropdown'
import { IconShield } from '@/components/ui/Icons'
import { ComingSoon } from '@/components/common/ComingSoon'

type TypeFilter = 'all' | GuardrailType

const TYPE_OPTIONS: DropdownOption<TypeFilter>[] = [
  { value: 'all', label: 'All policies' },
  { value: 'SCP', label: 'SCP' },
  { value: 'RCP', label: 'RCP' },
]

/**
 * Guardrails content hub — preventive-control discovery library.
 *
 * Mirrors the Emulations / Detections hubs: a search + filter toolbar over a
 * grid of library cards. Each card is one Service Control Policy or Resource
 * Control Policy; the service tags reuse the card's chip slot, and the action
 * opens the policy document on the scoped guardrails page.
 *
 * The library is served by /api/guardrails/ and is AWS-only today.
 */
export function GuardrailsHub() {
  const { data: library, loading } = useGuardrails('aws')
  const [search, setSearch] = useState('')
  const [type, setType] = useState<TypeFilter>('all')

  const all: GuardrailPolicy[] = useMemo(
    () => [...(library?.scp ?? []), ...(library?.rcp ?? [])],
    [library],
  )

  const filtered = useMemo(() => {
    let list = all
    if (type !== 'all') list = list.filter((g) => g.type === type)
    const q = search.trim().toLowerCase()
    if (q) {
      list = list.filter(
        (g) =>
          g.name.toLowerCase().includes(q) ||
          g.purpose.toLowerCase().includes(q) ||
          g.services.some((s) => s.toLowerCase().includes(q)),
      )
    }
    return list
  }, [all, search, type])

  return (
    <div>
      <div className="mb-6">
        <div className="font-mono text-[0.7rem] uppercase tracking-[2px] text-accent-blue font-medium mb-2">
          Security Content
        </div>
        <div className="font-display text-[1.8rem] font-[800] text-content-primary leading-tight tracking-[-1px]">
          Guardrails
        </div>
        <div className="text-[0.9rem] text-content-secondary mt-1.5">
          {library
            ? `${library.totalCount} preventive policies · ${library.formats}`
            : 'Preventive controls and hardening recommendations'}
        </div>
      </div>

      {loading ? (
        <div className="text-center py-16 text-content-dim font-mono text-sm">Loading guardrails...</div>
      ) : !library || library.totalCount === 0 ? (
        <ComingSoon
          icon={<IconShield size={32} />}
          title="Guardrails coming soon"
          body="Preventive controls, mapped services, and risk-reduction scoring will appear here once guardrail content is available."
        />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-3 mb-5">
            <SearchInput value={search} onChange={setSearch} placeholder="Search guardrails..." />
            <FilterDropdown label="Policy" value={type} options={TYPE_OPTIONS} onChange={setType} />
          </div>

          {filtered.length === 0 ? (
            <LibraryEmpty noun="guardrails" />
          ) : (
            <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(320px,1fr))]">
              {filtered.map((g) => (
                <LibraryCard
                  key={g.id}
                  name={g.name}
                  eyebrow={`${g.type} · AWS Guardrail`}
                  description={g.purpose}
                  tactics={g.services}
                  actions={[
                    {
                      label: 'View Policy',
                      icon: <IconShield size={14} />,
                      to: `/aws/guardrails/${g.id}`,
                      variant: 'secondary',
                    },
                  ]}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}
