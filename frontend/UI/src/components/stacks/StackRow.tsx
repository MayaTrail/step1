import type { Stack } from '@/types'
import { Badge } from '@/components/ui/Badge'
import { IconChevron } from '@/components/ui/Icons'
import {
    deriveHealth,
    STACK_HEALTH,
    formatAge,
    emulationLabel,
} from '@/components/dashboard/stackHelpers'
import { formatDuration, PHASE_LABEL } from './LifecycleTrack'
import { TtlCountdown } from './TtlCountdown'

/**
 * One stack on one line. The whole row opens the detail panel.
 *
 * A card per stack cost roughly two hundred pixels of height each, so a dozen
 * stacks meant a page nobody could scan and a filter bar that scrolled away.
 * Everything a card carried now lives in the panel; the row keeps only what
 * answers "which stack is this and is it healthy", plus the current phase and
 * how long it has been there, because that is the question the page exists for
 * and it should not need a click.
 */

interface StackRowProps {
    stack: Stack
    isBusy: boolean
    onOpen: () => void
}

export function StackRow({ stack, isBusy, onOpen }: StackRowProps) {
    const health = deriveHealth(stack)
    const meta = STACK_HEALTH[health]

    // The open phase is the last recorded one; its duration is still counting.
    const current = stack.lifecycle?.[stack.lifecycle.length - 1]
    const phaseLabel = current ? PHASE_LABEL[current.status] ?? current.status : ''
    const phaseTime = current ? formatDuration(current.seconds) : ''


    return (
        /*
         * Hover changes the content, not the container. The design system asks
         * for opacity and emphasis over background swaps, and a filled rectangle
         * across a row inside a rounded card is what that rule exists to stop.
         */
        <tr
            onClick={onOpen}
            className="group border-t border-border align-middle cursor-pointer"
        >
            <td className="py-3 pr-3">
                <span className="flex items-center gap-1.5">
                    <span className="text-xs font-medium tracking-body text-content-primary
                        transition-colors group-hover:text-accent-blue truncate">
                        {stack.name}
                    </span>
                    <span className="text-accent-blue opacity-0 -translate-x-1 transition-all
                        group-hover:opacity-100 group-hover:translate-x-0">
                        <IconChevron size={12} />
                    </span>
                </span>
                <span className="block font-mono text-2xs text-content-muted mt-0.5 truncate">
                    {stack.emulation_type ? emulationLabel(stack.emulation_type) : 'Infrastructure Stack'}
                </span>
            </td>

            <td className="py-3 pr-3 whitespace-nowrap">
                <Badge tone={meta.tone} mono dot pulse={meta.pulse || isBusy}>
                    {meta.label}
                </Badge>
            </td>

            <td className="py-3 pr-3 whitespace-nowrap">
                {phaseLabel ? (
                    <>
                        <span className={`block text-xs ${
                            current?.status === 'failed' ? 'text-danger'
                                : current?.current ? 'text-accent-blue'
                                    : 'text-content-secondary'
                        }`}>
                            {phaseLabel}
                        </span>
                        <span className={`block font-mono text-2xs mt-0.5 ${
                            current?.slow ? 'text-warning' : 'text-content-muted'
                        }`}>
                            {phaseTime}
                        </span>
                    </>
                ) : (
                    <span className="font-mono text-2xs text-content-muted">not recorded</span>
                )}
            </td>

            <td className="py-3 pr-3 font-mono text-2xs text-content-secondary whitespace-nowrap">
                {stack.region}
            </td>

            <td className="py-3 pr-3 font-mono text-2xs text-content-secondary whitespace-nowrap truncate max-w-[140px]">
                {stack.owner}
            </td>

            <td className="py-3 pr-3 font-mono text-2xs whitespace-nowrap text-right">
                <TtlCountdown expiresAt={stack.expires_at} />
            </td>

            <td className="py-3 font-mono text-2xs text-content-muted whitespace-nowrap text-right">
                {formatAge(stack.updated_at)} ago
            </td>
        </tr>
    )
}
