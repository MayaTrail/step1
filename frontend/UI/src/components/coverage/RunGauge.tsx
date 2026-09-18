import type { CoverageRun } from '@/types/coverageHistory'

/**
 * One workflow run as a gauge.
 *
 * The fired share leads the ring in green, what stayed silent trails it in
 * amber, and whatever was never judged is left as bare track. Arc colour is
 * fixed rather than driven by the target, so a run that only caught one
 * detection still draws that success in green; the numeral carries the verdict
 * against target instead. One meaning per channel.
 *
 * A run nothing reached draws a dashed empty ring and a dash for a figure,
 * never a zero, which would read as a total detection failure rather than as
 * a run that was never scored.
 */

interface RunGaugeProps {
    run: CoverageRun
    /** Reliability percentage a run is expected to meet, for the numeral colour. */
    target: number
    /** Larger ring and heavier stroke for the selected run. */
    emphasis?: boolean
}

const SIZE_BASE = 62
const SIZE_EMPHASIS = 70

/** Colour for the numeral: the run's verdict against the target. */
function numeralColor(coverage: number | null, target: number): string {
    if (coverage === null) return 'var(--content-muted)'
    if (coverage >= target) return '#5fc992'
    if (coverage >= 50) return '#ffbc33'
    return '#FF6363'
}

export function RunGauge({ run, target, emphasis = false }: RunGaugeProps) {
    const size = emphasis ? SIZE_EMPHASIS : SIZE_BASE
    const stroke = emphasis ? 7 : 6
    const radius = size / 2 - 5
    const centre = size / 2
    const circumference = 2 * Math.PI * radius

    const firedShare = run.ruleCount ? run.fired / run.ruleCount : 0
    const silentShare = run.ruleCount ? run.silent / run.ruleCount : 0

    return (
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
            <circle
                cx={centre}
                cy={centre}
                r={radius}
                fill="none"
                stroke="rgba(255,255,255,0.06)"
                strokeWidth={stroke}
                strokeDasharray={run.judged ? undefined : '3 4'}
            />
            {run.judged && (
                <g transform={`rotate(-90 ${centre} ${centre})`}>
                    {silentShare > 0 && (
                        <circle
                            cx={centre}
                            cy={centre}
                            r={radius}
                            fill="none"
                            stroke="#ffbc33"
                            strokeWidth={stroke}
                            strokeDasharray={`${silentShare * circumference} ${circumference}`}
                            strokeDashoffset={-firedShare * circumference}
                            opacity={0.8}
                        />
                    )}
                    {firedShare > 0 && (
                        <circle
                            cx={centre}
                            cy={centre}
                            r={radius}
                            fill="none"
                            stroke="#5fc992"
                            strokeWidth={stroke}
                            strokeDasharray={`${firedShare * circumference} ${circumference}`}
                            strokeLinecap="round"
                        />
                    )}
                </g>
            )}
            <text
                x={centre}
                y={centre + 5}
                textAnchor="middle"
                fontSize={run.judged ? (emphasis ? 16 : 14) : 14}
                fontWeight={600}
                fill={numeralColor(run.coverage, target)}
                style={{ fontVariantNumeric: 'tabular-nums' }}
            >
                {run.coverage === null ? '--' : run.coverage}
            </text>
        </svg>
    )
}
