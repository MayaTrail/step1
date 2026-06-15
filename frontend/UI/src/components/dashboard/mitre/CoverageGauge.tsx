import { PolarAngleAxis, RadialBar, RadialBarChart } from 'recharts'
import { STATUS_HEX, statusOf } from './status'

/**
 * Radial coverage gauge — the hero number of the summary band.
 *
 * A single-arc RadialBar over a 0-100 angle axis, coloured by coverage status,
 * with the percentage rendered in the centre.  Fixed size so it reads crisply.
 */
export function CoverageGauge({ pct }: { pct: number }) {
    const color = STATUS_HEX[statusOf(pct)]
    const data = [{ value: pct, fill: color }]

    return (
        <div className="relative shrink-0" style={{ width: 132, height: 132 }}>
            <RadialBarChart
                width={132}
                height={132}
                innerRadius="74%"
                outerRadius="100%"
                data={data}
                startAngle={90}
                endAngle={-270}
            >
                <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                <RadialBar dataKey="value" cornerRadius={8} background={{ fill: '#1b1c1e' }} />
            </RadialBarChart>
            <span className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="font-display text-3xl font-bold tabular-nums leading-none text-content-primary">
                    {pct}%
                </span>
                <span className="font-mono text-2xs uppercase tracking-label text-content-muted mt-1">
                    Coverage
                </span>
            </span>
        </div>
    )
}
