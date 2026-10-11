/**
 * The two ways to read a scan, and where their identities come from.
 *
 * Shown on the overview under the feature's introduction, and behind "How
 * these differ" beside the Scans page tabs, so the same words answer the same
 * question in both places.
 */

const WAYS = [
  {
    title: 'Ranked paths',
    question: 'What is most dangerous in my account?',
    facts: [
      ['Who picks', 'Scout. It scores every escalation path it finds and keeps the 25 riskiest.'],
      ['Starts from', 'Where several identities lead to the same target, the one closest to it, so paths stay short.'],
      ['Shows', 'Each path with its risk score, its steps, a fix, and the emulations that rehearse it.'],
      ['Use it', 'First, after every scan.'],
    ],
  },
  {
    title: 'What can an identity reach?',
    question: 'How far can this one identity get?',
    facts: [
      ['Who picks', 'You. Choose any user or role in the scan.'],
      ['Starts from', 'The identity you chose, even one no ranked path starts from.'],
      ['Shows', 'Every identity it can become, worst first, with the shortest way to each.'],
      ['Use it', 'When you already have a suspect: leaked keys, a new contractor role, a CI role.'],
    ],
  },
]

export function TwoWays() {
  return (
    <>
      <div className="grid grid-cols-1 border-t border-border md:grid-cols-2">
        {WAYS.map((way, i) => (
          <div key={way.title} className={`pt-4 md:pr-5 ${i > 0 ? 'mt-4 border-t border-border md:mt-0 md:border-l md:border-t-0 md:pl-5' : ''}`}>
            <h3 className="text-sm font-semibold text-content-primary">{way.title}</h3>
            <p className="mb-2.5 mt-0.5 text-sm text-content-secondary">{way.question}</p>
            <dl className="grid grid-cols-4 gap-x-3 gap-y-1.5 text-xs">
              {way.facts.map(([label, value]) => (
                <div key={label} className="contents">
                  <dt className="pt-0.5 font-mono text-2xs uppercase tracking-label text-content-dim">{label}</dt>
                  <dd className="col-span-3 text-content-secondary">{value}</dd>
                </div>
              ))}
            </dl>
          </div>
        ))}
      </div>
      <p className="mt-4 border-t border-border pt-3 text-xs text-content-dim">
        <span className="font-semibold text-content-secondary">Where the identities come from.</span> Every IAM user and
        role Scout read through your audit role when the scan ran, with the escalation steps between them. Both views
        read that copy, stored with the scan: nothing is read from AWS again and nothing in your account changes.
      </p>
    </>
  )
}

/** The overview's section: a heading over the explanation in a card. */
export function TwoWaysSection() {
  return (
    <section>
      <div className="mb-2.5 font-mono text-2xs uppercase tracking-label text-content-dim">Two ways to read a scan</div>
      <div className="rounded-card border border-border bg-surface-card px-6 pb-5 pt-1 shadow-ring">
        <TwoWays />
      </div>
    </section>
  )
}
