/**
 * What the Attack Graph is, for someone who has not run a scan yet.
 *
 * The page's landing content, and the same text behind "What does this scan
 * show?" once scans exist. It also places the feature next to the two that
 * sound like it (the guardrail check and emulations), because "how is this
 * different from the account check?" is the first question a reader asks.
 */

import { useState } from 'react'

import { IconChevron, IconFlask, IconGraph, IconShield } from '@/components/ui/Icons'

/** Where the reader is in the four steps: 1 before connecting, 2 before a first scan. */
export type AboutStep = 1 | 2

const STEPS = [
  { title: 'Connect a read-only role', body: 'Separate from your emulation role; it can only read IAM.' },
  { title: 'Run a scan', body: 'One to four minutes for most accounts.' },
  { title: 'Review ranked paths', body: 'Most dangerous first, each step explained.' },
  { title: 'Emulate, detect, fix', body: 'Jump to the emulation, detection or guardrail for each path.' },
]

export function AboutAttackGraph({ step, showSteps = true }: { step: AboutStep; showSteps?: boolean }) {
  return (
    <div className="rounded-card border border-border bg-surface-card px-7 py-7 shadow-ring">
      <h2 className="text-xl font-medium leading-snug text-content-primary">
        See which identities could become an administrator, before an attacker does.
      </h2>
      <p className="mt-2.5 max-w-3xl text-sm leading-relaxed text-content-secondary">
        In AWS, a permission rarely stops at what it says. A developer allowed to create access keys for
        any user can create one for an admin. A pipeline allowed to edit a role&apos;s trust policy can let
        itself into that role. Attack Graph reads your account&apos;s IAM configuration and follows those
        chains to the end, then ranks every path by how much access it reaches and how easy it is to walk.
      </p>
      <p className="mt-2.5 max-w-3xl text-sm leading-relaxed text-content-secondary">
        It is the question to ask before running an emulation: not &ldquo;would this attack work&rdquo;, but
        &ldquo;which attacks does my IAM already allow&rdquo;. It needs no lab, makes no changes, and reads
        through a role that can only read.
      </p>

      <div className="mt-5 grid grid-cols-1 border-t border-border md:grid-cols-3">
        <Facts title="What it reads" items={[
          'Your account’s IAM configuration, through one read-only permission',
          'Optionally, resources in the regions you choose (adds paths through Lambda, EC2, S3)',
        ]} />
        <Facts title="What you get" divider items={[
          'Ranked escalation paths, each step explained in plain words',
          'The emulations and detections MayaTrail has for each path’s IAM calls',
          'A concrete fix per path, where Scout has one',
        ]} />
        <Facts title="What it cannot see" divider items={[
          'Organization SCPs: a path may already be blocked by one (the guardrail check can confirm)',
          'Changes made after the scan: it is a snapshot',
        ]} />
      </div>

      {showSteps && (
        <>
          <div className="mb-3 mt-7 font-mono text-2xs uppercase tracking-label text-content-dim">How it works</div>
          <ol className="relative grid grid-cols-2 gap-y-5 md:grid-cols-4">
            <span aria-hidden className="absolute left-3.5 right-3.5 top-3.5 hidden h-px bg-border md:block" />
            {STEPS.map((item, i) => {
              const n = i + 1
              const state = n < step ? 'done' : n === step ? 'now' : 'later'
              return (
                <li key={item.title} className="relative pr-5">
                  <span className={`relative z-10 flex h-7 w-7 items-center justify-center rounded-full border bg-surface-deep font-mono text-xs
                    ${state === 'done' ? 'border-safe text-safe' : ''}
                    ${state === 'now' ? 'border-accent-blue text-accent-blue ring-4 ring-accent-blue-glow' : ''}
                    ${state === 'later' ? 'border-border text-content-dim' : ''}`}
                  >
                    {n}
                  </span>
                  <div className="mt-2.5 text-sm font-semibold text-content-primary">{item.title}</div>
                  <div className="text-xs text-content-dim">{item.body}</div>
                </li>
              )
            })}
          </ol>
        </>
      )}
    </div>
  )
}

function Facts({ title, items, divider = false }: { title: string; items: string[]; divider?: boolean }) {
  return (
    <div className={`pt-4 md:pr-5 ${divider ? 'md:border-l md:border-border md:pl-5' : ''}`}>
      <h3 className="mb-1.5 text-sm font-semibold text-content-primary">{title}</h3>
      <ul className="list-disc space-y-1 pl-4 text-sm text-content-dim">
        {items.map((item) => <li key={item}>{item}</li>)}
      </ul>
    </div>
  )
}

const FIT = [
  {
    icon: IconGraph, title: 'Attack Graph', tag: 'this page',
    desc: 'Which escalation paths does my IAM already allow?',
    asks: 'Can any identity in my account end up with more access than it was given, and how?',
    when: 'First, and after IAM changes: it needs no lab and changes nothing.',
    needs: 'A read-only role with iam:GetAccountAuthorizationDetails.',
    changes: 'Nothing. It only reads.',
    gives: 'Ranked escalation paths, each step explained, with a fix.',
    link: 'The starting point. Each path links to the emulations that perform its IAM calls, their detections, and a guardrail check.',
  },
  {
    icon: IconShield, title: 'Guardrail check', tag: 'per action',
    desc: 'Would my SCPs and boundaries stop a specific attack step?',
    asks: 'For one attack, would my organisation policies or permission boundaries refuse its calls?',
    when: 'Before running an emulation, or to see whether an Attack Graph path is already blocked.',
    needs: 'Your emulation role with iam:SimulatePrincipalPolicy.',
    changes: 'Nothing. AWS answers a simulation; no call is made for real.',
    gives: 'Allowed or refused per action, and which policy refused it.',
    link: 'Attack Graph does not evaluate SCPs, so this is how you confirm whether a path it found is really open.',
  },
  {
    icon: IconFlask, title: 'Emulations', tag: 'live attack',
    desc: 'Run the attack in a lab and see which of my detections fire.',
    asks: 'If this attack really happened, would my SIEM catch it?',
    when: 'After you know which paths matter, to prove detection end to end.',
    needs: 'Your emulation role, which deploys a lab and runs the attack in it.',
    changes: 'Creates lab resources for the run, then removes them.',
    gives: 'The attack’s real CloudTrail trail, and which detections fired or stayed silent.',
    link: 'Each Attack Graph path names the emulations that perform the same IAM calls, so a path on paper becomes a rehearsal in a lab.',
  },
]

/** The three related features, each opening to the same facts so they compare like for like. */
export function PlatformFit() {
  const [open, setOpen] = useState<number | null>(null)
  return (
    <section className="mt-7">
      <div className="mb-2.5 font-mono text-2xs uppercase tracking-label text-content-dim">
        How it fits with the rest of MayaTrail
      </div>
      <div className="divide-y divide-border rounded-card border border-border bg-surface-card px-5 py-1 shadow-ring">
        {FIT.map((item, i) => {
          const Icon = item.icon
          const isOpen = open === i
          return (
            <div key={item.title}>
              <button
                type="button"
                onClick={() => setOpen(isOpen ? null : i)}
                aria-expanded={isOpen}
                className="flex w-full items-center gap-3.5 bg-transparent py-3.5 text-left transition-opacity hover:opacity-60"
              >
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-btn bg-surface-elevated text-content-secondary">
                  <Icon size={16} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-semibold text-content-primary">{item.title}</span>
                  <span className="block text-xs text-content-dim">{item.desc}</span>
                </span>
                <span className="rounded-btn border border-border px-2 font-mono text-2xs text-content-dim">{item.tag}</span>
                <IconChevron size={14} className={`text-content-dim transition-transform ${isOpen ? 'rotate-90' : ''}`} />
              </button>
              {isOpen && (
                <dl className="grid animate-fadeSlideIn grid-cols-1 gap-x-6 gap-y-3.5 pb-4 pl-12 md:grid-cols-3">
                  <Fact wide label="The question it answers" value={item.asks} />
                  <Fact label="When to use it" value={item.when} />
                  <Fact label="What it needs" value={item.needs} />
                  <Fact label="What it changes" value={item.changes} />
                  <Fact wide label="What you get" value={item.gives} />
                  <Fact wide label="How it connects to Attack Graph" value={item.link} />
                </dl>
              )}
            </div>
          )
        })}
      </div>
    </section>
  )
}

function Fact({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={wide ? 'md:col-span-3' : ''}>
      <dt className="mb-0.5 font-mono text-2xs uppercase tracking-label text-content-dim">{label}</dt>
      <dd className="text-xs text-content-secondary">{value}</dd>
    </div>
  )
}
