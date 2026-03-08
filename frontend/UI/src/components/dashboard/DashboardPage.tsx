import { useMemo } from 'react'
import { platformRegistry, getPlatformData } from '@/data'

export function DashboardPage() {
  const stats = useMemo(() => {
    let totalEmulations = 0
    let totalTechniques = 0
    for (const meta of platformRegistry) {
      const data = getPlatformData(meta.id)
      if (data?.emulations) {
        totalEmulations += data.emulations.length
        for (const em of data.emulations) {
          totalTechniques += em.techniqueCount
        }
      }
    }
    return { totalEmulations, totalTechniques }
  }, [])

  return (
    <div>
      {/* Hero — frontend-style with danger accents */}
      <div className="border border-border rounded-card bg-surface-base p-8 mb-7 relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none"
          style={{
            background: 'radial-gradient(circle at 30% 50%, rgba(255,34,68,0.06), transparent 60%), radial-gradient(circle at 70% 50%, rgba(0,180,216,0.06), transparent 60%)',
          }} />
        {/* Decorative dots — right side */}
        <div className="absolute right-8 top-1/2 -translate-y-1/2 pointer-events-none select-none">
          <span className="absolute w-2 h-2 rounded-full bg-danger opacity-60" style={{ top: -30, right: 0 }} />
          <span className="absolute w-1.5 h-1.5 rounded-full bg-safe opacity-50" style={{ top: -18, right: 28 }} />
          <span className="absolute w-2.5 h-2.5 rounded-full bg-danger opacity-40" style={{ top: 2, right: 12 }} />
          <span className="absolute w-1.5 h-1.5 rounded-full bg-safe opacity-60" style={{ top: -6, right: 52 }} />
          <span className="absolute w-2 h-2 rounded-full bg-safe opacity-35" style={{ top: 18, right: 38 }} />
          <span className="absolute w-1 h-1 rounded-full bg-danger opacity-50" style={{ top: 10, right: 68 }} />
          <span className="absolute w-2 h-2 rounded-full bg-danger opacity-30" style={{ top: -36, right: 40 }} />
          <span className="absolute w-1.5 h-1.5 rounded-full bg-safe opacity-45" style={{ top: 26, right: 8 }} />
          <span className="absolute w-1 h-1 rounded-full bg-danger opacity-55" style={{ top: -44, right: 20 }} />
          <span className="absolute w-2 h-2 rounded-full bg-safe opacity-30" style={{ top: -40, right: 65 }} />
          <span className="absolute w-1.5 h-1.5 rounded-full bg-danger opacity-45" style={{ top: 30, right: 60 }} />
          <span className="absolute w-1 h-1 rounded-full bg-safe opacity-55" style={{ top: 36, right: 24 }} />
          <span className="absolute w-2 h-2 rounded-full bg-danger opacity-35" style={{ top: -12, right: 82 }} />
          <span className="absolute w-1.5 h-1.5 rounded-full bg-safe opacity-40" style={{ top: 14, right: 95 }} />
          <span className="absolute w-2.5 h-2.5 rounded-full bg-danger opacity-25" style={{ top: -50, right: 50 }} />
          <span className="absolute w-1 h-1 rounded-full bg-safe opacity-50" style={{ top: 40, right: 48 }} />
          <span className="absolute w-1.5 h-1.5 rounded-full bg-danger opacity-40" style={{ top: 22, right: 80 }} />
          <span className="absolute w-2 h-2 rounded-full bg-safe opacity-30" style={{ top: -24, right: 100 }} />
        </div>
        <div className="relative z-[1]">
          <div className="inline-flex items-center gap-2 bg-danger/[0.15] border border-danger/30 rounded-full px-4 py-1 font-mono text-[0.75rem] text-danger mb-4 tracking-[0.5px] font-medium">
            <span className="w-2 h-2 rounded-full bg-danger animate-pulse" />
            APT EMULATION PLATFORM
          </div>
          <h1 className="font-display text-[2.2rem] font-[900] text-content-primary mb-3 tracking-[-1px] leading-[1.1]">
            Welcome to <span className="text-gradient-danger">MayaTrail</span>
          </h1>
          <p className="text-content-secondary max-w-[720px] leading-[1.7] text-[0.95rem]">
            Proactively defend your cloud infrastructure by emulating real-world APT techniques.<br />
            Test your detections, validate your playbooks, and strengthen your security posture.
          </p>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-6 mb-7">
        <StatCard value={stats.totalEmulations} label="APT Emulations" colorClass="text-danger" />
        <StatCard value={stats.totalTechniques} label="MITRE Techniques" colorClass="text-accent-blue" />
        <StatCard value={212} label="Detection Rules" colorClass="text-safe" />
        <StatCard value={5} label="Cloud Platforms" colorClass="text-accent-cyan" />
      </div>

      {/* Feature Grid — alternating danger/cyan accents like frontend */}
      <div className="grid grid-cols-3 gap-6 mb-6">
        <FeatureCard
          variant="danger"
          icon="&#127919;"
          title="Adversary Emulation"
          body="Realistic simulation of TTPs used by known threat actors — based on real-world intelligence, MITRE ATT&CK mappings, and live incident data."
          tag="CORE"
        />
        <FeatureCard
          variant="cyan"
          icon="&#128203;"
          title="Playbooks"
          body="Step-by-step Incident Response guides co-authored with emulation results. Each playbook maps directly to a threat actor's known behavior."
          tag="IR"
        />
        <FeatureCard
          variant="danger"
          icon="&#128214;"
          title="Runbooks"
          body="Operational automation scripts tied to each emulation scenario. Runbooks codify your IR workflows for repeatable, consistent response execution."
          tag="AUTOMATION"
        />
        <FeatureCard
          variant="cyan"
          icon="&#128269;"
          title="Detections"
          body="SIGMA rules, KQL queries, and YARA signatures generated directly from emulation results for your SIEM or EDR platform."
          tag="SIGMA · KQL · YARA"
        />
        <FeatureCard
          variant="danger"
          icon="&#128737;"
          title="Guardrails"
          body="Org-level policies that define emulation scope, restrict blast radius, and prevent unintended impact. Define safe zones and excluded resources."
          tag="POLICY"
        />
        <FeatureCard
          variant="cyan"
          icon="&#128506;"
          title="Why Emulation?"
          body="Adversary emulation bridges the gap between threat intelligence and defense validation. MayaTrail proves your defenses work."
          tag="PHILOSOPHY"
        />
      </div>
    </div>
  )
}

function StatCard({ value, label, colorClass }: { value: number; label: string; colorClass: string }) {
  return (
    <div className="bg-surface-card border border-border rounded-card px-5 py-5 text-center
      transition-all duration-[400ms] hover:border-border-active hover:-translate-y-0.5">
      <div className={`text-[2rem] font-[900] font-display ${colorClass}`}>{value}</div>
      <div className="text-[0.7rem] text-content-dim mt-1.5 font-mono tracking-[1.5px] uppercase font-medium">{label}</div>
    </div>
  )
}

function FeatureCard({
  variant,
  icon,
  title,
  body,
  tag,
}: {
  variant: 'danger' | 'cyan'
  icon: string
  title: string
  body: string
  tag: string
}) {
  const isDanger = variant === 'danger'
  return (
    <div className={`bg-surface-card border border-border rounded-card p-8 relative overflow-hidden
      transition-all duration-[400ms] cursor-default group
      ${isDanger
        ? 'hover:border-[rgba(255,34,68,0.2)] hover:-translate-y-1 hover:shadow-[0_20px_60px_rgba(0,0,0,0.3)]'
        : 'hover:border-[rgba(72,232,200,0.2)] hover:-translate-y-1 hover:shadow-[0_20px_60px_rgba(0,0,0,0.3)]'
      }`}>
      {/* Hover accent line */}
      <div className={`absolute top-0 left-0 right-0 h-0.5 opacity-0 group-hover:opacity-100 transition-opacity duration-[400ms]
        ${isDanger
          ? 'bg-gradient-to-r from-transparent via-danger to-transparent'
          : 'bg-gradient-to-r from-transparent via-accent-cyan to-transparent'
        }`} />
      <div className={`w-12 h-12 rounded-btn flex items-center justify-center text-[22px] mb-5
        ${isDanger ? 'bg-danger/[0.15]' : 'bg-[rgba(72,232,200,0.1)]'}`}>{icon}</div>
      <div className="font-display text-[1.15rem] font-bold text-content-primary mb-2.5 tracking-[-0.3px]">{title}</div>
      <div className="text-[0.9rem] text-content-secondary leading-[1.65] mb-4">{body}</div>
      <span className={`inline-block px-2.5 py-1 rounded-[6px] font-mono text-[0.65rem] uppercase tracking-[0.5px] font-medium
        ${isDanger ? 'bg-danger/[0.1] text-danger' : 'bg-[rgba(72,232,200,0.1)] text-accent-cyan'}`}>
        {tag}
      </span>
    </div>
  )
}
