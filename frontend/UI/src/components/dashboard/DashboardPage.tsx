import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { platformRegistry } from '@/data'
import { fetchEmulations, fetchDetections } from '@/services/platform.service'

/* ── Types ── */
type Accent = 'red' | 'blue' | 'green' | 'amber'

interface DashStats {
  totalEmulations: number
  totalTechniques: number
  totalDetections: number
  loading: boolean
}

/* ── Accent token maps ── */
const accentColor: Record<Accent, string> = {
  red:   '#FF6363',
  blue:  '#55b3ff',
  green: '#5fc992',
  amber: '#ffbc33',
}
const accentBg: Record<Accent, string> = {
  red:   'rgba(255,99,99,0.08)',
  blue:  'rgba(85,179,255,0.08)',
  green: 'rgba(95,201,146,0.08)',
  amber: 'rgba(255,188,51,0.08)',
}
const accentBorder: Record<Accent, string> = {
  red:   'rgba(255,99,99,0.18)',
  blue:  'rgba(85,179,255,0.18)',
  green: 'rgba(95,201,146,0.18)',
  amber: 'rgba(255,188,51,0.18)',
}

/* ── Dashboard Page ── */
export function DashboardPage() {
  const navigate = useNavigate()

  const [stats, setStats] = useState<DashStats>({
    totalEmulations: 0,
    totalTechniques: 0,
    totalDetections: 0,
    loading: true,
  })

  useEffect(() => {
    let cancelled = false

    async function loadStats() {
      try {
        const emulations = await fetchEmulations('aws')
        if (cancelled) return

        const totalEmulations = emulations.length
        const totalTechniques = emulations.reduce(
          (sum, em) => sum + (em.techniqueCount ?? 0),
          0,
        )

        // Fetch detection counts for all emulations in parallel.
        const detectionResults = await Promise.all(
          emulations.map((em) => fetchDetections(em.id).catch(() => null)),
        )
        if (cancelled) return

        const totalDetections = detectionResults.reduce(
          (sum, d) => sum + (d?.totalCount ?? 0),
          0,
        )

        setStats({ totalEmulations, totalTechniques, totalDetections, loading: false })
      } catch {
        setStats((prev) => ({ ...prev, loading: false }))
      }
    }

    loadStats()
    return () => { cancelled = true }
  }, [])

  return (
    <div style={{ fontFamily: 'Inter, system-ui, sans-serif', color: '#f9f9f9' }}>

      {/* ── Page header ── */}
      <div style={{ marginBottom: '32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
          {/* Status badge */}
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '11px',
              fontWeight: 500,
              color: '#5fc992',
              background: 'rgba(95,201,146,0.08)',
              border: '1px solid rgba(95,201,146,0.2)',
              borderRadius: '4px',
              padding: '2px 8px',
              letterSpacing: '0.3px',
            }}
          >
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: '#5fc992',
                flexShrink: 0,
              }}
            />
            Platform active
          </span>
        </div>
        <h1
          style={{
            fontSize: '22px',
            fontWeight: 600,
            color: '#f9f9f9',
            letterSpacing: '-0.3px',
            marginBottom: '6px',
            lineHeight: 1.2,
          }}
        >
          Overview
        </h1>
        <p style={{ fontSize: '13px', color: '#6a6b6c', letterSpacing: '0.2px', lineHeight: 1.6 }}>
          Adversary emulation coverage across your connected cloud environments.
        </p>
      </div>

      {/* ── Metric row ── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '16px',
          marginBottom: '32px',
        }}
      >
        <MetricCard value={stats.totalEmulations} label="APT Emulations" accent="red" loading={stats.loading} />
        <MetricCard value={stats.totalTechniques} label="MITRE Techniques" accent="blue" loading={stats.loading} />
        <MetricCard value={stats.totalDetections} label="Detection Rules" accent="green" loading={stats.loading} />
        <MetricCard value={platformRegistry.length} label="Cloud Platforms" accent="amber" />
      </div>

      {/* ── Section divider ── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          marginBottom: '20px',
        }}
      >
        <span style={{ fontSize: '11px', fontWeight: 500, color: '#434345', letterSpacing: '0.3px', textTransform: 'uppercase' }}>
          Capabilities
        </span>
        <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.05)' }} />
      </div>

      {/* ── Feature grid ── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '16px',
          marginBottom: '32px',
        }}
      >
        <FeatureCard
          accent="red"
          iconLabel="EM"
          title="Adversary Emulation"
          body="Realistic emulation of TTPs used by known threat actors — based on real-world intelligence and MITRE ATT&CK mappings."
          tag="Core"
          onClick={() => navigate('/aws/emulations')}
        />
        <FeatureCard
          accent="blue"
          iconLabel="PB"
          title="Playbooks"
          body="Step-by-step Incident Response guides co-authored with emulation results, mapped to threat actor behavior."
          tag="IR"
          onClick={() => navigate('/aws/emulations')}
        />
        <FeatureCard
          accent="green"
          iconLabel="DT"
          title="Detections"
          body="SIGMA rules, KQL queries, and YARA signatures generated from emulation results for your SIEM or EDR platform."
          tag="SIGMA · KQL"
          onClick={() => navigate('/aws/emulations')}
        />
        <FeatureCard
          accent="amber"
          iconLabel="GR"
          title="Guardrails"
          body="Org-level policies that define emulation scope, restrict blast radius, and prevent unintended impact on live resources."
          tag="Policy"
          onClick={() => navigate('/aws/guardrails')}
        />
        <FeatureCard
          accent="blue"
          iconLabel="RB"
          title="Runbooks"
          body="Operational automation scripts tied to each emulation scenario — codify IR workflows for repeatable response execution."
          tag="Automation"
        />
        <FeatureCard
          accent="green"
          iconLabel="??"
          title="Why Emulation?"
          body="Adversary emulation bridges the gap between threat intelligence and defense validation. Prove your defenses work."
          tag="Philosophy"
        />
      </div>

      {/* ── Quick-access platform row ── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          marginBottom: '20px',
        }}
      >
        <span style={{ fontSize: '11px', fontWeight: 500, color: '#434345', letterSpacing: '0.3px', textTransform: 'uppercase' }}>
          Cloud Platforms
        </span>
        <div style={{ flex: 1, height: '1px', background: 'rgba(255,255,255,0.05)' }} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px', marginBottom: '8px' }}>
        {platformRegistry.map((platform) => (
          <PlatformCard
            key={platform.id}
            label={
              platform.label.includes('Amazon') ? 'AWS'
              : platform.label.includes('Google') ? 'GCP'
              : platform.label.includes('Microsoft') ? 'Azure'
              : platform.label.includes('AI') ? 'AI / ML'
              : platform.label
            }
            count={platform.badgeCount}
            route={platform.route}
            onClick={() => navigate(`/${platform.route}/emulations`)}
          />
        ))}
      </div>

    </div>
  )
}

/* ── Metric Card ── */
function MetricCard({
  value, label, accent, loading = false,
}: {
  value: number
  label: string
  accent: Accent
  loading?: boolean
}) {
  const color = accentColor[accent]
  const bg    = accentBg[accent]
  const bdr   = accentBorder[accent]
  return (
    <div
      style={{
        background: '#101111',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '10px',
        boxShadow: 'rgb(27,28,30) 0px 0px 0px 1px, rgb(7,8,10) 0px 0px 0px 1px inset',
        padding: '18px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        position: 'relative',
        overflow: 'hidden',
        transition: 'border-color 0.2s',
      }}
      onMouseEnter={(e) => (e.currentTarget.style.borderColor = bdr)}
      onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)')}
    >
      {/* Left accent bar */}
      <div
        style={{
          position: 'absolute',
          top: '14px',
          bottom: '14px',
          left: 0,
          width: '3px',
          background: color,
          borderRadius: '0 2px 2px 0',
          opacity: 0.8,
        }}
      />
      {/* Icon chip */}
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '28px',
          height: '28px',
          borderRadius: '6px',
          background: bg,
          border: `1px solid ${bdr}`,
          marginBottom: '4px',
        }}
      >
        <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: color }} />
      </div>
      <div
        style={{
          fontSize: '28px',
          fontWeight: 700,
          color: loading ? '#434345' : '#f9f9f9',
          letterSpacing: '-0.5px',
          lineHeight: 1,
          transition: 'color 0.3s',
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {loading ? '—' : value}
      </div>
      <div
        style={{
          fontSize: '11px',
          fontWeight: 500,
          color: '#6a6b6c',
          letterSpacing: '0.3px',
          textTransform: 'uppercase',
        }}
      >
        {label}
      </div>
    </div>
  )
}

/* ── Feature Card ── */
function FeatureCard({
  accent, iconLabel, title, body, tag, onClick,
}: {
  accent: Accent
  iconLabel: string
  title: string
  body: string
  tag: string
  onClick?: () => void
}) {
  const color = accentColor[accent]
  const bg    = accentBg[accent]
  const bdr   = accentBorder[accent]

  return (
    <div
      onClick={onClick}
      style={{
        background: '#101111',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '10px',
        boxShadow: 'rgb(27,28,30) 0px 0px 0px 1px, rgb(7,8,10) 0px 0px 0px 1px inset',
        padding: '20px',
        cursor: onClick ? 'pointer' : 'default',
        transition: 'border-color 0.2s, transform 0.15s',
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = bdr
        if (onClick) e.currentTarget.style.transform = 'translateY(-1px)'
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'
        e.currentTarget.style.transform = 'translateY(0)'
      }}
    >
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '8px' }}>
        {/* Icon chip */}
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '32px',
            height: '32px',
            borderRadius: '6px',
            background: bg,
            border: `1px solid ${bdr}`,
            fontSize: '10px',
            fontWeight: 700,
            color,
            letterSpacing: '0.3px',
            flexShrink: 0,
            fontFamily: 'Geist Mono, monospace',
          }}
        >
          {iconLabel}
        </div>
        {/* Tag */}
        <span
          style={{
            fontSize: '10px',
            fontWeight: 500,
            color: '#434345',
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: '4px',
            padding: '2px 7px',
            letterSpacing: '0.3px',
            fontFamily: 'Geist Mono, monospace',
            whiteSpace: 'nowrap',
          }}
        >
          {tag}
        </span>
      </div>

      {/* Title */}
      <div style={{ fontSize: '13px', fontWeight: 600, color: '#f9f9f9', letterSpacing: '-0.1px' }}>
        {title}
      </div>

      {/* Body */}
      <div style={{ fontSize: '12px', color: '#6a6b6c', lineHeight: 1.65, letterSpacing: '0.2px' }}>
        {body}
      </div>

      {/* Arrow indicator if clickable */}
      {onClick && (
        <div style={{ fontSize: '11px', color, letterSpacing: '0.2px', marginTop: '2px' }}>
          Explore →
        </div>
      )}
    </div>
  )
}

/* ── Platform Card ── */
function PlatformCard({
  label, count, onClick,
}: {
  label: string
  count: number
  route: string
  onClick: () => void
}) {
  return (
    <div
      onClick={onClick}
      style={{
        background: '#101111',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: '10px',
        boxShadow: 'rgb(27,28,30) 0px 0px 0px 1px, rgb(7,8,10) 0px 0px 0px 1px inset',
        padding: '14px 16px',
        cursor: 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '8px',
        transition: 'border-color 0.2s',
      }}
      onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.12)')}
      onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)')}
    >
      <span style={{ fontSize: '13px', fontWeight: 500, color: '#d4d4d5', letterSpacing: '0.1px' }}>
        {label}
      </span>
      <span
        style={{
          fontSize: '10px',
          fontWeight: 600,
          color: '#434345',
          background: 'rgba(255,255,255,0.04)',
          border: '1px solid rgba(255,255,255,0.06)',
          borderRadius: '4px',
          padding: '1px 6px',
          fontFamily: 'Geist Mono, monospace',
          letterSpacing: '0.2px',
          flexShrink: 0,
        }}
      >
        {count}
      </span>
    </div>
  )
}
