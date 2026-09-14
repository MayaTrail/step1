import { useState } from 'react'
import type { AlertEndpoint, AlertEndpointCreated } from '@/types/workflow'
import { createAlertEndpoint } from '@/services/workflow.service'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { IconCopy, IconShield } from '@/components/ui/Icons'
import { formatWhen } from '@/components/threatfeed/feedMeta'

/**
 * Where a client wires their SIEM into MayaTrail.
 *
 * The panel exists because a workflow cannot say anything useful until alerts
 * arrive, and the commonest failure is a client running an emulation before
 * their webhook works. So the alert count is shown prominently: it is how
 * someone confirms the integration is live before spending money on a run.
 *
 * The secret is displayed once, on creation, and never again. It is stored
 * encrypted and cannot be read back, which is stated plainly rather than
 * discovered later.
 */

interface AlertEndpointPanelProps {
  endpoints: AlertEndpoint[] | undefined
  onCreated: () => void
}

export function AlertEndpointPanel({ endpoints, onCreated }: AlertEndpointPanelProps) {
  const [name, setName] = useState('')
  const [creating, setCreating] = useState(false)
  const [created, setCreated] = useState<AlertEndpointCreated | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function submit() {
    if (!name.trim() || creating) return
    setCreating(true)
    setError(null)
    try {
      setCreated(await createAlertEndpoint(name.trim()))
      setName('')
      onCreated()
    } catch {
      setError('Could not create the endpoint. Check that alert ingestion is configured.')
    } finally {
      setCreating(false)
    }
  }

  const list = endpoints ?? []

  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 mb-1">
        <span className="text-accent-blue">
          <IconShield size={15} />
        </span>
        <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim">
          SIEM alert endpoint
        </h2>
      </div>
      <p className="text-sm text-content-secondary leading-relaxed tracking-body mb-4">
        Point your SIEM at this endpoint so MayaTrail can tell which of an emulation&apos;s
        expected detections your own rules actually caught. Without it a workflow can run,
        but it cannot report anything.
      </p>

      {list.length > 0 && (
        <div className="flex flex-col divide-y divide-border border border-border rounded-btn mb-4">
          {list.map((endpoint) => (
            <div key={endpoint.id} className="flex items-center gap-3 px-3 py-2.5">
              <span className="min-w-0 flex-1">
                <span className="block text-sm text-content-primary tracking-body">
                  {endpoint.name}
                </span>
                <span className="block font-mono text-2xs text-content-muted mt-0.5 truncate">
                  secret ends {endpoint.secretHint}
                  {endpoint.lastAlertAt
                    ? ` · last alert ${formatWhen(endpoint.lastAlertAt)}`
                    : ' · no alerts yet'}
                </span>
              </span>
              {/* The number that tells a client their integration works before
                  they spend money running an emulation. */}
              <Badge tone={endpoint.alertCount > 0 ? 'green' : 'neutral'} mono>
                {endpoint.alertCount} received
              </Badge>
            </div>
          ))}
        </div>
      )}

      {created && <SecretOnce created={created} onDismiss={() => setCreated(null)} />}

      <div className="flex flex-wrap items-center gap-2">
        <input
          value={name}
          onChange={(event) => setName(event.target.value)}
          onKeyDown={(event) => event.key === 'Enter' && submit()}
          placeholder="Endpoint name, for example Splunk production"
          className="flex-1 min-w-[220px] bg-surface-base border border-border rounded-btn px-3 py-2
            text-sm text-content-primary placeholder:text-content-dim outline-none
            transition-colors focus:border-border-active"
        />
        <button
          type="button"
          onClick={submit}
          disabled={!name.trim() || creating}
          className="px-4 py-2 rounded-btn text-sm font-medium tracking-btn border border-border
            text-content-primary shadow-button transition-opacity hover:opacity-60
            disabled:opacity-30 disabled:cursor-not-allowed"
        >
          {creating ? 'Creating…' : 'Create endpoint'}
        </button>
      </div>

      {error && <p className="text-xs text-danger mt-2">{error}</p>}
    </Card>
  )
}

/**
 * The one and only sighting of a new endpoint's secret.
 *
 * Shown inline rather than in a toast, and not dismissible by clicking away,
 * because losing it means creating a new endpoint and reconfiguring the SIEM.
 */
function SecretOnce({
  created,
  onDismiss,
}: {
  created: AlertEndpointCreated
  onDismiss: () => void
}) {
  const url = `${window.location.origin}/api/workflows/alerts/${created.id}/`

  return (
    <div className="border border-safe/25 bg-safe-dim rounded-btn p-4 mb-4">
      <div className="font-mono text-2xs uppercase tracking-label text-safe mb-2">
        Copy these now
      </div>
      <p className="text-xs text-content-secondary leading-relaxed mb-3">
        The secret is stored encrypted and cannot be shown again. Configure your SIEM&apos;s
        webhook action to POST to this URL, signing each request as described below.
      </p>

      <CopyRow label="Webhook URL" value={url} />
      <CopyRow label="Signing secret" value={created.secret} mono />

      <details className="mt-3">
        <summary className="text-xs text-content-secondary cursor-pointer hover:opacity-60">
          How to sign the request
        </summary>
        <pre className="mt-2 bg-surface-base border border-border rounded-btn p-3 overflow-x-auto
          font-mono text-2xs text-content-secondary leading-relaxed">
{`X-MayaTrail-Timestamp: <unix seconds>
X-MayaTrail-Signature: sha256=<hex>

signature = HMAC_SHA256(secret, "<timestamp>." + <raw body>)

body:
{
  "ruleId":    "<your rule id, or our Sigma UUID>",
  "ruleName":  "<rule title>",
  "technique": "T1098.001",
  "severity":  "high",
  "firedAt":   "2026-09-11T06:12:00Z"
}`}
        </pre>
      </details>

      <button
        type="button"
        onClick={onDismiss}
        className="mt-3 text-xs font-medium tracking-btn text-content-secondary
          transition-opacity hover:opacity-60"
      >
        I have copied them
      </button>
    </div>
  )
}

/** A value with a copy button, for things that must be transcribed exactly. */
function CopyRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false)

  return (
    <div className="flex items-center gap-2 mb-2">
      <span className="w-28 shrink-0 font-mono text-2xs text-content-dim">{label}</span>
      <code className={`flex-1 min-w-0 truncate bg-surface-base border border-border rounded px-2 py-1
        text-2xs text-content-secondary ${mono ? 'font-mono' : ''}`}>
        {value}
      </code>
      <button
        type="button"
        onClick={() => {
          navigator.clipboard?.writeText(value)
          setCopied(true)
          window.setTimeout(() => setCopied(false), 1500)
        }}
        aria-label={`Copy ${label}`}
        className="shrink-0 p-1.5 rounded-btn text-content-dim transition-opacity hover:opacity-60"
      >
        {copied ? <span className="text-2xs text-safe">copied</span> : <IconCopy size={13} />}
      </button>
    </div>
  )
}
