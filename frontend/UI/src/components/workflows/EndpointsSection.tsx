import { useState } from 'react'
import type { AlertEndpoint, AlertEndpointCreated } from '@/types/workflow'
import { createAlertEndpoint } from '@/services/workflow.service'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { IconCheck, IconCopy } from '@/components/ui/Icons'
import { formatWhen } from '@/components/threatfeed/feedMeta'

/**
 * Where a client wires their SIEM into MayaTrail, on its own tab.
 *
 * Separated from the runs list because endpoints are configuration, read once
 * and rarely changed, while runs are the working surface. Sharing one scroll
 * with them meant a team with several SIEMs pushed their own results off the
 * page.
 *
 * Rendered as a table rather than stacked cards, so ten endpoints stay as
 * scannable as one.
 */

interface EndpointsSectionProps {
  endpoints: AlertEndpoint[] | undefined
  loading: boolean
  onCreated: () => void
}

export function EndpointsSection({ endpoints, loading, onCreated }: EndpointsSectionProps) {
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
      // Refetches the list. Deliberately does not remount anything: an earlier
      // version keyed the page on a counter, which destroyed the state holding
      // the secret on the line above.
      onCreated()
    } catch {
      setError('Could not create the endpoint. Check that alert ingestion is configured.')
    } finally {
      setCreating(false)
    }
  }

  const list = endpoints ?? []

  return (
    <div className="flex flex-col gap-4">
      {created && <SecretOnce created={created} onDismiss={() => setCreated(null)} />}

      <Card className="p-5">
        <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-3">
          Create an endpoint
        </h2>
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
        <p className="text-xs text-content-dim mt-2">
          The signing secret is shown once, here, and cannot be retrieved afterwards. Copy it
          into your SIEM before leaving this page.
        </p>
        {error && <p className="text-xs text-danger mt-2">{error}</p>}
      </Card>

      <Card className="p-5">
        <h2 className="font-mono text-2xs uppercase tracking-label text-content-dim mb-3">
          Endpoints
        </h2>

        {loading && list.length === 0 ? (
          <div className="py-8 text-center font-mono text-xs text-content-dim">Loading…</div>
        ) : list.length === 0 ? (
          <div className="py-8 text-center text-sm text-content-dim">
            No endpoints yet. Create one above so a workflow can report what your SIEM caught.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[720px]">
              <thead>
                <tr className="font-mono text-2xs uppercase tracking-caps text-content-dim">
                  <th className="font-normal pb-2 pr-3">Name</th>
                  <th className="font-normal pb-2 pr-3">Endpoint URL</th>
                  <th className="font-normal pb-2 pr-3">Created</th>
                  <th className="font-normal pb-2 pr-3">By</th>
                  <th className="font-normal pb-2">In use</th>
                </tr>
              </thead>
              <tbody>
                {list.map((endpoint) => (
                  <EndpointRow key={endpoint.id} endpoint={endpoint} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

/** One endpoint: what it is, where it lives, and whether anything ever used it. */
function EndpointRow({ endpoint }: { endpoint: AlertEndpoint }) {
  const url = endpointUrl(endpoint.id)
  const used = endpoint.alertCount > 0

  return (
    <tr className="border-t border-border align-middle">
      <td className="py-3 pr-3">
        <span className="block text-xs text-content-primary tracking-body">{endpoint.name}</span>
        <span className="block font-mono text-2xs text-content-muted mt-0.5">
          secret ends {endpoint.secretHint}
        </span>
      </td>
      <td className="py-3 pr-3">
        <CopyValue value={url} />
      </td>
      <td className="py-3 pr-3 text-xs text-content-secondary whitespace-nowrap">
        {formatWhen(endpoint.createdAt)}
      </td>
      <td className="py-3 pr-3 text-xs text-content-secondary whitespace-nowrap">{endpoint.createdBy}</td>
      <td className="py-3">
        {/* The number that tells a client their integration works before they
            spend money running an emulation. */}
        <Badge tone={used ? 'green' : 'neutral'} mono>
          {used ? `${endpoint.alertCount} alerts` : 'never used'}
        </Badge>
        {endpoint.lastAlertAt && (
          <span className="block font-mono text-2xs text-content-muted mt-1">
            last {formatWhen(endpoint.lastAlertAt)}
          </span>
        )}
      </td>
    </tr>
  )
}

/**
 * Build the URL a SIEM posts to.
 *
 * Composed client-side from the current origin, so it is right whether the
 * platform is reached on localhost or a customer's own hostname.
 *
 * @param endpointId - UUID of the endpoint.
 */
export function endpointUrl(endpointId: string): string {
  return `${window.location.origin}/api/workflows/alerts/${endpointId}/`
}

/** A value with a copy button, for things that must be transcribed exactly. */
function CopyValue({ value, mono = true }: { value: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false)

  return (
    <span className="flex items-center gap-1.5">
      <code className={`min-w-0 truncate bg-surface-base border border-border rounded px-2 py-1
        text-2xs text-content-secondary ${mono ? 'font-mono' : ''}`}>
        {value}
      </code>
      {/* The confirmation swaps one 12px glyph for another rather than for the
          word "copied". Text is wider than the icon, so the button grew, shoved
          the row's neighbours aside, and snapped back a second and a half
          later. A same-size swap cannot move anything. */}
      <button
        type="button"
        onClick={() => {
          navigator.clipboard?.writeText(value)
          setCopied(true)
          window.setTimeout(() => setCopied(false), 1500)
        }}
        aria-label={copied ? 'Copied' : 'Copy'}
        className={`shrink-0 p-1 rounded-btn transition-colors
          ${copied ? 'text-safe' : 'text-content-dim hover:text-content-primary'}`}
      >
        {copied ? <IconCheck size={12} /> : <IconCopy size={12} />}
      </button>
    </span>
  )
}

/**
 * The one and only sighting of a new endpoint's signing secret.
 *
 * Rendered above everything else and dismissed only by an explicit click,
 * because losing it means creating another endpoint and reconfiguring the SIEM.
 */
function SecretOnce({
  created,
  onDismiss,
}: {
  created: AlertEndpointCreated
  onDismiss: () => void
}) {
  return (
    <Card className="p-5 border-safe/25">
      <div className="font-mono text-2xs uppercase tracking-label text-safe mb-2">
        Copy these now
      </div>
      <p className="text-xs text-content-secondary leading-relaxed mb-3">
        The secret is stored encrypted and cannot be shown again. Configure your SIEM&apos;s
        webhook action to POST to this URL, signing each request as below.
      </p>

      <Labelled label="Webhook URL">
        <CopyValue value={endpointUrl(created.id)} />
      </Labelled>
      <Labelled label="Signing secret">
        <CopyValue value={created.secret} />
      </Labelled>

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
  "firedAt":   "2026-09-14T06:12:00Z"
}`}
        </pre>
      </details>

      <button
        type="button"
        onClick={onDismiss}
        className="mt-3 px-3 py-1.5 rounded-btn text-xs font-medium tracking-btn border border-border
          text-content-primary transition-opacity hover:opacity-60"
      >
        I have copied them
      </button>
    </Card>
  )
}

/** A labelled row inside the secret panel. */
function Labelled({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 mb-2">
      <span className="w-28 shrink-0 font-mono text-2xs text-content-dim">{label}</span>
      <span className="min-w-0 flex-1">{children}</span>
    </div>
  )
}
