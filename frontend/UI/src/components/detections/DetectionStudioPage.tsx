import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import {
  createAuthoredDetection,
  deleteAuthoredDetection,
  downloadAuthoredDetection,
  generateDetection,
  getAuthoredDetection,
  updateAuthoredDetection,
  validateAdhocSigma,
} from '@/services/authoredDetection.service'
import type {
  AuthoredDetection,
  AuthoredStatus,
  AuthoredVisibility,
  DetectionValidationResult,
} from '@/types'

/**
 * Detection Studio — author or generate a Sigma rule, and close the loop.
 *
 * The reason this beats pasting a prompt into a chatbot: the rule can be scored
 * against synthetic CloudTrail events right here (Validate), so "draft ->
 * check whether it actually fires -> tune -> export" happens without leaving
 * the product. Generation and validation both reuse the user's AI connector.
 */

const INPUT =
  'w-full bg-surface-base border border-border-subtle rounded-btn px-3 py-2 text-[0.875rem] ' +
  'text-content-primary placeholder:text-content-muted focus:outline-none focus:border-accent-blue transition-colors'

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono text-[0.65rem] uppercase tracking-[1.5px] text-content-dim">
        {label}
      </span>
      {children}
    </label>
  )
}

function fidelityTone(f: number): string {
  if (f >= 0.8) return 'text-safe'
  if (f >= 0.5) return 'text-warning'
  return 'text-danger'
}

export function DetectionStudioPage() {
  const { detectionId } = useParams<{ detectionId: string }>()
  const navigate = useNavigate()
  const isNew = !detectionId

  const [loading, setLoading] = useState(!isNew)
  const [saving, setSaving] = useState<null | AuthoredStatus>(null)
  const [error, setError] = useState<string | null>(null)
  const [record, setRecord] = useState<AuthoredDetection | null>(null)

  const [title, setTitle] = useState('')
  const [technique, setTechnique] = useState('')
  const [summary, setSummary] = useState('')
  const [sigma, setSigma] = useState('')
  const [visibility, setVisibility] = useState<AuthoredVisibility>('private')
  const [status, setStatus] = useState<AuthoredStatus>('draft')

  // AI draft form
  const [showDraft, setShowDraft] = useState(false)
  const [brief, setBrief] = useState('')
  const [refUrls, setRefUrls] = useState('')
  const [drafting, setDrafting] = useState(false)
  // True once AI produced the current rule, so it is saved with origin
  // 'generated' rather than 'manual'.
  const [aiDrafted, setAiDrafted] = useState(false)

  // Validation
  const [validating, setValidating] = useState(false)
  const [validation, setValidation] = useState<DetectionValidationResult | null>(null)

  const saved = useRef({ title: '', summary: '', technique: '', sigma: '', visibility: '' })
  const dirty =
    title !== saved.current.title ||
    summary !== saved.current.summary ||
    technique !== saved.current.technique ||
    sigma !== saved.current.sigma ||
    visibility !== saved.current.visibility

  const adopt = useCallback((d: AuthoredDetection) => {
    setRecord(d)
    setTitle(d.title)
    setTechnique(d.technique_id)
    setSummary(d.summary)
    setSigma(d.sigma)
    setVisibility(d.visibility)
    setStatus(d.status)
    saved.current = {
      title: d.title, summary: d.summary, technique: d.technique_id,
      sigma: d.sigma, visibility: d.visibility,
    }
  }, [])

  useEffect(() => {
    if (isNew) return
    let cancelled = false
    getAuthoredDetection(detectionId!)
      .then((d) => !cancelled && adopt(d))
      .catch((e) => !cancelled && setError(errText(e)))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
  }, [detectionId, isNew, adopt])

  function errText(e: unknown): string {
    const detail = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
    return detail || (e instanceof Error ? e.message : 'Something went wrong.')
  }

  async function draft() {
    if (brief.trim().length < 20) {
      setError('Describe the behaviour to detect in a sentence or two.')
      return
    }
    setDrafting(true)
    setError(null)
    try {
      const urls = refUrls.split(/[\s,]+/).map((u) => u.trim()).filter(Boolean)
      const { sigma: generated } = await generateDetection({
        brief: brief.trim(),
        ...(technique.trim() ? { technique_id: technique.trim() } : {}),
        ...(urls.length ? { reference_urls: urls } : {}),
      })
      setSigma(generated)
      setValidation(null)
      setShowDraft(false)
      setAiDrafted(true)
      if (!title.trim()) setTitle(brief.trim().slice(0, 80))
    } catch (e) {
      setError(errText(e))
    } finally {
      setDrafting(false)
    }
  }

  async function validate() {
    if (!sigma.trim()) {
      setError('Nothing to validate yet — write or generate a rule first.')
      return
    }
    setValidating(true)
    setError(null)
    setValidation(null)
    try {
      setValidation(await validateAdhocSigma(sigma))
    } catch (e) {
      setError(errText(e))
    } finally {
      setValidating(false)
    }
  }

  async function save(next: AuthoredStatus) {
    if (!title.trim()) {
      setError('Give the rule a title before saving.')
      return
    }
    setSaving(next)
    setError(null)
    try {
      const draftBody = {
        title: title.trim(),
        summary,
        technique_id: technique.trim(),
        sigma,
        status: next,
        visibility,
      }
      const d = record
        ? await updateAuthoredDetection(record.id, draftBody)
        : await createAuthoredDetection({
            ...draftBody,
            origin: aiDrafted ? 'generated' : 'manual',
          })
      adopt(d)
      setStatus(d.status)
      if (!record) navigate(`/detections/studio/${d.id}`, { replace: true })
    } catch (e) {
      setError(errText(e))
    } finally {
      setSaving(null)
    }
  }

  async function handleDelete() {
    if (!record) return
    if (!window.confirm(`Delete "${record.title}"?`)) return
    try {
      await deleteAuthoredDetection(record.id)
      saved.current = { title, summary, technique, sigma, visibility }
      navigate('/detections')
    } catch (e) {
      setError(errText(e))
    }
  }

  if (loading) {
    return <div className="py-16 text-center font-mono text-sm text-content-dim">Loading rule...</div>
  }

  return (
    <div className="max-w-[64rem]">
      <div className="font-mono text-[11px] text-content-dim mb-4 flex items-center gap-2">
        <Link to="/detections" className="hover:text-content-secondary transition-colors">
          Detections
        </Link>
        <span>/</span>
        <span className="text-content-secondary">{isNew ? 'New rule' : 'Edit rule'}</span>
      </div>

      <div className="flex flex-wrap items-start justify-between gap-3 mb-5">
        <div>
          <h1 className="font-display text-[1.6rem] font-[800] text-content-primary leading-tight tracking-[-0.5px]">
            Detection Studio
          </h1>
          <p className="text-[0.9rem] text-content-secondary mt-1.5 max-w-[42rem]">
            Write a Sigma rule, or let AI draft one, then score whether it
            actually fires against synthetic CloudTrail events before you ship it.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setShowDraft((v) => !v)}
            className="border border-transparent text-accent-blue rounded-btn px-3 py-2 text-[0.85rem] transition-opacity hover:opacity-60 disabled:opacity-30"
          >
            Draft with AI
          </button>
          <button
            type="button"
            onClick={() => void save('draft')}
            disabled={saving !== null || (!dirty && status === 'draft')}
            className="border border-border text-content-secondary rounded-btn px-3 py-2 text-[0.85rem] transition-opacity hover:opacity-60 disabled:opacity-30"
          >
            {saving === 'draft' ? 'Saving...' : 'Save draft'}
          </button>
          <button
            type="button"
            onClick={() => void save('published')}
            disabled={saving !== null}
            className="border border-border text-content-primary shadow-button rounded-btn px-4 py-2 text-[0.85rem] font-medium tracking-btn transition-opacity hover:opacity-60 disabled:opacity-30"
          >
            {saving === 'published' ? 'Publishing...' : status === 'published' ? 'Save' : 'Publish'}
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" className="mb-4 border border-danger/40 bg-danger/10 text-danger rounded-btn px-3 py-2 text-[0.85rem]">
          {error}
        </div>
      )}

      {showDraft && (
        <div className="mb-5 border border-accent-blue/30 bg-accent-blue/[0.05] rounded-card p-4 flex flex-col gap-3">
          <Field label="Describe the behaviour to detect">
            <textarea
              className={`${INPUT} resize-y min-h-[4.5rem]`}
              value={brief}
              disabled={drafting}
              placeholder="CloudTrail StopLogging called outside a change window by a role that does not normally touch CloudTrail."
              onChange={(e) => setBrief(e.target.value)}
            />
          </Field>
          <Field label="Reference links (optional — cited, never fetched)">
            <input
              className={`${INPUT} font-mono text-[0.8rem]`}
              value={refUrls}
              disabled={drafting}
              placeholder="https://attack.mitre.org/techniques/T1562/008/"
              onChange={(e) => setRefUrls(e.target.value)}
            />
          </Field>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void draft()}
              disabled={drafting || brief.trim().length < 20}
              className="border border-border text-content-primary shadow-button rounded-btn px-4 py-2 text-[0.85rem] font-medium tracking-btn transition-opacity hover:opacity-60 disabled:opacity-30"
            >
              {drafting ? 'Drafting...' : 'Draft the rule'}
            </button>
            <span className="text-[0.78rem] text-content-dim">
              Replaces the Sigma below. Review it before saving.
            </span>
          </div>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-[2fr_1fr_1fr] mb-4">
        <Field label="Title">
          <input className={INPUT} value={title} onChange={(e) => setTitle(e.target.value)}
            placeholder="StopLogging outside change window" />
        </Field>
        <Field label="Technique">
          <input className={INPUT} value={technique} onChange={(e) => setTechnique(e.target.value)}
            placeholder="T1562.008" />
        </Field>
        <Field label="Visible to">
          <select className={INPUT} value={visibility}
            onChange={(e) => setVisibility(e.target.value as AuthoredVisibility)}>
            <option value="private">Only me</option>
            <option value="organization">My organisation</option>
          </select>
        </Field>
        <div className="md:col-span-3">
          <Field label="Summary">
            <input className={INPUT} value={summary} onChange={(e) => setSummary(e.target.value)}
              placeholder="One line, shown on the rule card." maxLength={400} />
          </Field>
        </div>
      </div>

      <Field label="Sigma rule">
        <textarea
          className={`${INPUT} resize-y min-h-[22rem] font-mono text-[0.8rem] leading-relaxed`}
          value={sigma}
          spellCheck={false}
          placeholder={'title: ...\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  selection:\n    eventName: StopLogging\n  condition: selection'}
          onChange={(e) => { setSigma(e.target.value); setValidation(null) }}
        />
      </Field>

      <div className="flex flex-wrap items-center gap-2 mt-3">
        <button
          type="button"
          onClick={() => void validate()}
          disabled={validating || !sigma.trim()}
          className="border border-border text-content-secondary rounded-btn px-4 py-2 text-[0.85rem] transition-opacity hover:opacity-60 disabled:opacity-30"
        >
          {validating ? 'Validating...' : 'Validate against synthetic events'}
        </button>
        {record && <ExportControl record={record} />}
        {record && (
          <button type="button" onClick={handleDelete}
            className="ml-auto text-danger hover:underline text-[0.85rem]">
            Delete
          </button>
        )}
      </div>

      {validation && <ValidationReport result={validation} />}
    </div>
  )
}

function ValidationReport({ result }: { result: DetectionValidationResult }) {
  if (result.evaluable === false) {
    return (
      <div className="mt-4 border border-warning/40 bg-warning/10 rounded-card px-4 py-3 text-[0.85rem] text-content-secondary">
        This rule can&rsquo;t be scored automatically ({result.reason}). Correlation
        and aggregation rules span many events, so a per-event score would
        mislead — validate those against a real run instead.
      </div>
    )
  }
  const f = result.fidelity ?? 0
  return (
    <div className="mt-4 border border-border rounded-card bg-surface-card overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-border bg-surface-deep">
        <span className="font-mono text-2xs uppercase tracking-label text-content-dim">Fidelity</span>
        <span className={`font-mono text-[1.1rem] font-bold ${fidelityTone(f)}`}>
          {Math.round(f * 100)}%
        </span>
        {result.summary && <span className="text-[0.82rem] text-content-secondary">{result.summary}</span>}
      </div>
      {result.scenarios && result.scenarios.length > 0 && (
        <div className="divide-y divide-border">
          {result.scenarios.map((s, i) => {
            const ok = s.matched === s.expected
            return (
              <div key={i} className="flex items-center gap-3 px-4 py-2 text-[0.82rem]">
                <span className={`font-mono text-2xs ${ok ? 'text-safe' : 'text-danger'}`}>
                  {ok ? 'PASS' : 'MISS'}
                </span>
                <span className="font-mono text-2xs uppercase tracking-label text-content-dim w-16">
                  {s.label}
                </span>
                <span className="text-content-secondary">
                  {s.note || (s.expected ? 'should fire' : 'should stay quiet')}
                  {' — '}{s.matched ? 'fired' : 'quiet'}
                </span>
              </div>
            )
          })}
        </div>
      )}
      {result.suggestions && (
        <div className="px-4 py-3 border-t border-border text-[0.82rem] text-content-secondary">
          <span className="font-mono text-2xs uppercase tracking-label text-content-dim">Suggestions</span>
          <div className="mt-1 whitespace-pre-wrap">{result.suggestions}</div>
        </div>
      )}
    </div>
  )
}

function ExportControl({ record }: { record: AuthoredDetection }) {
  const [target, setTarget] = useState('splunk')
  const [busy, setBusy] = useState(false)
  return (
    <div className="flex items-center gap-2">
      <select
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        className="bg-surface-base border border-border rounded-btn px-2.5 py-2 text-[0.82rem] text-content-primary focus:outline-none focus:border-accent-blue"
      >
        <option value="splunk">Splunk</option>
        <option value="opensearch">OpenSearch / Wazuh</option>
      </select>
      <button
        type="button"
        disabled={busy}
        onClick={async () => {
          setBusy(true)
          try {
            await downloadAuthoredDetection(record.id, target, record.slug)
          } finally {
            setBusy(false)
          }
        }}
        className="border border-border text-content-secondary rounded-btn px-3 py-2 text-[0.85rem] transition-opacity hover:opacity-60 disabled:opacity-30"
      >
        Export
      </button>
    </div>
  )
}
