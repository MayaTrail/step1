import { useState } from 'react'
import type { ReactNode } from 'react'
import { runPlaybookCommand } from '@/services/platform.service'
import type { CommandResult } from '@/types'

/**
 * Classify a code block for the run affordance. This is cosmetic only — the
 * backend re-validates every command against the allowlist, so an optimistic
 * "read-only" here is still rejected server-side if it is actually unsafe.
 */
function classify(code: string): 'readonly' | 'mutating' | 'none' {
  const m = code.match(/\baws\s+([a-z0-9-]+)\s+([a-z0-9-]+)/i)
  if (!m) return 'none'
  const operation = m[2] ?? ''
  return /^(describe|list|get|lookup|head|search)/i.test(operation) ? 'readonly' : 'mutating'
}

/** The first `aws ...` line, used as a compact header label. */
function headerLabel(code: string): string {
  const line = code.split('\n').find((l) => l.trim().startsWith('aws '))
  return (line ?? code.split('\n')[0] ?? '').trim()
}

type RunState = { status: 'idle' | 'loading' | 'done'; result?: CommandResult; failed?: boolean }

const BTN =
  'text-[11px] font-semibold px-2.5 py-1 rounded-md border border-border-active text-content-secondary hover:opacity-60 transition-opacity cursor-pointer'

export function CommandBlock({ code, emulationType }: { code: string; emulationType: string }) {
  const kind = classify(code)
  const [run, setRun] = useState<RunState>({ status: 'idle' })
  const [copied, setCopied] = useState(false)

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard may be blocked; nothing actionable to show.
    }
  }

  const onRun = async () => {
    setRun({ status: 'loading' })
    try {
      const result = await runPlaybookCommand(emulationType, code)
      setRun({ status: 'done', result })
    } catch {
      setRun({ status: 'done', failed: true })
    }
  }

  return (
    <div className="my-3 border border-border rounded-btn overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-surface-base border-b border-border">
        <span className="font-mono text-2xs text-content-dim truncate">{headerLabel(code)}</span>
        {kind === 'readonly' && (
          <span className="text-[10px] font-semibold px-2 py-0.5 rounded border bg-safe/10 text-safe border-safe/30 shrink-0">
            Read-only
          </span>
        )}
        {kind === 'mutating' && (
          <span className="text-[10px] font-semibold px-2 py-0.5 rounded border bg-danger/10 text-danger border-danger/30 shrink-0">
            Mutating · copy only
          </span>
        )}
        <div className="ml-auto flex items-center gap-1.5 shrink-0">
          <button onClick={onCopy} className={BTN}>{copied ? 'Copied' : 'Copy'}</button>
          {kind === 'readonly' && (
            <button
              onClick={onRun}
              disabled={run.status === 'loading'}
              className={`${BTN} text-accent-blue border-accent-blue/40 disabled:opacity-50`}
            >
              {run.status === 'loading' ? 'Running...' : 'Run in my environment'}
            </button>
          )}
        </div>
      </div>

      <pre className="bg-surface-deep p-3.5 overflow-x-auto text-[13px] font-mono text-content-primary leading-relaxed">
        {code}
      </pre>

      {run.status === 'done' && <CommandOutput run={run} />}
    </div>
  )
}

function CommandOutput({ run }: { run: RunState }) {
  if (run.failed) {
    return <Notice tone="danger">Request failed. Try again.</Notice>
  }
  const r = run.result
  if (!r) return null
  if (!r.runnable) {
    return <Notice tone="dim">{r.reason ?? 'This command cannot be run here.'} Copy it to run locally.</Notice>
  }
  if (r.error) {
    return <Notice tone="danger">{r.error}</Notice>
  }

  const isOk = r.ok
  const body = isOk ? (r.stdout || '(no output)') : (r.stderr || r.stdout || `exited ${r.returncode}`)
  return (
    <div className="border-t border-border bg-surface-deep px-3.5 py-2.5">
      <div className="font-mono text-2xs uppercase tracking-label text-content-dim mb-1.5">
        {isOk ? 'Output' : `Error (exit ${r.returncode})`}
      </div>
      <pre className="font-mono text-[12px] text-content-secondary whitespace-pre-wrap max-h-[320px] overflow-auto">
        {body}
      </pre>
    </div>
  )
}

function Notice({ tone, children }: { tone: 'danger' | 'dim'; children: ReactNode }) {
  const cls = tone === 'danger' ? 'text-danger' : 'text-content-dim'
  return (
    <div className={`border-t border-border bg-surface-deep px-3.5 py-2.5 text-[12px] ${cls}`}>{children}</div>
  )
}
