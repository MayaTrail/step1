import { useEffect, useState } from 'react'
import type { LLMConnector, LLMProvider } from '@/types'
import {
    getLLMConnector,
    saveLLMConnector,
    deleteLLMConnector,
    testLLMConnector,
    SUGGESTED_MODELS,
} from '@/services/ai.service'

/**
 * AI Assistant settings tab — the bring-your-own-key LLM connector.
 *
 * Lets a user store an OpenAI or Anthropic key (encrypted server-side), pick a
 * model, test the connection, and remove it. The key is write-only: the server
 * never returns it, so the input is only for entering a new or replacement key;
 * an existing key is shown as a masked hint.
 */

const PROVIDERS: { id: LLMProvider; label: string }[] = [
    { id: 'openai', label: 'OpenAI' },
    { id: 'anthropic', label: 'Anthropic' },
]

type TestState = { ok: boolean; detail: string } | null

export function AIAssistantTab() {
    const [loading, setLoading] = useState(true)
    const [connector, setConnector] = useState<LLMConnector | null>(null)
    const [provider, setProvider] = useState<LLMProvider>('openai')
    const [model, setModel] = useState<string>(SUGGESTED_MODELS.openai[0]!)
    const [apiKey, setApiKey] = useState('')
    const [enabled, setEnabled] = useState(true)

    const [saving, setSaving] = useState(false)
    const [testing, setTesting] = useState(false)
    const [testResult, setTestResult] = useState<TestState>(null)
    const [message, setMessage] = useState<string | null>(null)

    useEffect(() => {
        let cancelled = false
        getLLMConnector()
            .then((c) => {
                if (cancelled) return
                setConnector(c)
                if (c.provider) setProvider(c.provider)
                if (c.model) setModel(c.model)
                setEnabled(c.enabled)
            })
            .catch(() => undefined)
            .finally(() => !cancelled && setLoading(false))
        return () => {
            cancelled = true
        }
    }, [])

    // When the provider changes, keep the model valid for that provider.
    function handleProviderChange(next: LLMProvider) {
        setProvider(next)
        if (!SUGGESTED_MODELS[next].includes(model)) {
            setModel(SUGGESTED_MODELS[next][0]!)
        }
        setTestResult(null)
    }

    const hasKey = connector?.has_key ?? false

    async function handleSave() {
        setMessage(null)
        if (!hasKey && !apiKey.trim()) {
            setMessage('An API key is required to connect.')
            return
        }
        setSaving(true)
        try {
            const saved = await saveLLMConnector({
                provider,
                model,
                enabled,
                api_key: apiKey.trim() || undefined,
            })
            setConnector(saved)
            setApiKey('')
            setMessage('Saved.')
        } catch {
            setMessage('Could not save the connector. Check the key and try again.')
        } finally {
            setSaving(false)
        }
    }

    async function handleTest() {
        setTesting(true)
        setTestResult(null)
        try {
            const result = apiKey.trim()
                ? await testLLMConnector({ provider, api_key: apiKey.trim() })
                : await testLLMConnector()
            setTestResult(result)
        } catch {
            setTestResult({ ok: false, detail: 'Test request failed.' })
        } finally {
            setTesting(false)
        }
    }

    async function handleRemove() {
        setSaving(true)
        try {
            await deleteLLMConnector()
            setConnector({ provider: null, model: null, enabled: false, has_key: false })
            setApiKey('')
            setTestResult(null)
            setMessage('Connector removed.')
        } catch {
            setMessage('Could not remove the connector.')
        } finally {
            setSaving(false)
        }
    }

    return (
        <>
            <header className="mb-10">
                <div
                    className="h-1 w-16 mb-5 rounded-full opacity-80"
                    style={{
                        background: 'repeating-linear-gradient(-45deg, #FF6363, #FF6363 4px, transparent 4px, transparent 8px)',
                    }}
                />
                <h2 className="font-display text-[28px] md:text-[36px] font-bold text-content-primary leading-tight mb-2 tracking-[-0.5px]">
                    AI Assistant
                </h2>
                <p className="text-content-secondary text-sm max-w-2xl leading-relaxed">
                    Connect your own LLM provider. Your API key is encrypted on the server and never shared.
                    It powers the upcoming "Explain this emulation" features. You are billed by your provider.
                </p>
            </header>

            {loading ? (
                <div className="text-content-dim font-mono text-sm">Loading...</div>
            ) : (
                <div className="space-y-8">
                    <section className="bg-surface-card rounded-[12px] border border-border p-6 md:p-8 shadow-ring">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="font-display text-lg font-semibold text-content-primary">LLM Connector</h3>
                            <span
                                className={`font-mono text-[11px] px-2.5 py-1 rounded-full ${hasKey
                                    ? 'text-safe bg-safe-dim'
                                    : 'text-content-dim bg-white/[0.04]'}`}
                            >
                                {hasKey ? 'Connected' : 'Not connected'}
                            </span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                            {/* Provider */}
                            <Field label="Provider">
                                <select
                                    value={provider}
                                    onChange={(e) => handleProviderChange(e.target.value as LLMProvider)}
                                    className="w-full bg-surface-base border border-border rounded-btn px-3 py-2.5 text-sm text-content-primary outline-none focus:border-border-active"
                                >
                                    {PROVIDERS.map((p) => (
                                        <option key={p.id} value={p.id}>{p.label}</option>
                                    ))}
                                </select>
                            </Field>

                            {/* Model */}
                            <Field label="Model">
                                <select
                                    value={model}
                                    onChange={(e) => setModel(e.target.value)}
                                    className="w-full bg-surface-base border border-border rounded-btn px-3 py-2.5 text-sm text-content-primary outline-none focus:border-border-active"
                                >
                                    {SUGGESTED_MODELS[provider].map((m) => (
                                        <option key={m} value={m}>{m}</option>
                                    ))}
                                </select>
                            </Field>
                        </div>

                        {/* API key */}
                        <Field label="API Key" className="mt-5">
                            <input
                                type="password"
                                value={apiKey}
                                onChange={(e) => setApiKey(e.target.value)}
                                placeholder={hasKey ? `•••• •••• ${connector?.key_hint ?? ''}` : 'sk-... (stored encrypted)'}
                                autoComplete="off"
                                className="w-full bg-surface-base border border-border rounded-btn px-3 py-2.5 text-sm font-mono text-content-primary placeholder:text-content-dim outline-none focus:border-border-active"
                            />
                            <p className="text-content-dim text-xs mt-2">
                                {hasKey
                                    ? 'A key is stored. Enter a new one only to replace it.'
                                    : 'Your key is encrypted at rest and never returned by the server.'}
                            </p>
                        </Field>

                        {/* Enabled toggle */}
                        <div className="flex items-center justify-between mt-6 pt-6 border-t border-white/[0.05]">
                            <div>
                                <p className="text-content-primary text-sm font-medium">Enabled</p>
                                <p className="text-content-dim text-xs mt-0.5">Allow AI features to use this connector.</p>
                            </div>
                            <button
                                type="button"
                                role="switch"
                                aria-checked={enabled}
                                onClick={() => setEnabled((v) => !v)}
                                className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none"
                                style={{ backgroundColor: enabled ? '#FF6363' : 'rgba(255,255,255,0.1)' }}
                            >
                                <span
                                    className={`pointer-events-none inline-block h-4 w-4 transform rounded-full transition duration-200 ${enabled ? 'translate-x-4 bg-white' : 'translate-x-0 bg-content-secondary'}`}
                                />
                            </button>
                        </div>

                        {/* Test result + message */}
                        {testResult && (
                            <div
                                className={`mt-5 font-mono text-[12px] px-4 py-2.5 rounded-btn border ${testResult.ok
                                    ? 'text-safe bg-safe-dim border-safe/25'
                                    : 'text-danger bg-danger-dim border-danger/25'}`}
                            >
                                {testResult.ok ? 'OK · ' : 'Failed · '}{testResult.detail}
                            </div>
                        )}
                        {message && <div className="mt-3 text-content-secondary text-xs">{message}</div>}
                    </section>

                    {/* Action bar */}
                    <div className="flex items-center justify-between gap-4 border-t border-white/[0.05] pt-7">
                        <button
                            onClick={handleRemove}
                            disabled={!hasKey || saving}
                            className="text-sm font-medium text-danger hover:opacity-70 transition-opacity bg-transparent border-none cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                            Remove connector
                        </button>
                        <div className="flex items-center gap-3">
                            <button
                                onClick={handleTest}
                                disabled={testing || (!hasKey && !apiKey.trim())}
                                className="px-4 py-2 rounded-btn text-sm font-medium text-content-primary bg-transparent border border-border hover:bg-white/[0.05] transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                                {testing ? 'Testing...' : 'Test connection'}
                            </button>
                            <button
                                onClick={handleSave}
                                disabled={saving}
                                className="px-5 py-2 rounded-pill bg-white/10 hover:bg-white/[0.15] text-content-primary shadow-ring transition-all text-sm font-semibold border border-border active:scale-[0.98] cursor-pointer disabled:opacity-40"
                            >
                                {saving ? 'Saving...' : 'Save'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </>
    )
}

/* ── Field wrapper ── */
function Field({ label, children, className = '' }: { label: string; children: React.ReactNode; className?: string }) {
    return (
        <div className={className}>
            <label className="block text-content-secondary text-xs font-mono uppercase tracking-label mb-2">{label}</label>
            {children}
        </div>
    )
}
