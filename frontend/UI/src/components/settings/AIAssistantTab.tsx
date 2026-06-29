import { useEffect, useState } from 'react'
import type { LLMConnector, LLMProvider } from '@/types'
import {
    getLLMConnector,
    saveLLMConnector,
    deleteLLMConnector,
    testLLMConnector,
    SUGGESTED_MODELS,
} from '@/services/ai.service'
import { SectionHeader } from './SectionHeader'

/**
 * AI Assistant settings tab — the bring-your-own-key LLM connector.
 *
 * Key-based providers (OpenAI, Anthropic) store a write-only key, encrypted
 * server-side; the server never returns it, so the input is only for entering a
 * new or replacement key, and an existing key shows as a masked hint. Amazon
 * Bedrock stores no key: it authenticates through the user's connected AWS role
 * and only needs a region, so its inference is billed to the user's AWS account
 * (disclosed below).
 */

const PROVIDERS: { id: LLMProvider; label: string }[] = [
    { id: 'openai', label: 'OpenAI' },
    { id: 'anthropic', label: 'Anthropic' },
    { id: 'bedrock', label: 'Amazon Bedrock' },
]

type TestState = { ok: boolean; detail: string } | null

// Module-level cache of the last-loaded connector. Switching Settings tabs
// remounts this panel; seeding from the cache shows the saved connector
// immediately and revalidates in the background, instead of flashing "Loading...".
let _connectorCache: LLMConnector | undefined

export function AIAssistantTab() {
    const [loading, setLoading] = useState(_connectorCache === undefined)
    const [connector, setConnector] = useState<LLMConnector | null>(_connectorCache ?? null)
    const [provider, setProvider] = useState<LLMProvider>(_connectorCache?.provider ?? 'openai')
    const [model, setModel] = useState<string>(_connectorCache?.model ?? SUGGESTED_MODELS.openai[0]!)
    const [apiKey, setApiKey] = useState('')
    const [region, setRegion] = useState(_connectorCache?.region ?? '')
    const [enabled, setEnabled] = useState(_connectorCache?.enabled ?? true)

    const [saving, setSaving] = useState(false)
    const [testing, setTesting] = useState(false)
    const [testResult, setTestResult] = useState<TestState>(null)
    const [message, setMessage] = useState<string | null>(null)

    useEffect(() => {
        let cancelled = false
        getLLMConnector()
            .then((c) => {
                if (cancelled) return
                _connectorCache = c
                setConnector(c)
                if (c.provider) setProvider(c.provider)
                if (c.model) setModel(c.model)
                if (c.region) setRegion(c.region)
                setEnabled(c.enabled)
            })
            .catch(() => undefined)
            .finally(() => !cancelled && setLoading(false))
        return () => {
            cancelled = true
        }
    }, [])

    const isBedrock = provider === 'bedrock'
    const hasKey = connector?.has_key ?? false
    // "Connected" reflects the saved connector: a stored key, or a saved Bedrock
    // connector (which carries no key, so has_key is always false for it).
    const connected = connector?.provider === 'bedrock' ? true : hasKey
    // Bedrock can be tested once a region is set; key providers need a key.
    const canTest = isBedrock ? !!region.trim() : hasKey || !!apiKey.trim()

    // When the provider changes, keep the model valid for that provider.
    function handleProviderChange(next: LLMProvider) {
        setProvider(next)
        if (!SUGGESTED_MODELS[next].includes(model)) {
            setModel(SUGGESTED_MODELS[next][0]!)
        }
        setTestResult(null)
    }

    async function handleSave() {
        setMessage(null)
        if (isBedrock) {
            if (!region.trim()) {
                setMessage('An AWS region is required for Amazon Bedrock.')
                return
            }
        } else if (!hasKey && !apiKey.trim()) {
            setMessage('An API key is required to connect.')
            return
        }
        setSaving(true)
        try {
            const saved = await saveLLMConnector({
                provider,
                model,
                enabled,
                api_key: isBedrock ? undefined : apiKey.trim() || undefined,
                region: isBedrock ? region.trim() : undefined,
            })
            _connectorCache = saved
            setConnector(saved)
            setApiKey('')
            setMessage('Saved.')
        } catch {
            setMessage(
                isBedrock
                    ? 'Could not save the connector. Check the region and try again.'
                    : 'Could not save the connector. Check the key and try again.',
            )
        } finally {
            setSaving(false)
        }
    }

    async function handleTest() {
        setTesting(true)
        setTestResult(null)
        try {
            let result
            if (isBedrock) {
                result = await testLLMConnector({ provider, region: region.trim() || undefined })
            } else if (apiKey.trim()) {
                result = await testLLMConnector({ provider, api_key: apiKey.trim() })
            } else {
                result = await testLLMConnector()
            }
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
            const cleared: LLMConnector = { provider: null, model: null, region: null, enabled: false, has_key: false }
            _connectorCache = cleared
            setConnector(cleared)
            setApiKey('')
            setRegion('')
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
            <SectionHeader
                title="AI Assistant"
                description={'Connect your own LLM provider to power the "Explain this emulation" features. API keys are encrypted on the server and never shared; Amazon Bedrock authenticates through your connected AWS role instead. You are billed by your provider.'}
            />

            {loading ? (
                <div className="text-content-dim font-mono text-sm">Loading...</div>
            ) : (
                <div className="space-y-8">
                    <section className="bg-surface-card rounded-[12px] border border-border p-6 md:p-8 shadow-ring">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="font-display text-lg font-semibold text-content-primary">LLM Connector</h3>
                            <span
                                className={`font-mono text-[11px] px-2.5 py-1 rounded-full ${connected
                                    ? 'text-safe bg-safe-dim'
                                    : 'text-content-dim bg-white/[0.04]'}`}
                            >
                                {connected ? 'Connected' : 'Not connected'}
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

                            {/* Model — a fixed dropdown for key providers; a free-text
                                field with suggestions for Bedrock, whose valid
                                inference-profile ids vary by region and account. */}
                            <Field label="Model">
                                {isBedrock ? (
                                    <>
                                        <input
                                            type="text"
                                            list="bedrock-models"
                                            value={model}
                                            onChange={(e) => setModel(e.target.value)}
                                            placeholder="us.anthropic.claude-sonnet-4-6"
                                            autoComplete="off"
                                            className="w-full bg-surface-base border border-border rounded-btn px-3 py-2.5 text-sm font-mono text-content-primary placeholder:text-content-dim outline-none focus:border-border-active"
                                        />
                                        <datalist id="bedrock-models">
                                            {SUGGESTED_MODELS.bedrock.map((m) => (
                                                <option key={m} value={m} />
                                            ))}
                                        </datalist>
                                        <p className="text-content-dim text-xs mt-2">
                                            Inference-profile id; the prefix must match your region —
                                            <code className="font-mono text-content-secondary"> us.</code> for US regions,
                                            <code className="font-mono text-content-secondary"> apac.</code> for ap-south-1,
                                            <code className="font-mono text-content-secondary"> eu.</code> for EU.
                                        </p>
                                    </>
                                ) : (
                                    <select
                                        value={model}
                                        onChange={(e) => setModel(e.target.value)}
                                        className="w-full bg-surface-base border border-border rounded-btn px-3 py-2.5 text-sm text-content-primary outline-none focus:border-border-active"
                                    >
                                        {SUGGESTED_MODELS[provider].map((m) => (
                                            <option key={m} value={m}>{m}</option>
                                        ))}
                                    </select>
                                )}
                            </Field>
                        </div>

                        {/* Credentials — a key for key providers, a region for Bedrock */}
                        {isBedrock ? (
                            <>
                                <Field label="AWS Region" className="mt-5">
                                    <input
                                        type="text"
                                        value={region}
                                        onChange={(e) => setRegion(e.target.value)}
                                        placeholder="us-east-1"
                                        autoComplete="off"
                                        className="w-full bg-surface-base border border-border rounded-btn px-3 py-2.5 text-sm font-mono text-content-primary placeholder:text-content-dim outline-none focus:border-border-active"
                                    />
                                    <p className="text-content-dim text-xs mt-2">
                                        Bedrock is region-scoped. Use a region where your models have access enabled.
                                    </p>
                                </Field>

                                {/* Cost + IAM disclosure — Bedrock bills the user's own AWS account */}
                                <div className="mt-5 rounded-btn border border-warning/25 bg-warning-dim p-4">
                                    <p className="text-warning text-sm font-semibold mb-1.5">Billed to your AWS account</p>
                                    <p className="text-content-secondary text-xs leading-relaxed">
                                        Bedrock inference runs under the IAM role MayaTrail assumes, so model usage is
                                        charged to your connected AWS account — the same one used for simulations.
                                        Pricing varies by model and region.
                                    </p>
                                    <p className="text-content-dim text-xs leading-relaxed mt-2">
                                        Grant{' '}
                                        <code className="font-mono text-content-secondary">bedrock:InvokeModelWithResponseStream</code>{' '}
                                        and{' '}
                                        <code className="font-mono text-content-secondary">bedrock:ListFoundationModels</code>{' '}
                                        to the role. Serverless models are enabled by default, but Anthropic Claude needs
                                        a one-time usage form per AWS account (complete it once in the Bedrock playground)
                                        before its first use. A passing connection test confirms access to list models,
                                        not that the chosen model can be invoked.
                                    </p>
                                </div>
                            </>
                        ) : (
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
                        )}

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
                            disabled={!connected || saving}
                            className="text-sm font-medium text-danger hover:opacity-70 transition-opacity bg-transparent border-none cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                            Remove connector
                        </button>
                        <div className="flex items-center gap-3">
                            <button
                                onClick={handleTest}
                                disabled={testing || !canTest}
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
