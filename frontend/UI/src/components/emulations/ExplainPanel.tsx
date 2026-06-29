import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import type { ChatMessage, Conversation, Emulation, Reference } from '@/types'
import { Markdown } from '@/components/common/Markdown'
import {
    getLLMConnector,
    listConversations,
    createConversation,
    getConversation,
    deleteConversation,
    streamMessage,
} from '@/services/ai.service'

/**
 * ExplainPanel — multi-turn "Ask AI" chat about one emulation.
 *
 * Left: a streaming chat grounded server-side on the emulation MANIFEST, with
 * persisted history (conversations load on mount). Right: recent conversations
 * plus the emulation's references as a hyperlinked sidebar.
 *
 * The ask panel is connect-gated (prompts to connect a key when none exists);
 * the references stay visible to everyone. Grounding is rebuilt on the server
 * each turn, so the client only ever sends the conversation content.
 */

const SUGGESTIONS = [
    'Explain this emulation',
    'How would a defender detect this?',
    'Which phase is hardest to detect, and why?',
]

export function ExplainPanel({ emulation }: { emulation: Emulation }) {
    const [checkingConnector, setCheckingConnector] = useState(true)
    const [hasConnector, setHasConnector] = useState(false)
    const [provider, setProvider] = useState<string | null>(null)

    const [conversations, setConversations] = useState<Conversation[]>([])
    const [activeId, setActiveId] = useState<string | null>(null)
    const [messages, setMessages] = useState<ChatMessage[]>([])

    const [input, setInput] = useState('')
    const [streaming, setStreaming] = useState(false)
    const [streamingText, setStreamingText] = useState('')
    const [error, setError] = useState<string | null>(null)

    const bottomRef = useRef<HTMLDivElement>(null)

    // Load connector state and any existing conversations for this emulation.
    useEffect(() => {
        let cancelled = false
        async function load() {
            try {
                const connector = await getLLMConnector()
                if (cancelled) return
                // Bedrock authenticates via the assumed AWS role and stores no
                // key, so has_key is always false for it; treat a saved, enabled
                // Bedrock connector as connected just like a key-based one.
                const configured =
                    connector.provider === 'bedrock'
                        ? Boolean(connector.region)
                        : Boolean(connector.has_key)
                setHasConnector(configured && connector.enabled)
                setProvider(connector.provider)
                const convos = await listConversations(emulation.id)
                if (cancelled) return
                setConversations(convos)
                if (convos.length > 0 && convos[0]) {
                    const full = await getConversation(convos[0].id)
                    if (cancelled) return
                    setActiveId(full.id)
                    setMessages(full.messages ?? [])
                }
            } catch {
                /* leave empty; UI handles the no-connector / no-history case */
            } finally {
                if (!cancelled) setCheckingConnector(false)
            }
        }
        load()
        return () => {
            cancelled = true
        }
    }, [emulation.id])

    // Keep the latest message in view while streaming.
    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    }, [messages, streamingText])

    async function send(content: string) {
        const text = content.trim()
        if (!text || streaming) return
        setError(null)
        setInput('')

        // Ensure a conversation exists.
        let conversationId = activeId
        try {
            if (!conversationId) {
                const created = await createConversation(emulation.id)
                conversationId = created.id
                setActiveId(created.id)
                setConversations((prev) => [{ ...created, title: text.slice(0, 60) }, ...prev])
            }
        } catch {
            setError('Could not start a conversation. Please try again.')
            return
        }

        // Optimistically show the user's turn.
        const userMsg: ChatMessage = {
            id: crypto.randomUUID(),
            role: 'user',
            content: text,
            created_at: new Date().toISOString(),
        }
        setMessages((prev) => [...prev, userMsg])
        setStreaming(true)
        setStreamingText('')

        let acc = ''
        try {
            await streamMessage(conversationId, text, (chunk) => {
                acc += chunk
                setStreamingText(acc)
            })
            // Commit the streamed assistant turn (already persisted server-side).
            setMessages((prev) => [
                ...prev,
                {
                    id: crypto.randomUUID(),
                    role: 'assistant',
                    content: acc.trim(),
                    created_at: new Date().toISOString(),
                },
            ])
        } catch (err) {
            setError(err instanceof Error ? err.message : 'The chat request failed.')
        } finally {
            setStreaming(false)
            setStreamingText('')
        }
    }

    function newChat() {
        setActiveId(null)
        setMessages([])
        setError(null)
        setStreamingText('')
    }

    async function switchTo(id: string) {
        if (id === activeId) return
        try {
            const full = await getConversation(id)
            setActiveId(full.id)
            setMessages(full.messages ?? [])
            setError(null)
        } catch {
            setError('Could not load that conversation.')
        }
    }

    async function removeConversation(id: string) {
        try {
            await deleteConversation(id)
            setConversations((prev) => prev.filter((c) => c.id !== id))
            if (id === activeId) newChat()
        } catch {
            setError('Could not delete that conversation.')
        }
    }

    const empty = messages.length === 0 && !streaming

    return (
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_280px] gap-6 animate-fadeIn">
            {/* ── Chat panel ── */}
            <main className="min-w-0 flex flex-col">
                {checkingConnector ? (
                    <div className="text-content-dim font-mono text-sm py-6">Loading...</div>
                ) : !hasConnector ? (
                    <div className="bg-surface-card rounded-card border border-border shadow-ring p-6 md:p-7">
                        <h3 className="font-display text-lg font-semibold text-content-primary mb-1">
                            Ask about this emulation
                        </h3>
                        <p className="text-content-dim text-sm mb-5 leading-relaxed">
                            Have a grounded conversation about this attack, built from its threat intel, attack
                            path, and MITRE mapping.
                        </p>
                        <ConnectPrompt />
                    </div>
                ) : (
                    <div className="bg-surface-card rounded-card border border-border shadow-ring flex flex-col min-h-[420px]">
                        {/* Messages */}
                        <div className="flex-1 overflow-y-auto p-5 md:p-6 space-y-5 max-h-[60vh]">
                            {empty && (
                                <div className="text-center py-10">
                                    <p className="text-content-secondary text-sm mb-1">Ask about this emulation</p>
                                    <p className="text-content-dim text-xs mb-5 max-w-sm mx-auto leading-relaxed">
                                        Grounded on this emulation's data. Try one of these, or ask your own question.
                                    </p>
                                    <div className="flex flex-wrap gap-2 justify-center">
                                        {SUGGESTIONS.map((s) => (
                                            <button
                                                key={s}
                                                onClick={() => send(s)}
                                                className="text-xs text-content-secondary bg-white/[0.04] hover:bg-white/[0.08] border border-border rounded-full px-3 py-1.5 transition-colors cursor-pointer"
                                            >
                                                {s}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {messages.map((m) =>
                                m.role === 'user' ? (
                                    <div key={m.id} className="flex justify-end">
                                        <div className="bg-white/[0.06] border border-border rounded-card px-4 py-2.5 max-w-[85%] text-content-primary text-[14px] whitespace-pre-wrap">
                                            {m.content}
                                        </div>
                                    </div>
                                ) : (
                                    <div key={m.id} className="max-w-full">
                                        <Markdown content={m.content} />
                                    </div>
                                ),
                            )}

                            {streaming && (
                                <div className="max-w-full">
                                    {streamingText ? (
                                        <Markdown content={streamingText} />
                                    ) : (
                                        <p className="text-content-dim text-sm animate-pulse">Thinking...</p>
                                    )}
                                </div>
                            )}

                            {error && (
                                <div className="bg-danger-dim border border-danger/25 rounded-btn p-3 text-danger text-sm">
                                    {error}
                                </div>
                            )}
                            <div ref={bottomRef} />
                        </div>

                        {/* Composer */}
                        <div className="border-t border-white/[0.05] p-4">
                            <div className="flex gap-2">
                                <input
                                    value={input}
                                    onChange={(e) => setInput(e.target.value)}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter' && !e.shiftKey) {
                                            e.preventDefault()
                                            send(input)
                                        }
                                    }}
                                    disabled={streaming}
                                    placeholder="Ask a question about this emulation..."
                                    className="flex-1 min-w-0 bg-surface-base border border-border rounded-btn px-3 py-2.5 text-sm text-content-primary placeholder:text-content-dim outline-none focus:border-border-active disabled:opacity-50"
                                />
                                <button
                                    onClick={() => send(input)}
                                    disabled={streaming || !input.trim()}
                                    className="px-5 py-2.5 rounded-pill bg-white/10 hover:bg-white/[0.15] text-content-primary shadow-ring transition-all text-sm font-semibold border border-border active:scale-[0.98] cursor-pointer disabled:opacity-40"
                                >
                                    Send
                                </button>
                            </div>
                            <p className="text-content-dim text-[11px] mt-2">
                                Runs on your {provider ?? 'provider'} key. You are billed by your provider.
                            </p>
                        </div>
                    </div>
                )}
            </main>

            {/* ── Sidebar: conversations + references ── */}
            <aside className="min-w-0 space-y-6">
                {hasConnector && (
                    <div>
                        <div className="flex items-center justify-between mb-3">
                            <h4 className="font-mono text-[11px] uppercase tracking-label text-content-dim">Chats</h4>
                            <button
                                onClick={newChat}
                                className="text-[11px] text-content-secondary hover:text-content-primary transition-colors cursor-pointer bg-transparent border-none"
                            >
                                + New
                            </button>
                        </div>
                        <div className="flex flex-col gap-1.5">
                            {conversations.length === 0 && (
                                <p className="text-content-dim text-xs">No conversations yet.</p>
                            )}
                            {conversations.map((c) => (
                                <div
                                    key={c.id}
                                    className={`group flex items-center gap-2 rounded-btn px-2.5 py-2 border transition-colors cursor-pointer ${c.id === activeId
                                        ? 'bg-white/[0.06] border-border'
                                        : 'bg-transparent border-transparent hover:bg-white/[0.03]'}`}
                                    onClick={() => switchTo(c.id)}
                                >
                                    <span className="flex-1 min-w-0 truncate text-[12px] text-content-secondary">
                                        {c.title || 'Untitled chat'}
                                    </span>
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation()
                                            removeConversation(c.id)
                                        }}
                                        className="opacity-0 group-hover:opacity-100 text-content-dim hover:text-danger transition-opacity text-xs bg-transparent border-none cursor-pointer"
                                        aria-label="Delete conversation"
                                    >
                                        ✕
                                    </button>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                <div>
                    <h4 className="font-mono text-[11px] uppercase tracking-label text-content-dim mb-3">References</h4>
                    <div className="flex flex-col gap-2">
                        {emulation.references.length === 0 && (
                            <p className="text-content-dim text-xs">No references for this emulation.</p>
                        )}
                        {emulation.references.map((ref, i) => (
                            <RefLink key={`${ref.title}-${i}`} reference={ref} />
                        ))}
                    </div>
                </div>
            </aside>
        </div>
    )
}

/* ── Connect-your-LLM empty state ── */
function ConnectPrompt() {
    return (
        <div className="border border-dashed border-border rounded-card p-6 text-center">
            <p className="text-content-secondary text-sm mb-1.5">No LLM connected</p>
            <p className="text-content-dim text-xs mb-4 max-w-sm mx-auto leading-relaxed">
                Connect your own OpenAI or Anthropic key to chat about this emulation. The references on the
                right are available without a connection.
            </p>
            <Link
                to="/settings"
                className="inline-block px-4 py-2 rounded-pill bg-white/10 hover:bg-white/[0.15] text-content-primary shadow-ring transition-all text-sm font-semibold border border-border"
            >
                Connect in Settings
            </Link>
        </div>
    )
}

/* ── One reference link ── */
function asUrl(value: string): string | null {
    return /^https?:\/\//i.test(value) ? value : null
}

function safeHostname(url: string): string {
    try {
        return new URL(url).hostname.replace(/^www\./, '')
    } catch {
        return url
    }
}

function RefLink({ reference }: { reference: Reference }) {
    const url = reference.url ?? asUrl(reference.source)
    const meta = url ? safeHostname(url) : reference.source

    const inner = (
        <>
            <span className="text-base leading-none mt-0.5 shrink-0">{reference.icon}</span>
            <span className="min-w-0">
                <span className="block text-content-primary text-[13px] font-medium leading-snug truncate">
                    {reference.title}
                </span>
                <span className="block text-content-dim text-[11px] font-mono truncate">{meta}</span>
            </span>
        </>
    )

    if (!url) {
        return (
            <div className="flex items-start gap-2.5 bg-surface-card border border-border rounded-btn px-3 py-2.5">
                {inner}
            </div>
        )
    }
    return (
        <a
            href={url}
            target="_blank"
            rel="noreferrer noopener"
            className="flex items-start gap-2.5 bg-surface-card border border-border rounded-btn px-3 py-2.5 hover:border-border-active hover:opacity-80 transition-all"
        >
            {inner}
        </a>
    )
}
