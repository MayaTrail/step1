import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

/**
 * Markdown — renders assistant output with the MayaTrail design system.
 *
 * Security: raw HTML is NOT enabled (no rehype-raw), so LLM output cannot inject
 * HTML or scripts. Links open in a new tab with rel="noopener". Element styles
 * map to design tokens so rendered chat looks native rather than like default
 * Markdown.
 */

export function Markdown({ content }: { content: string }) {
    return (
        <div className="text-content-secondary text-[14px] leading-[1.7]">
            <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                    p: ({ children }) => <p className="mb-3 last:mb-0">{children}</p>,
                    ul: ({ children }) => <ul className="list-disc pl-5 mb-3 space-y-1">{children}</ul>,
                    ol: ({ children }) => <ol className="list-decimal pl-5 mb-3 space-y-1">{children}</ol>,
                    li: ({ children }) => <li className="leading-[1.6]">{children}</li>,
                    h1: ({ children }) => <h3 className="font-display text-base font-semibold text-content-primary mt-4 mb-2">{children}</h3>,
                    h2: ({ children }) => <h3 className="font-display text-base font-semibold text-content-primary mt-4 mb-2">{children}</h3>,
                    h3: ({ children }) => <h4 className="font-display text-sm font-semibold text-content-primary mt-3 mb-1.5">{children}</h4>,
                    strong: ({ children }) => <strong className="font-semibold text-content-primary">{children}</strong>,
                    em: ({ children }) => <em className="italic">{children}</em>,
                    a: ({ href, children }) => (
                        <a href={href} target="_blank" rel="noreferrer noopener" className="text-accent-blue hover:underline">
                            {children}
                        </a>
                    ),
                    blockquote: ({ children }) => (
                        <blockquote className="border-l-2 border-border pl-3 my-3 text-content-dim italic">{children}</blockquote>
                    ),
                    pre: ({ children }) => (
                        <pre className="bg-surface-deep border border-border rounded-btn p-3.5 overflow-x-auto my-3 text-[13px]">{children}</pre>
                    ),
                    code: ({ className, children }) => {
                        const text = String(children)
                        const isInline = !className && !text.includes('\n')
                        if (isInline) {
                            return <code className="font-mono text-[0.85em] bg-white/[0.06] text-content-primary rounded px-1 py-0.5">{children}</code>
                        }
                        // Block code stays neutral: brighter primary text on the darker
                        // surface-deep block sets it apart from prose without a colour hue.
                        return <code className="font-mono text-content-primary leading-relaxed">{children}</code>
                    },
                    table: ({ children }) => (
                        <div className="overflow-x-auto my-3">
                            <table className="w-full text-[13px] border-collapse">{children}</table>
                        </div>
                    ),
                    th: ({ children }) => <th className="text-left border border-border px-2 py-1 text-content-primary font-semibold">{children}</th>,
                    td: ({ children }) => <td className="border border-border px-2 py-1">{children}</td>,
                }}
            >
                {content}
            </ReactMarkdown>
        </div>
    )
}
