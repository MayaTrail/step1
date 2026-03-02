interface CodeBlockProps {
  code: string
  className?: string
}

export function CodeBlock({ code, className = '' }: CodeBlockProps) {
  return (
    <div
      className={`bg-[rgba(0,0,0,0.3)] border border-border rounded-btn px-4 py-3.5 font-mono text-[0.73rem] text-content-secondary
        mt-2.5 overflow-x-auto leading-[1.6] whitespace-pre ${className}`}
    >
      {code}
    </div>
  )
}
