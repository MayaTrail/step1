interface TagProps {
  children: React.ReactNode
  className?: string
}

export function Tag({ children, className = '' }: TagProps) {
  return (
    <span className={`bg-danger/[0.1] rounded-[6px] px-2.5 py-0.5
      font-mono text-[0.65rem] text-danger tracking-[0.5px] uppercase font-medium ${className}`}>
      {children}
    </span>
  )
}
