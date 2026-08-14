/** Colour treatments a Tag can take. `danger` is the default so existing
 *  call-sites (emulation threat tags) keep their appearance. */
type TagTone = 'danger' | 'info' | 'muted'

const toneClasses: Record<TagTone, string> = {
  danger: 'bg-danger/[0.1] text-danger',
  info: 'bg-accent-blue/[0.1] text-accent-blue',
  muted: 'bg-[rgba(255,255,255,0.05)] text-content-dim',
}

interface TagProps {
  children: React.ReactNode
  tone?: TagTone
  title?: string
  className?: string
}

export function Tag({ children, tone = 'danger', title, className = '' }: TagProps) {
  return (
    <span
      title={title}
      className={`${toneClasses[tone]} rounded-[6px] px-2.5 py-0.5
      font-mono text-[0.65rem] tracking-[0.5px] uppercase font-medium ${className}`}
    >
      {children}
    </span>
  )
}
