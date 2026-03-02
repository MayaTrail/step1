interface EmptyStateProps {
  icon: string
  title: string
  body: string
}

export function EmptyState({ icon, title, body }: EmptyStateProps) {
  return (
    <div className="text-center py-20 px-5 text-content-dim">
      <div className="w-16 h-16 rounded-card bg-surface-card border border-border mx-auto mb-4 flex items-center justify-center text-[32px]">{icon}</div>
      <div className="font-display text-lg font-bold text-content-primary mb-2">{title}</div>
      <div className="text-[0.9rem] text-content-secondary leading-[1.7] max-w-md mx-auto" dangerouslySetInnerHTML={{ __html: body }} />
    </div>
  )
}
