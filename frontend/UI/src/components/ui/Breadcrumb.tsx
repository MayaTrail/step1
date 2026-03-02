import { Link } from 'react-router-dom'

interface BreadcrumbItem {
  label: string
  to?: string
}

export function Breadcrumb({ items }: { items: BreadcrumbItem[] }) {
  return (
    <div className="font-mono text-[11px] text-content-dim mb-4 flex items-center gap-1.5">
      {items.map((item, i) => (
        <span key={i} className="flex items-center gap-1.5">
          {i > 0 && <span className="text-content-dim">/</span>}
          {item.to ? (
            <Link to={item.to} className="text-content-dim no-underline hover:text-content-secondary transition-colors">
              {item.label}
            </Link>
          ) : (
            <span className="text-content-secondary">{item.label}</span>
          )}
        </span>
      ))}
    </div>
  )
}
