/**
 * The per-entity glyph.
 *
 * Keyed on Scout's NodeType, which only a node from the stored graph carries —
 * every scan stored before that field existed has none, and so does every node
 * the envelope derived by parsing an ARN. Both fall through to the letter
 * badge, which is also what an uncurated NodeType gets. There is no broken-image
 * state by construction: NODE_TYPE_ICON is a lookup, and a miss is a badge.
 *
 * NODE_TYPE_ICON is empty until the AWS Architecture Icons are added. Until
 * then every entity renders as a badge, exactly as it did before this feature.
 */

/** Scout NodeType -> imported SVG url. Populated when the icons land. */
export const NODE_TYPE_ICON: Record<string, string> = {}

function initials(label: string): string {
  const trimmed = (label || '?').trim()
  return trimmed.slice(0, 3).toUpperCase()
}

export function NodeIcon({
  nodeType, label, size = 20,
}: { nodeType?: string; label: string; size?: number }) {
  const src = nodeType ? NODE_TYPE_ICON[nodeType] : undefined

  if (src) {
    return (
      <img
        src={src}
        alt=""
        width={size}
        height={size}
        // Decorative: the entity's name is rendered next to it as text, so a
        // screen reader announcing the icon would just repeat it.
        aria-hidden="true"
        className="shrink-0"
      />
    )
  }

  return (
    <span
      aria-hidden="true"
      className="shrink-0 inline-flex items-center justify-center rounded bg-surface-elevated text-content-secondary font-mono"
      style={{ width: size, height: size, fontSize: size * 0.38 }}
    >
      {initials(label)}
    </span>
  )
}
