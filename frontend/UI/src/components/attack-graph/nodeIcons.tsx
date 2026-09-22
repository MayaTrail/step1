/**
 * The per-entity glyph.
 *
 * Keyed on Scout's NodeType, which only a node from the stored graph carries —
 * every scan stored before that field existed has none, and so does every node
 * the envelope derived by parsing an ARN. Both fall through to the letter
 * badge, which is also what an uncurated NodeType gets. There is no broken-image
 * state by construction: NODE_TYPE_ICON is a lookup, and a miss is a badge.
 *
 * Only two entries: `IAM_ROLE` gets AWS's own Role icon, and every `RESOURCE`
 * (an S3 bucket, an EC2 instance, a Lambda function, ...) shares one generic
 * resource icon. That second part is a deliberate scope cut, not an
 * oversight: `ChainNode.node_type` only ever carries Scout's coarse
 * `NodeType` ("RESOURCE" for all of them), never `properties.resource_type`
 * — that finer distinction lives only on `GraphEntity`, fetched per node in
 * the entity panel. Keying `NODE_TYPE_ICON` by `resource_type` would need
 * that field threaded through `graph_search.chain_node` into `ChainNode`
 * everywhere a node is drawn (search results, query paths, the graph's own
 * cards) — real scope beyond what this task's files cover, so it wasn't
 * done. `IAM_USER`/`IAM_GROUP` also stay on the badge: AWS's Architecture
 * Icons set has no distinct resource icon for either, only for `Role`.
 *
 * Icons are the `_Dark` variant (white fill, `#FFFFFF`/brand colour) from
 * the AWS package, not `_Light` — `_Light` icons are near-black
 * (`#232F3D`), meant for a light background, and would be invisible against
 * this app's dark surfaces.
 */

import iamRole from '@/assets/aws-icons/iam-role.svg'
import resource from '@/assets/aws-icons/resource.svg'

/** Scout NodeType -> imported SVG url. A miss falls through to the letter badge. */
export const NODE_TYPE_ICON: Record<string, string> = {
  IAM_ROLE: iamRole,
  RESOURCE: resource,
}

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
