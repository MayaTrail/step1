/**
 * Envelope → graph.
 *
 * Kept out of the component on purpose: this is the only part of the Attack
 * Graph frontend with logic worth being wrong about, and a pure module can be
 * reasoned about (and, if a test runner is ever added, tested) without a DOM.
 *
 * The result state is NOT computed here. The backend stamps envelope.state,
 * and the rule that a self-scoped scan is never "clean" has exactly one
 * implementation (apps/attack_graph/envelope.py). A second one in TypeScript
 * is a second one to get wrong.
 */

import type { AttackChain, ChainNode, ChainStep, ScanEnvelope } from '@/types/attackGraph'

/**
 * One edge of the graph.
 *
 * No `technique` field: Scout does not attach a technique per hop (verified
 * in Task 1 — see apps/attack_graph/envelope.py's `_step`). `mechanism` and
 * `action` are Scout's own hop fields; a chain's MITRE technique ids are
 * chain-level (AttackChain.mitre_techniques), not per edge.
 */
export interface GraphEdge {
  id: string
  from: string
  to: string
  mechanism: string
  action: string
  detail: string
  chainId: string
  certainty: 'deterministic' | 'conditional'
}

export interface Graph {
  nodes: ChainNode[]
  edges: GraphEdge[]
}

/**
 * Flatten one path's steps into the node and edge sets the layout needs.
 *
 * `known` is a *lookup*, not a seed list: an id a step references is rendered
 * with the real node when one is known, and synthesized as an untyped box
 * otherwise. That fallback is correct for a stray id and would be wrong for
 * every node in a query result — which is why the path endpoint returns
 * `nodes` at all, and why the query caller passes the whole response's node
 * array here for each path without those nodes leaking into paths that do not
 * reference them.
 *
 * `seed` is what goes in regardless of the steps. Only the ranked-chain
 * caller uses it, for one reason: a zero-hop chain has no steps and still has
 * to draw — its two endpoints are the entire result.
 */
export function stepsToGraph(
  steps: ChainStep[],
  pathId: string,
  known: ChainNode[],
  seed: ChainNode[] = [],
): Graph {
  const lookup = new Map<string, ChainNode>()
  for (const node of known) {
    if (node?.id) lookup.set(node.id, node)
  }

  const nodes = new Map<string, ChainNode>()
  const edges: GraphEdge[] = []

  const include = (id: string) => {
    if (!id || nodes.has(id)) return
    nodes.set(id, lookup.get(id) ?? { id, arn: '', type: 'other', label: id })
  }

  for (const node of seed) {
    if (node?.id) include(node.id)
  }

  steps.forEach((step, index) => {
    if (!step.from || !step.to) return
    edges.push({
      id: `${pathId}-${index}`,
      from: step.from,
      to: step.to,
      mechanism: step.mechanism,
      action: step.action,
      detail: step.detail,
      chainId: pathId,
      certainty: step.certainty,
    })
    include(step.from)
    include(step.to)
  })

  return { nodes: [...nodes.values()], edges }
}

/**
 * Flatten ranked chains into the node and edge sets the layout needs.
 *
 * Nodes are deduplicated by id: chains overlap heavily — the same
 * over-permissioned role is usually the hop in several of them — and drawing
 * it once is what makes that visible.
 *
 * Every chain's endpoints are hoisted into one `known` lookup before any
 * chain is walked, and the merge below is guarded. Both matter: a role that
 * is chain 1's target and chain 2's middle hop must keep chain 1's real type.
 * Building each chain's sub-graph against only its own endpoints, then
 * merging with a bare set(), replaces that role with a grey ARN-labelled box
 * — a regression this function did not have before it was extracted.
 */
export function toGraph(envelope: ScanEnvelope | null): Graph {
  if (!envelope) return { nodes: [], edges: [] }

  const known = envelope.chains.flatMap((chain) => [chain.source, chain.target])
  const nodes = new Map<string, ChainNode>()
  const edges: GraphEdge[] = []

  for (const chain of envelope.chains) {
    const sub = stepsToGraph(chain.steps, chain.id, known,
                             [chain.source, chain.target])
    for (const node of sub.nodes) {
      if (!nodes.has(node.id)) nodes.set(node.id, node)
    }
    edges.push(...sub.edges)
  }

  return { nodes: [...nodes.values()], edges }
}

/** Chains that pass through a node, for the detail panel. */
export function chainsThrough(envelope: ScanEnvelope, nodeId: string): AttackChain[] {
  return envelope.chains.filter(
    (chain) =>
      chain.source.id === nodeId ||
      chain.target.id === nodeId ||
      chain.steps.some((step) => step.from === nodeId || step.to === nodeId),
  )
}
