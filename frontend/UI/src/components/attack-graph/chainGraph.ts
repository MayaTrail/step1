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

import type { AttackChain, ChainNode, ScanEnvelope } from '@/types/attackGraph'

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
}

export interface Graph {
  nodes: ChainNode[]
  edges: GraphEdge[]
}

/**
 * Flatten ranked chains into the node and edge sets the layout needs.
 *
 * Nodes are deduplicated by id: chains overlap heavily — the same
 * over-permissioned role is usually the hop in several of them — and drawing
 * it once is what makes that visible.
 */
export function toGraph(envelope: ScanEnvelope | null): Graph {
  if (!envelope) return { nodes: [], edges: [] }

  const nodes = new Map<string, ChainNode>()
  const edges: GraphEdge[] = []

  for (const chain of envelope.chains) {
    for (const node of [chain.source, chain.target]) {
      if (node?.id) nodes.set(node.id, node)
    }
    chain.steps.forEach((step, index) => {
      if (!step.from || !step.to) return
      edges.push({
        id: `${chain.id}-${index}`,
        from: step.from,
        to: step.to,
        mechanism: step.mechanism,
        action: step.action,
        detail: step.detail,
        chainId: chain.id,
      })
      for (const id of [step.from, step.to]) {
        if (!nodes.has(id)) {
          nodes.set(id, { id, arn: '', type: 'other', label: id })
        }
      }
    })
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
