"""
Prompt construction for the AI chat feature.

build_context turns a registry MANIFEST entry into a grounding block. It draws
ONLY from the emulation's static catalogue data (threat intel, attack path,
MITRE mappings, reference titles). It never includes stack outputs, IAM details,
or any live AWS account data.

build_chat_system embeds that grounding in the chat system prompt (Markdown
allowed, since the UI renders it).
"""

from __future__ import annotations

# Multi-turn chat: the UI renders Markdown, so allow it.
CHAT_SYSTEM_PROMPT = (
    "You are a security analyst assistant inside the MayaTrail platform. "
    "You help security and detection engineers understand the AWS attack "
    "emulation described in the context below. Answer primarily from that "
    "context; if it does not cover something, say so rather than inventing "
    "details. Be concise and practical, and define security jargon simply. "
    "You may use Markdown (short headings, bullet lists, fenced code blocks) "
    "when it makes the answer clearer."
)


def build_context(entry: dict) -> str:
    """
    Build the grounding text block from a registry entry (snake_case keys).

    Includes only static catalogue data; never live account data.
    """
    lines: list[str] = []
    name = entry.get("display_name") or entry.get("name") or "this emulation"
    lines.append(f"Emulation: {name}")
    if entry.get("description"):
        lines.append(f"Summary: {entry['description']}")

    # Threat intelligence (only non-empty fields).
    intel = []
    for label, key in (
        ("Attribution", "attribution"),
        ("Origin", "origin_label"),
        ("Aliases", "aliases"),
        ("Active since", "active_since"),
        ("Targets", "targets"),
        ("Severity", "severity"),
    ):
        value = entry.get(key)
        if value:
            intel.append(f"{label}: {value}")
    if intel:
        lines.append("Threat intelligence:")
        lines.extend(f"- {item}" for item in intel)

    # Attack path (kill chain).
    attack_path = entry.get("attack_path") or []
    if attack_path:
        lines.append("Attack path (kill chain):")
        for phase in attack_path:
            techniques = ", ".join(
                f"{t.get('id', '')} {t.get('name', '')}".strip()
                for t in phase.get("techniques", [])
            )
            lines.append(f"- Phase {phase.get('phase', '?')} {phase.get('name', '')}: {techniques}")

    # MITRE ATT&CK techniques.
    mitre = entry.get("mitre_mappings") or []
    if mitre:
        lines.append("MITRE ATT&CK techniques:")
        for mapping in mitre:
            lines.append(
                f"- {mapping.get('id', '')} {mapping.get('name', '')} "
                f"({mapping.get('tactic', '')}): {mapping.get('description', '')}"
            )

    # Reference titles (the UI shows the links; the model gets titles for context).
    refs = entry.get("references") or []
    if refs:
        lines.append("Reference sources:")
        for ref in refs:
            lines.append(f"- {ref.get('title', '')} ({ref.get('source', '')})")

    return "\n".join(lines)


def build_chat_system(entry: dict) -> str:
    """
    Build the system prompt for a multi-turn chat.

    The grounding context is embedded in the system message so the conversation
    turns carry only the actual user/assistant exchange.
    """
    return f"{CHAT_SYSTEM_PROMPT}\n\nContext about this emulation:\n{build_context(entry)}"
