#!/usr/bin/env python3
"""
MayaTrail APT Emulation Pipeline v2 — Main Orchestrator
========================================================

Internal content authoring tool. Transforms APT threat intelligence into
complete emulation packages with production-grade fidelity.

Three execution planes: control_plane / data_plane / host_plane
Credential chaining: stolen creds flow between attack phases
Bait resources: realistic discovery targets for enumeration

Usage:
    python pipeline.py --url https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
    python pipeline.py --technique T1078.004
    python pipeline.py --url <url> --plan-only
    python pipeline.py --url <url> --auto-approve
"""

import argparse
from typing import Optional
import hashlib
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from utils import (
    SONNET, OPUS,
    PipelineError, log, save, save_json, load_json,
    load_agent, call_claude, extract_json, extract_all_code_blocks,
    human_gate, review_loop,
    update_manifest, load_manifest, is_phase_complete,
    fetch_article, validate_environment, get_token_summary,
    ti_for_infra, ti_for_attack, ti_for_detections,
    infra_for_attack, attack_for_detections, _load_implementor,
)
from validators import (
    validate_generated_code, validate_json_schema, validate_sigma_rule,
    validate_technique_coverage, validate_module_loads, cross_validate_phase5,
    TI_METADATA_JSON_SCHEMA, TI_TECHNIQUES_JSON_SCHEMA,
)
from cost_estimator import estimate_cost

# ── Paths ────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
AGENTS_DIR = BASE_DIR / "agents"
OUTPUT_DIR = BASE_DIR / "emulation_output"

# ── TI-extract content-hash cache ────────────────────────────────────────
# Keyed by SHA-256 of the article URL so repeated runs against the same
# article skip both the HTTP fetch AND the two Phase-0B Claude calls
# (~180 k tokens / ~$0.54 saved each time).
_TI_CACHE_DIR = Path.home() / ".cache" / "aptpipeline" / "ti_cache"


def _ti_cache_path(url: str) -> Path:
    """Return the cache-file path for a given URL's TI extract."""
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
    return _TI_CACHE_DIR / f"ti_{url_hash}.json"


def _load_ti_cache(url: str) -> "dict | None":
    """Return cached TI extract for *url*, or ``None`` on miss / corruption."""
    cache_file = _ti_cache_path(url)
    if not cache_file.exists():
        return None
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        log("CACHE", f"TI extract cache hit → {cache_file.name}", "dim")
        return data
    except Exception:
        log("CACHE", f"Corrupt TI cache {cache_file.name} — ignoring", "warn")
        return None


def _save_ti_cache(url: str, ti_data: dict) -> None:
    """Persist *ti_data* to disk, keyed by the SHA-256 of *url*."""
    try:
        _TI_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_file = _ti_cache_path(url)
        cache_file.write_text(json.dumps(ti_data, indent=2), encoding="utf-8")
        log("CACHE", f"TI extract saved → {cache_file.name}", "dim")
    except Exception as exc:
        log("CACHE", f"Failed to write TI cache: {exc}", "warn")


# ══════════════════════════════════════════════════════════════════════════
# PHASE 0A — Security Services Advisory Check
# ══════════════════════════════════════════════════════════════════════════

def phase_0a_security_check(out_dir: Path, profile: Optional[str] = None, region: str = "us-east-1"):
    """Advisory-only check of security services. NEVER blocks execution.

    Currently supports AWS (CloudTrail, GuardDuty, SecurityHub).
    For non-AWS platforms (Azure, GCP, identity, SaaS), skips gracefully
    with an advisory note. Platform-specific checks can be added later.
    """
    log("PHASE-0A", "Checking security services (advisory only)…")

    services = {}

    # ── AWS checks (only run if boto3 + credentials available) ──
    try:
        import boto3
        session = boto3.Session(profile_name=profile, region_name=region)
        # Quick validation that we have real credentials
        session.client("sts").get_caller_identity()

        # CloudTrail
        try:
            ct = session.client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])
            services["CloudTrail"] = {"enabled": len(trails) > 0, "trails": len(trails)}
        except Exception:
            services["CloudTrail"] = {"enabled": False, "error": "check failed"}

        # GuardDuty
        try:
            gd = session.client("guardduty")
            detectors = gd.list_detectors().get("DetectorIds", [])
            services["GuardDuty"] = {"enabled": len(detectors) > 0}
        except Exception:
            services["GuardDuty"] = {"enabled": False, "error": "check failed"}

        # SecurityHub
        try:
            sh = session.client("securityhub")
            sh.describe_hub()
            services["SecurityHub"] = {"enabled": True}
        except Exception:
            services["SecurityHub"] = {"enabled": False}

    except ImportError:
        log("PHASE-0A", "boto3 not installed — skipping AWS checks", "warn")
        services = {"note": "AWS checks skipped — boto3 not installed"}
    except Exception:
        log("PHASE-0A", "No AWS credentials — skipping AWS checks (OK for non-AWS emulations)", "warn")
        services = {"note": "AWS checks skipped — no credentials (non-AWS emulations don't need this)"}

    # ── Future: Azure, GCP, Okta checks would go here ──
    # e.g., Azure Monitor/Defender, GCP Security Command Center, Okta org health

    # Display advisory
    print(f"\n  {'─' * 52}", flush=True)
    print(f"  SECURITY SERVICES ADVISORY", flush=True)
    print(f"  {'─' * 52}", flush=True)
    for svc, status in services.items():
        if isinstance(status, dict):
            icon = "+" if status.get("enabled") else "-"
            print(f"  [{icon}] {svc:20s} — {'enabled' if status.get('enabled') else 'NOT enabled'}", flush=True)
        elif svc == "note":
            print(f"  [*] {status}", flush=True)
    print(f"  {'─' * 52}", flush=True)
    print(f"  Pipeline continues regardless.\n", flush=True)

    save_json(out_dir / "security_posture.json", services)
    update_manifest(out_dir, "phase_0a", "complete", {"services": services})
    return services


# ══════════════════════════════════════════════════════════════════════════
# PHASE 0B — Threat Intelligence Extraction
# ══════════════════════════════════════════════════════════════════════════

def phase_0b_ti_extraction(article_text: str, source_url: str, out_dir: Path) -> dict:
    """Extract structured TI from article — the canonical source of truth.

    Split into two CLI calls (CRIT-1 / HIGH-1):
      1. Metadata — threat_actor, platform, kill_chain_order, iocs, etc.
         Small output (~3-5 KB). Schema-enforced.
      2. Techniques — the full techniques array referencing call 1's kill_chain.
         Larger output (~20-40 KB). Schema-enforced.

    Both use `--output-format json --json-schema`, so CLI-side schema
    validation plus authoritative token/cost accounting come for free. The
    two responses are merged into the legacy ti_extract.json shape before
    returning, so downstream phases see the same dict they always did.
    """
    log("PHASE-0B", "Extracting structured threat intelligence (split: metadata + techniques)…")
    agent = load_agent(AGENTS_DIR, "sonnet_ti_extractor")

    # ── Sub-phase checkpointing: resume from whichever call succeeded ──
    # If Call 1 (metadata) already completed in a prior attempt, load the
    # cached file instead of re-calling — saves ~75k tokens per retry.
    _prior = (load_manifest(out_dir) or {}).get("phases", {})
    _meta_done = _prior.get("phase_0b_meta", {}).get("status") == "complete"
    _tech_done = _prior.get("phase_0b_tech", {}).get("status") == "complete"

    # ── Call 1: metadata ────────────────────────────────────────────────
    if _meta_done:
        log("PHASE-0B-META", "Skipping — loaded from prior attempt (phase_0b_meta complete)", "dim")
        meta_data = load_json(out_dir / "phase0b_metadata.json")
        meta_tokens = _prior["phase_0b_meta"].get("tokens", {})
    else:
        meta_prompt = (
            f"## Source URL\n{source_url}\n\n## Article Content\n{article_text}\n\n"
            f"## Mode: METADATA ONLY (call 1 of 2)\n"
            f"Output ONLY the top-level metadata fields. Do NOT include the "
            f"`techniques` array — that comes in call 2.\n"
            f"Required fields: status, threat_actor, platform, targeted_services, "
            f"kill_chain_order (list of mitre_ids in attack sequence), "
            f"credential_chain, iocs, operational_notes, source_url, extraction_confidence.\n"
            f"`kill_chain_order` MUST list every technique you will emit in call 2."
        )
        meta_response, meta_tokens = call_claude(
            SONNET, agent, meta_prompt, "PHASE-0B-META",
            timeout=600, json_schema=TI_METADATA_JSON_SCHEMA,
        )
        save(out_dir / "phase0b_metadata_raw.md", meta_response)
        meta_data = extract_json(meta_response)
        if not meta_data:
            raise PipelineError(
                "Phase 0B (metadata call): Failed to extract JSON. "
                "Raw output saved to phase0b_metadata_raw.md."
            )
        save_json(out_dir / "phase0b_metadata.json", meta_data)
        # Checkpoint: mark sub-phase complete so resume skips this call
        update_manifest(out_dir, "phase_0b_meta", "complete", {"tokens": meta_tokens})

    kill_chain = meta_data.get("kill_chain_order", [])
    actor_name = meta_data.get("threat_actor", {}).get("name", "Unknown")
    kc_level = "warn" if len(kill_chain) == 0 else "ok"
    log("PHASE-0B-META",
        f"{'⚠' if not kill_chain else '✅'} {actor_name}: "
        f"{len(kill_chain)} techniques in kill_chain_order", kc_level)

    # ── Call 2: techniques ──────────────────────────────────────────────
    # Feed call 1's kill_chain back so the model knows exactly which
    # techniques to emit and in what order. This pins the technique set
    # and prevents drift between the two calls.
    # Only send the first ~1500 chars of the article — the kill_chain from
    # call 1 already anchors the technique set; the full text is redundant.
    if _tech_done:
        log("PHASE-0B-TECH", "Skipping — loaded from prior attempt (phase_0b_tech complete)", "dim")
        tech_data = load_json(out_dir / "phase0b_techniques.json")
        tech_tokens = _prior["phase_0b_tech"].get("tokens", {})
    else:
        article_excerpt = article_text[:1500] + ("...[truncated]" if len(article_text) > 1500 else "")
        tech_prompt = (
            f"## Source URL\n{source_url}\n\n"
            f"## Article Excerpt (first 1500 chars — metadata already extracted in call 1)\n{article_excerpt}\n\n"
            f"## Mode: TECHNIQUES ONLY (call 2 of 2)\n"
            f"## Metadata from call 1\n```json\n{json.dumps(meta_data)}\n```\n\n"
            f"Output ONLY the `techniques` array as an object: "
            f'{{"techniques": [ ... ]}}.\n'
            f"Emit one technique object for EACH mitre_id in `kill_chain_order` "
            f"above, in the same order. Do NOT include any top-level metadata "
            f"fields — those were already extracted in call 1.\n"
            f"Keep each technique's strings terse (under 20 words where possible) "
            f"so the full array fits in one response."
        )
        tech_response, tech_tokens = call_claude(
            SONNET, agent, tech_prompt, "PHASE-0B-TECH",
            timeout=900, json_schema=TI_TECHNIQUES_JSON_SCHEMA,
        )
        save(out_dir / "phase0b_techniques_raw.md", tech_response)
        tech_data = extract_json(tech_response)
        if not tech_data or "techniques" not in tech_data:
            raise PipelineError(
                "Phase 0B (techniques call): Failed to extract JSON or missing "
                "`techniques` key. Raw output saved to phase0b_techniques_raw.md."
            )
        save_json(out_dir / "phase0b_techniques.json", tech_data)
        # Checkpoint: mark sub-phase complete so resume skips this call
        update_manifest(out_dir, "phase_0b_tech", "complete", {"tokens": tech_tokens})

    # ── Merge ────────────────────────────────────────────────────────────
    # Start from metadata, overlay the techniques array. Force a canonical
    # status string regardless of what either call emitted.
    ti_data = dict(meta_data)
    ti_data["techniques"] = tech_data["techniques"]
    ti_data["status"] = "PHASE_0B_COMPLETE"

    # Legacy single-file raw output for debugging (kept for
    # backward-compatibility with existing tooling that greps phase0b_raw.md).
    # When a sub-phase was loaded from cache its raw response isn't re-available,
    # so fall back to a note rather than leaving a stale file.
    meta_raw = (out_dir / "phase0b_metadata_raw.md").read_text(encoding="utf-8") \
        if (out_dir / "phase0b_metadata_raw.md").exists() else "[loaded from phase_0b_meta cache]"
    tech_raw = (out_dir / "phase0b_techniques_raw.md").read_text(encoding="utf-8") \
        if (out_dir / "phase0b_techniques_raw.md").exists() else "[loaded from phase_0b_tech cache]"
    save(out_dir / "phase0b_raw.md",
         f"# Metadata response\n{meta_raw}\n\n# Techniques response\n{tech_raw}")

    tokens = {
        "input_tokens": meta_tokens.get("input_tokens", 0) + tech_tokens.get("input_tokens", 0),
        "output_tokens": meta_tokens.get("output_tokens", 0) + tech_tokens.get("output_tokens", 0),
        "model": meta_tokens.get("model"),
        "elapsed_s": (meta_tokens.get("elapsed_s") or 0) + (tech_tokens.get("elapsed_s") or 0),
        "cost_usd": (meta_tokens.get("cost_usd") or 0) + (tech_tokens.get("cost_usd") or 0),
    }

    # ── Hard-fail on schema violations. Downstream phases will silently produce
    # nonsense if the TI extract is missing 'techniques', 'kill_chain_order', etc.
    # Letting the pipeline continue with a broken extract is the worst failure
    # mode — the LUCR-3 run ended up generating infra for a single fragment
    # object pulled from the middle of the response. ──
    validation = validate_json_schema(ti_data, "ti_extract")
    tech_count = len(ti_data.get("techniques", []))
    actor = ti_data.get("threat_actor", {}).get("name", "Unknown")

    if validation["critical_errors"]:
        # Save the bad extract for debugging before we raise
        save_json(out_dir / "ti_extract.json", ti_data)
        raise PipelineError(
            f"Phase 0B: TI extract failed critical schema validation. "
            f"Critical errors: {validation['critical_errors']}. "
            f"Techniques extracted: {tech_count}. Actor: {actor!r}. "
            f"Raw output saved to phase0b_raw.md; malformed extract saved to "
            f"ti_extract.json. Check for response truncation or retry."
        )
    if validation["advisory_errors"]:
        log("PHASE-0B",
            f"Advisory schema issues (not blocking): {validation['advisory_errors']}",
            "warn")

    if tech_count == 0:
        save_json(out_dir / "ti_extract.json", ti_data)
        raise PipelineError(
            "Phase 0B: extracted zero techniques. Cannot plan infrastructure "
            "or attack chain. Check article.txt quality and phase0b_raw.md."
        )

    save_json(out_dir / "ti_extract.json", ti_data)

    planes = {}
    for t in ti_data.get("techniques", []):
        plane = t.get("execution_plane", "unknown")
        planes[plane] = planes.get(plane, 0) + 1

    tc_level = "warn" if tech_count == 0 else "ok"
    log("PHASE-0B", f"{'⚠' if tech_count == 0 else '✅'} {actor}: {tech_count} techniques "
        f"(control:{planes.get('control_plane',0)} "
        f"data:{planes.get('data_plane',0)} "
        f"host:{planes.get('host_plane',0)})", tc_level)

    cred_chain = ti_data.get("credential_chain", [])
    if cred_chain:
        log("PHASE-0B", f"   Credential chain: {len(cred_chain)} pivot(s)", "ok")

    update_manifest(out_dir, "phase_0b", "complete", {
        "techniques": tech_count, "threat_actor": actor,
        "execution_planes": planes, "tokens": tokens,
    })
    return ti_data


def phase_0b_single_technique(technique_id: str, out_dir: Path) -> dict:
    """Generate TI extract for a single MITRE technique."""
    log("PHASE-0B", f"Generating TI for single technique: {technique_id}…")

    agent = load_agent(AGENTS_DIR, "sonnet_ti_extractor")
    prompt = (
        f"## Mode: Single Technique\n"
        f"Generate a complete TI extract for MITRE ATT&CK technique {technique_id}.\n"
        f"Create a realistic entry as if extracted from a real threat report about "
        f"an APT using this technique against cloud or enterprise infrastructure.\n"
        f"Include credential_chain if this technique involves credential theft."
    )

    response, tokens = call_claude(SONNET, agent, prompt, "PHASE-0B", timeout=900)
    save(out_dir / "phase0b_raw.md", response)
    ti_data = extract_json(response)

    if not ti_data:
        raise PipelineError(
            "Phase 0B: Failed to extract JSON for single technique. "
            "Raw output saved to phase0b_raw.md."
        )

    validation = validate_json_schema(ti_data, "ti_extract")
    tech_count = len(ti_data.get("techniques", []))
    actor = ti_data.get("threat_actor", {}).get("name", "Unknown")

    if validation["critical_errors"]:
        save_json(out_dir / "ti_extract.json", ti_data)
        raise PipelineError(
            f"Phase 0B: TI extract failed critical schema validation. "
            f"Critical errors: {validation['critical_errors']}. "
            f"Techniques extracted: {tech_count}. Actor: {actor!r}. "
            f"Raw output saved to phase0b_raw.md; malformed extract saved to ti_extract.json."
        )
    if validation["advisory_errors"]:
        log("PHASE-0B",
            f"Advisory schema issues (not blocking): {validation['advisory_errors']}",
            "warn")

    if tech_count == 0:
        save_json(out_dir / "ti_extract.json", ti_data)
        raise PipelineError(
            "Phase 0B: extracted zero techniques for single-technique mode. "
            "Check phase0b_raw.md."
        )

    save_json(out_dir / "ti_extract.json", ti_data)

    planes = {}
    for t in ti_data.get("techniques", []):
        plane = t.get("execution_plane", "unknown")
        planes[plane] = planes.get(plane, 0) + 1

    log("PHASE-0B", f"✅ {actor}: {tech_count} technique(s) "
        f"(control:{planes.get('control_plane',0)} "
        f"data:{planes.get('data_plane',0)} "
        f"host:{planes.get('host_plane',0)})", "ok")

    cred_chain = ti_data.get("credential_chain", [])
    if cred_chain:
        log("PHASE-0B", f"   Credential chain: {len(cred_chain)} pivot(s)", "ok")

    update_manifest(out_dir, "phase_0b", "complete", {
        "technique": technique_id,
        "techniques": tech_count,
        "execution_planes": planes,
        "tokens": tokens,
    })
    return ti_data


# ══════════════════════════════════════════════════════════════════════════
# PHASE 1 — Infrastructure Planning
# ══════════════════════════════════════════════════════════════════════════

def phase_1_infra_plan(ti_extract: dict, out_dir: Path) -> dict:
    """Generate infra plan with attack_surface/target/bait categories."""
    log("PHASE-1", "Planning infrastructure…")

    agent = load_agent(AGENTS_DIR, "sonnet_infra_planner")
    prompt = (
        f"## Threat Intelligence Extract\n"
        f"```json\n{json.dumps(ti_for_infra(ti_extract), separators=(',',':'))}\n```\n\n"
        f"Design the minimum infrastructure for this emulation.\n"
        f"Use the platform from the TI extract (AWS, Azure, GCP, identity, SaaS, etc.).\n"
        f"Include attack_surface resources, target resources, bait resources, "
        f"and any host-level setup actions appropriate to the platform."
    )

    response, tokens = call_claude(SONNET, agent, prompt, "PHASE-1", timeout=600)
    infra_data = extract_json(response)

    if not infra_data:
        fallback_path = out_dir / "infra_plan.json"
        if fallback_path.exists():
            log("PHASE-1", "extract_json failed but file written by Claude Code tool — loading from disk", "warn")
            infra_data = load_json(fallback_path)
        else:
            save(out_dir / "phase1_raw.md", response)
            raise PipelineError("Phase 1: Failed to extract JSON.")

    validation = validate_json_schema(infra_data, "infra_plan")
    resources = infra_data.get("resources", [])
    if validation["critical_errors"]:
        save_json(out_dir / "infra_plan.json", infra_data)
        raise PipelineError(
            f"Phase 1: infra plan failed critical schema validation. "
            f"Critical errors: {validation['critical_errors']}. "
            f"Resources found: {len(resources)}. "
            f"Malformed plan saved to infra_plan.json."
        )
    if validation["advisory_errors"]:
        log("PHASE-1",
            f"Advisory schema issues (not blocking): {validation['advisory_errors']}",
            "warn")
    if not resources:
        save_json(out_dir / "infra_plan.json", infra_data)
        raise PipelineError(
            "Phase 1: infra plan has zero resources. Cannot emulate anything."
        )

    save_json(out_dir / "infra_plan.json", infra_data)
    categories = {}
    for r in resources:
        cat = r.get("resource_category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1

    log("PHASE-1", f"✅ {len(resources)} resources "
        f"(surface:{categories.get('attack_surface',0)} "
        f"target:{categories.get('target',0)} "
        f"bait:{categories.get('bait',0)} "
        f"support:{categories.get('support',0)})", "ok")

    ud_actions = infra_data.get("userdata_actions", [])
    if ud_actions:
        log("PHASE-1", f"   UserData: {len(ud_actions)} host-level actions", "ok")

    update_manifest(out_dir, "phase_1", "complete", {
        "resources": len(resources), "categories": categories, "tokens": tokens,
    })
    return infra_data


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2 — Infrastructure Review (Opus Loop)
# ══════════════════════════════════════════════════════════════════════════

def phase_2_infra_review(ti_extract: dict, infra_plan: dict, out_dir: Path, max_iter: int = 3) -> dict:
    """Opus reviews infra plan for attack surface correctness and isolation."""
    log("PHASE-2", "Opus reviewing infrastructure…")

    reviewer = load_agent(AGENTS_DIR, "opus_infra_reviewer")
    planner = load_agent(AGENTS_DIR, "sonnet_infra_planner")

    context = f"## Threat Intelligence\n```json\n{json.dumps(ti_for_infra(ti_extract), separators=(',',':'))}\n```"

    def redraft(ctx, feedback):
        prompt = (
            f"{ctx}\n\n## Reviewer Feedback\n{feedback}\n\n"
            f"## Previous Plan\n```json\n{json.dumps(infra_plan, separators=(',',':'))}\n```\n\n"
            f"Generate a REVISED infrastructure plan addressing ALL issues."
        )
        return call_claude(SONNET, planner, prompt, "PHASE-2-REDRAFT")

    approved_draft, envelope = review_loop(
        reviewer, redraft, json.dumps(infra_plan, separators=(',',':')),
        context, "PHASE-2", out_dir, max_iter,
    )

    approved = extract_json(approved_draft)
    fell_back = False
    if not approved:
        log("PHASE-2", "Could not extract JSON from approved draft — using original infra plan", "warn")
        save(out_dir / "phase2_fallback_raw.md", approved_draft)
        approved = infra_plan
        fell_back = True
        envelope["_fallback"] = "extract_json failed on approved draft, using original plan"
    save_json(out_dir / "infra_plan_approved.json", approved)
    save_json(out_dir / "phase2_review.json", envelope)
    update_manifest(out_dir, "phase_2", "complete", {
        "verdict": envelope.get("verdict", "APPROVED"), "fallback": fell_back,
    })
    return approved


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3 — Attack Planning
# ══════════════════════════════════════════════════════════════════════════

def phase_3_attack_plan(ti_extract: dict, infra_plan: dict, out_dir: Path) -> dict:
    """Generate attack plan with credential chaining and execution contexts."""
    log("PHASE-3", "Planning attack chain…")

    agent = load_agent(AGENTS_DIR, "sonnet_attack_planner")
    prompt = (
        f"## Threat Intelligence\n```json\n{json.dumps(ti_for_attack(ti_extract), separators=(',',':'))}\n```\n\n"
        f"## Approved Infrastructure\n```json\n{json.dumps(infra_for_attack(infra_plan), separators=(',',':'))}\n```\n\n"
        f"Create a sequenced attack plan with credential chaining.\n"
        f"The plan will be implemented as a SINGLE attack.py with credential flow."
    )

    # Scale timeout by technique count: complex actors (10+ techniques) need
    # more than 600 s to plan a full credential-chaining attack chain.
    # Formula: 600 s base + 60 s per technique above 8, capped at 1800 s (30 min).
    _n_techs = len(ti_extract.get("techniques", []))
    _phase3_timeout = min(1800, 600 + max(0, _n_techs - 8) * 60)
    if _n_techs > 8:
        log("PHASE-3", f"Timeout scaled to {_phase3_timeout}s for {_n_techs} techniques", "dim")
    response, tokens = call_claude(SONNET, agent, prompt, "PHASE-3", timeout=_phase3_timeout)
    attack_data = extract_json(response)

    if not attack_data:
        fallback_path = out_dir / "attack_plan.json"
        if fallback_path.exists():
            log("PHASE-3", "extract_json failed but file written by Claude Code tool — loading from disk", "warn")
            attack_data = load_json(fallback_path)
        else:
            save(out_dir / "phase3_raw.md", response)
            raise PipelineError("Phase 3: Failed to extract JSON.")

    validation = validate_json_schema(attack_data, "attack_plan")
    steps = attack_data.get("attack_chain", [])
    cred_chain = attack_data.get("credential_chain", [])
    if validation["critical_errors"]:
        save_json(out_dir / "attack_plan.json", attack_data)
        raise PipelineError(
            f"Phase 3: attack plan failed critical schema validation. "
            f"Critical errors: {validation['critical_errors']}. "
            f"Steps: {len(steps)}. Malformed plan saved to attack_plan.json."
        )
    if validation["advisory_errors"]:
        log("PHASE-3",
            f"Advisory schema issues (not blocking): {validation['advisory_errors']}",
            "warn")
    if not steps:
        save_json(out_dir / "attack_plan.json", attack_data)
        raise PipelineError(
            "Phase 3: attack plan has zero steps. Cannot generate attack.py."
        )

    save_json(out_dir / "attack_plan.json", attack_data)

    log("PHASE-3", f"✅ {len(steps)} attack steps, {len(cred_chain)} credential pivot(s)", "ok")

    update_manifest(out_dir, "phase_3", "complete", {
        "steps": len(steps), "credential_pivots": len(cred_chain), "tokens": tokens,
    })
    return attack_data


# ══════════════════════════════════════════════════════════════════════════
# PHASE 4 — Attack Plan Review (Opus Loop)
# ══════════════════════════════════════════════════════════════════════════

def phase_4_attack_review(
    ti_extract: dict, infra_plan: dict, attack_plan: dict,
    out_dir: Path, max_iter: int = 3,
) -> dict:
    """Opus reviews attack plan for credential chain integrity and fidelity."""
    log("PHASE-4", "Opus reviewing attack plan…")

    reviewer = load_agent(AGENTS_DIR, "opus_attack_reviewer")
    planner = load_agent(AGENTS_DIR, "sonnet_attack_planner")

    context = (
        f"## Threat Intelligence\n```json\n{json.dumps(ti_for_attack(ti_extract), separators=(',',':'))}\n```\n\n"
        f"## Approved Infrastructure\n```json\n{json.dumps(infra_for_attack(infra_plan), separators=(',',':'))}\n```"
    )

    def redraft(ctx, feedback):
        prompt = (
            f"{ctx}\n\n## Reviewer Feedback\n{feedback}\n\n"
            f"## Previous Plan\n```json\n{json.dumps(attack_plan, separators=(',',':'))}\n```\n\n"
            f"Generate a REVISED attack plan addressing ALL gaps."
        )
        return call_claude(SONNET, planner, prompt, "PHASE-4-REDRAFT")

    approved_draft, envelope = review_loop(
        reviewer, redraft, json.dumps(attack_plan, separators=(',',':')),
        context, "PHASE-4", out_dir, max_iter,
    )

    approved = extract_json(approved_draft)
    fell_back = False
    if not approved:
        log("PHASE-4", "Could not extract JSON from approved draft — using original attack plan", "warn")
        save(out_dir / "phase4_fallback_raw.md", approved_draft)
        approved = attack_plan
        fell_back = True
        envelope["_fallback"] = "extract_json failed on approved draft, using original plan"
    save_json(out_dir / "attack_plan_approved.json", approved)
    save_json(out_dir / "phase4_review.json", envelope)

    fidelity = envelope.get("fidelity_score", "N/A")
    log("PHASE-4", f"Attack plan approved (fidelity: {fidelity})", "ok")

    update_manifest(out_dir, "phase_4", "complete", {
        "verdict": envelope.get("verdict"), "fidelity_score": fidelity,
        "fallback": fell_back,
    })
    return approved


# ══════════════════════════════════════════════════════════════════════════
# PHASE 5 — Code Generation (Pulumi + attack.py)
# ══════════════════════════════════════════════════════════════════════════

def _rate_limit_aware_status(errors: list, critical_files: "list | None" = None) -> str:
    """Return the manifest status string for a phase that may have been
    rate-limited or partially failed.

    Two cases must NOT be recorded as 'complete':
      1. Rate-limit exit — --resume must re-run so we don't skip a phase
         whose Claude call never returned.
      2. Non-rate-limit failure (timeout, parse error) that left a critical
         output ungenerated — the AMBERSQUID failure mode where Phase 5B
         timed out 3× at 600 s and was silently marked 'complete' with 0
         attack files, causing --resume to skip Phase 5 and leave attack.py
         permanently missing.

    critical_files: list of filenames the phase MUST produce (e.g.
        ["attack.py"] for Phase 5). When provided, errors + empty list →
        "incomplete". Pass None (default) to skip this check (Phase 6
        can succeed partially and is handled differently).
    """
    if any("RATE_LIMIT_EXIT" in e for e in errors):
        return "incomplete_rate_limit"
    if critical_files is not None and errors and not critical_files:
        return "incomplete"
    return "complete"

def phase_5_code_generation(
    ti_extract: dict, infra_plan: dict, attack_plan: dict, out_dir: Path,
    max_concurrency: int = 2,
    test_mode: bool = False,
) -> dict:
    """Generate Pulumi IaC + attack.py IN PARALLEL (5A || 5B).

    max_concurrency caps the number of simultaneous Claude calls within this
    phase (MED-3). Default 2 = both sub-phases run in parallel. 1 = serial.

    test_mode overrides operational delays in the generated attack.py with
    short values (2-5 s) so iterative test runs don't wait for real APT
    inter-phase delays that can be 5-60 minutes (LOW-2).
    """
    platform = ti_extract.get("platform", "aws")
    implementor_infra = _load_implementor(AGENTS_DIR, "infra", platform)
    implementor_attack = _load_implementor(AGENTS_DIR, "attack", platform)
    results = {"infra_files": [], "attack_files": [], "validation": {}}

    # Use compact JSON to reduce token count (~30% smaller than indent=2)
    infra_compact = json.dumps(infra_plan, separators=(",", ":"))
    attack_compact = json.dumps(attack_plan, separators=(",", ":"))

    # Only expose attack-relevant resources to the attack script generator
    attack_resources = [
        r for r in infra_plan.get("resources", [])
        if r.get("resource_category") in ("attack_surface", "target", "bait")
    ]

    # ── Build prompts (before dispatching threads) ──
    infra_prompt = (
        f"TASK: IMPLEMENT INFRASTRUCTURE\n\n"
        f"## Output Directory\n"
        f"Write ALL infrastructure files to this exact directory: {out_dir / 'infra'}\n"
        f"Do NOT write to a relative path — use the full absolute path above.\n\n"
        f"## Approved Infrastructure Plan\n```json\n{infra_compact}\n```\n\n"
        f"## Attack Plan (for auto-trigger hook)\n"
        f"```json\n{json.dumps(attack_plan.get('script_manifest', {}), separators=(',',':'))}\n```\n\n"
        f"Generate: Pulumi.yaml, requirements.txt, __main__.py (with UserData + auto-trigger hook).\n"
        f"Each file in a separate code block with `# FILE: filename` as first line.\n\n"
        f"HARD CONSTRAINTS (from live execution experience):\n"
        f"1. AWS resource descriptions/names: ASCII only — no em-dashes (—) or arrows (→).\n"
        f"2. pulumi-aws v7 API: UserLoginProfile has no `password` arg; "
        f"PublishingDestination uses flat `destination_arn`+`kms_key_arn` (no nested destination_properties); "
        f"use standalone S3 versioning/encryption/lifecycle resources, not inline Bucket args.\n"
        f"3. IAM trust policy principals must be REAL AWS account IDs — never placeholders like 111111111111.\n"
        f"4. SecretsManager: always set recovery_window_in_days=0; never create a deny policy that blocks the deployer IAM principal.\n"
        f"5. GuardDuty S3 publishing: bucket policy needs s3:GetBucketLocation (not GetBucketAcl) "
        f"and s3:PutObject to /AWSLogs/{{account_id}}/GuardDuty/*, with aws:SourceAccount condition (not s3:x-amz-acl).\n"
        f"6. pulumi-aws v7 ECS/CloudTrail API: CloudTrail Trail uses `enable_logging=True` (NOT `is_logging`); "
        f"ECS Cluster has NO `capacity_providers` arg — FARGATE is implicit when RunTask specifies launchType=FARGATE.\n"
        f"7. AWS managed policy AmplifyFullAccess NO LONGER EXISTS — omit it from any AttachRolePolicy call. "
        f"Use AWSAmplifyReadOnlyAccess or an inline policy for Amplify permissions.\n"
        f"8. Victim IAM policy MUST include `sts:AssumeRole` and `iam:ListAttachedRolePolicies` — "
        f"without these the emulated victim cannot assume attacker-created roles or clean up policies.\n"
        f"9. MANDATORY STRUCTURE — Resource Name Constants block:\n"
        f"   At the very top of __main__.py (after imports, before any resource creation) define ALL\n"
        f"   AWS resource names and identifiers as Python module-level constants, e.g.:\n"
        f"     CLUSTER_NAME  = 'mythreat-cluster'\n"
        f"     TRAIL_NAME    = 'mythreat-trail'\n"
        f"     TASK_FAMILY   = 'mythreat-miner'\n"
        f"     LOG_GROUP     = '/ecs/mythreat'\n"
        f"   Use these constants everywhere a resource name appears — never repeat the string literal.\n"
        f"   Export every constant as a Pulumi output with a matching snake_case key, e.g.:\n"
        f"     pulumi.export('cluster_name', CLUSTER_NAME)\n"
        f"     pulumi.export('trail_name',   TRAIL_NAME)\n"
        f"     pulumi.export('task_family',  TASK_FAMILY)\n"
        f"   attack.py reads these exact exported keys — they MUST match.\n"
        f"10. Required export keys (attack.py reads these by name — spelling must match exactly):\n"
        f"    cluster_name, trail_name, task_family, subnet_id, task_sg_id,\n"
        f"    victim_access_key_id, victim_secret_access_key,\n"
        f"    cloudtrail_bucket_name, codecommit_repo_name (add others as the plan requires).\n"
        f"11. _launch_attack() in __main__.py: set attack_script path to\n"
        f"    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'emulation_scripts', 'attack.py')\n"
        f"    NOT os.path.join(os.path.dirname(__file__), 'attack.py') — attack.py lives in emulation_scripts/, not infra/.\n"
        f"12. Env vars set in _launch_attack env dict must EXACTLY match the names attack.py reads:\n"
        f"    env['ECS_SUBNET_ID'], env['ECS_SECURITY_GROUP_ID'], env['ECS_CLUSTER_NAME'], env['TASK_DEFINITION_ARN']."
    )
    attack_prompt = (
        f"TASK: IMPLEMENT ATTACK SCRIPT\n\n"
        f"## Output File\n"
        f"Write the attack script to this exact path: {out_dir / 'emulation_scripts' / 'attack.py'}\n"
        f"Do NOT write to a relative path — use the full absolute path above.\n\n"
        f"## Approved Attack Plan\n```json\n{attack_compact}\n```\n\n"
        f"## Infrastructure Resources (attack-relevant only)\n```json\n{json.dumps(attack_resources, separators=(',',':'))}\n```\n\n"
        f"Generate a SINGLE attack.py with:\n"
        f"- Credential chaining from the credential_chain in the attack plan\n"
        f"- Implement EVERY execution_context using the appropriate method:\n"
        f"  container_attack: HTTP POST to vulnerable app endpoint\n"
        f"  api_attack: SDK calls (boto3/azure/gcloud/etc.) using stolen session\n"
        f"  sso_attack: SAML/OAuth/OIDC federation flows\n"
        f"  saas_attack: SaaS API calls using stolen tokens\n"
        f"  idp_attack: Identity provider API manipulation\n"
        f"  lateral_movement: Pivoting using harvested credentials\n"
        f"- IMPORTANT: host_attack steps are pre-deployed in UserData — do NOT include them in attack.py\n"
        f"- IMPORTANT: phishing_attack steps are documented-only (out-of-band social engineering: SIM swap, MFA fatigue, credential harvesting). Emit a clearly-marked comment block in attack.py describing the step and expected outcome — do NOT write placeholder/simulated Python for it.\n"
        f"- op_delay() between API calls, phase_delay() between phases\n"
        + (
            "- TEST MODE ACTIVE: use 2-5 second delays for BOTH op_delay and phase_delay "
            "regardless of operational_notes values — this run is for testing, not real emulation\n"
            if test_mode else ""
        )
        + f"- If attack plan includes container/app RCE, add wait_for_app() polling\n"
        f"- Proper error handling for expected errors (AccessDenied, 403, 401, etc.)\n"
        f"- HARD: First lines after imports must be:\n"
        f"    import sys\n"
        f"    if hasattr(sys.stdout, 'reconfigure'): sys.stdout.reconfigure(encoding='utf-8', errors='replace')\n"
        f"    if hasattr(sys.stderr, 'reconfigure'): sys.stderr.reconfigure(encoding='utf-8', errors='replace')\n"
        f"- HARD: ASCII only in all print/log strings — use -> not →, use - not —\n"
        f"- HARD: IAM AccessKeysPerUser quota = 2. Before EVERY create_access_key(UserName=victim):\n"
        f"  enumerate existing keys; if len >= 2, delete the newest (stale from prior run) then proceed.\n"
        f"  Pattern:\n"
        f"    existing = iam.list_access_keys(UserName=victim)['AccessKeyMetadata']\n"
        f"    if len(existing) >= 2:\n"
        f"        newest = max(existing, key=lambda k: k['CreateDate'])\n"
        f"        iam.delete_access_key(UserName=victim, AccessKeyId=newest['AccessKeyId'])\n"
        f"- HARD: Hijacked victim sessions must stay valid through ALL steps that use them.\n"
        f"  Do NOT call creds.invalidate() on a session in indicator-removal steps if later steps\n"
        f"  still need that session. Place the hijacked key deletion + invalidation in a dedicated\n"
        f"  post-attack cleanup block at the END of the last phase that uses the session.\n"
        f"- HARD: MANDATORY STRUCTURE — resolve all resource names from Pulumi outputs at the start of main():\n"
        f"  infra = get_pulumi_outputs(stack_dir)  # reads from pulumi stack output\n"
        f"  cluster_name  = infra.get('cluster_name', '')\n"
        f"  trail_name    = infra.get('trail_name', '')\n"
        f"  task_family   = infra.get('task_family', '')\n"
        f"  subnet_id     = infra.get('subnet_id', '')\n"
        f"  task_sg_id    = infra.get('task_sg_id', '')\n"
        f"  victim_key_id = infra.get('victim_access_key_id', '') or os.environ.get('AWS_VICTIM_ACCESS_KEY_ID', '')\n"
        f"  victim_secret = infra.get('victim_secret_access_key', '') or os.environ.get('AWS_VICTIM_SECRET_ACCESS_KEY', '')\n"
        f"  # ... and any other plan-specific names\n"
        f"  Pass these variables as parameters to each phase function — NEVER hardcode any name.\n"
        f"  Phase functions must accept resource names as parameters, not access module-level constants.\n"
        f"- HARD: get_pulumi_outputs() MUST use ['pulumi','stack','output','--json','--show-secrets'] AND\n"
        f"  pass env={{**os.environ,'PULUMI_CONFIG_PASSPHRASE':os.environ.get('PULUMI_CONFIG_PASSPHRASE','')}}.\n"
        f"  Without --show-secrets, victim IAM keys come back as '[secret]' and the script aborts.\n"
        f"- HARD: NEVER hardcode any AWS resource name string in a boto3 call. Every cluster=, Name=,\n"
        f"  repositoryName=, trailName=, etc. must come from a variable resolved from infra dict.\n"
        f"  Pulumi logical names (first positional arg like 'ambersquid-ecs-cluster') are NOT AWS names —\n"
        f"  the AWS name is the `name=` kwarg value. The exported key (e.g. 'cluster_name') is the bridge.\n"
        f"- HARD: AWS managed policy AmplifyFullAccess NO LONGER EXISTS. Never attach it. "
        f"Use AWSAmplifyReadOnlyAccess or an inline policy if Amplify access is needed.\n"
        f"Output as a single ```python block with `# FILE: attack.py`"
    )

    # ── Dispatch 5A and 5B in parallel ──
    log("PHASE-5", "Generating infrastructure + attack script in parallel…")

    def run_5a():
        log("PHASE-5A", "Generating Pulumi project + UserData…")
        resp, _ = call_claude(SONNET, implementor_infra, infra_prompt, "PHASE-5A", timeout=1500, max_retries=0)
        save(out_dir / "phase5a_raw.md", resp)
        return resp

    def run_5b():
        log("PHASE-5B", "Generating attack.py with credential chaining…")
        resp, _ = call_claude(SONNET, implementor_attack, attack_prompt, "PHASE-5B", timeout=1500)
        save(out_dir / "phase5b_raw.md", resp)
        return resp

    with ThreadPoolExecutor(max_workers=min(2, max_concurrency)) as pool:
        fut_5a = pool.submit(run_5a)
        fut_5b = pool.submit(run_5b)

        # Collect results — don't let one failure lose the other's output
        resp_5a = resp_5b = None
        errors = []
        for label_name, fut in [("PHASE-5A", fut_5a), ("PHASE-5B", fut_5b)]:
            try:
                result = fut.result()
                if label_name == "PHASE-5A":
                    resp_5a = result
                else:
                    resp_5b = result
            except Exception as e:
                log(label_name, f"Failed: {e}", "err")
                errors.append(f"{label_name}: {e}")
        if errors and not resp_5a and not resp_5b:
            raise PipelineError(f"Phase 5 failed completely: {'; '.join(errors)}")
        if errors:
            log("PHASE-5", f"Partial failure: {'; '.join(errors)} — processing available results", "warn")

    # ── Process 5A results ──
    if resp_5a:
        infra_dir = out_dir / "infra"
        infra_dir.mkdir(exist_ok=True)
        for filename, content, lang in extract_all_code_blocks(resp_5a):
            save(infra_dir / filename, content)
            results["infra_files"].append(filename)
            if filename.endswith(".py"):
                val = validate_generated_code(content, filename)
                results["validation"][filename] = val
                status = "+" if val["valid"] else "!"
                log("PHASE-5A", f"[{status}] {val['summary']}", "ok" if val["valid"] else "warn")

    # ── 5A disk recovery ──
    # Claude Code runs with --dangerously-skip-permissions and can write files
    # directly to infra/ via its file tools during the call — the prompt asks
    # it to do exactly that. When it does, the response text may say "I've
    # written the files" without embedding the code as blocks, so
    # extract_all_code_blocks yields nothing. Files are already in infra/,
    # so just register them without copying.
    if not results["infra_files"]:
        infra_dir = out_dir / "infra"
        infra_dir.mkdir(exist_ok=True)
        for fname in ("__main__.py", "Pulumi.yaml", "requirements.txt"):
            fpath = infra_dir / fname
            if fpath.exists():
                content = fpath.read_text(encoding="utf-8")
                results["infra_files"].append(fname)
                if fname.endswith(".py"):
                    val = validate_generated_code(content, fname)
                    results["validation"][fname] = val
                    icon = "+" if val["valid"] else "!"
                    log("PHASE-5A", f"[{icon}] Recovered {fname} from infra/ — {val['summary']}", "warn")
                else:
                    log("PHASE-5A", f"[+] Recovered {fname} from infra/ (written by Claude Code tools)", "warn")

    # ── Process 5B results ──
    attack_code_combined = ""
    if resp_5b:
        scripts_dir = out_dir / "emulation_scripts"
        scripts_dir.mkdir(exist_ok=True)
        for filename, content, lang in extract_all_code_blocks(resp_5b):
            if lang == "python":
                save(scripts_dir / filename, content)
                results["attack_files"].append(filename)
                attack_code_combined += content + "\n"
                val = validate_generated_code(content, filename)
                results["validation"][filename] = val
                status = "+" if val["valid"] else "!"
                log("PHASE-5B", f"[{status}] {val['summary']}", "ok" if val["valid"] else "warn")

                # Tier 1B: Module load check. Only runs if syntax/imports passed —
                # importing a module with bad syntax or undeclared packages
                # would just repeat what earlier tiers already told us.
                if val["valid"]:
                    load_res = validate_module_loads(scripts_dir / filename)
                    val["tiers"]["module_load"] = load_res
                    if not load_res["valid"]:
                        val["valid"] = False
                        val["error_count"] += len(load_res["errors"])
                        for e in load_res["errors"]:
                            log("PHASE-5B", f"[!] {filename} module load failed: {e}", "warn")
                    else:
                        log("PHASE-5B", f"[+] {filename} imports cleanly", "dim")

    # ── 5B disk recovery ──
    # The prompt directs Claude Code to write attack.py directly to emulation_scripts/.
    # If the response had no code block, check emulation_scripts/ first, then fall
    # back to infra/ (legacy location from earlier prompt versions).
    if not results["attack_files"]:
        scripts_dir = out_dir / "emulation_scripts"
        scripts_dir.mkdir(exist_ok=True)
        attack_disk = scripts_dir / "attack.py"
        if not attack_disk.exists():
            attack_disk = out_dir / "infra" / "attack.py"
        if attack_disk.exists():
            content = attack_disk.read_text(encoding="utf-8")
            if attack_disk.parent != scripts_dir:
                save(scripts_dir / "attack.py", content)
            results["attack_files"].append("attack.py")
            attack_code_combined += content + "\n"
            val = validate_generated_code(content, "attack.py")
            results["validation"]["attack.py"] = val
            icon = "+" if val["valid"] else "!"
            log("PHASE-5B", f"[{icon}] Recovered attack.py from {attack_disk.parent.name}/ — {val['summary']}", "warn")
            if val["valid"]:
                load_res = validate_module_loads(scripts_dir / "attack.py")
                val["tiers"]["module_load"] = load_res
                if not load_res["valid"]:
                    val["valid"] = False
                    val["error_count"] += len(load_res["errors"])
                    for err_msg in load_res["errors"]:
                        log("PHASE-5B", f"[!] attack.py module load failed: {err_msg}", "warn")
                else:
                    log("PHASE-5B", "[+] attack.py imports cleanly", "dim")

    # ── Technique coverage check ──
    if attack_code_combined:
        cov = validate_technique_coverage(attack_code_combined, attack_plan)
        results["technique_coverage"] = cov
        if cov["missing"]:
            log("PHASE-5B",
                f"Technique coverage: {cov['coverage_pct']}% — "
                f"missing: {', '.join(cov['missing'])}", "warn")
        else:
            log("PHASE-5B", f"Technique coverage: {cov['coverage_pct']}% — all techniques present", "ok")
        if cov["warnings"]:
            for w in cov["warnings"]:
                log("PHASE-5B", f"  {w}", "dim")

    # ── Cross-validate __main__.py ↔ attack.py ──────────────────────────────
    # Catches name/path/env-var mismatches that let both scripts pass individual
    # validation but fail at runtime (wrong cluster name, missing --show-secrets, etc.)
    infra_main_path = out_dir / "infra" / "__main__.py"
    if infra_main_path.exists() and attack_code_combined:
        infra_content = infra_main_path.read_text(encoding="utf-8")
        xval = cross_validate_phase5(infra_content, attack_code_combined)
        results["cross_validation"] = xval
        for w in xval.get("warnings", []):
            log("PHASE-5", f"[cross-val] {w}", "dim")
        if xval["errors"]:
            for err in xval["errors"]:
                log("PHASE-5", f"[cross-val] DEPLOY BLOCKER: {err}", "err")
            log("PHASE-5",
                f"Cross-validation: {xval['error_count']} deploy blocker(s) — "
                "fix before running pulumi up", "err")
        else:
            log("PHASE-5", "Cross-validation: __main__.py <-> attack.py consistent", "ok")

    # Summary
    total_errors = sum(v.get("error_count", 0) for v in results["validation"].values())
    log("PHASE-5", f"Done: {len(results['infra_files'])} infra + "
        f"{len(results['attack_files'])} attack files ({total_errors} errors)", "ok")

    update_manifest(out_dir, "phase_5", _rate_limit_aware_status(errors, results["attack_files"]), {
        "infra_files": len(results["infra_files"]),
        "attack_files": len(results["attack_files"]),
        "validation_errors": total_errors,
        "technique_coverage_pct": results.get("technique_coverage", {}).get("coverage_pct"),
    })
    return results


# ══════════════════════════════════════════════════════════════════════════
# PHASE 6 — Detections + Playbooks + Guardrails
# ══════════════════════════════════════════════════════════════════════════

def phase_6_detections_and_content(
    ti_extract: dict, attack_plan: dict, out_dir: Path,
    skip_sigma: bool = False, skip_guardrails: bool = False,
    max_concurrency: int = 2,
) -> dict:
    """Generate SIGMA rules, KQL, IR playbooks, guardrails — ALL IN PARALLEL (6A || 6B || 6C).

    max_concurrency caps simultaneous Claude calls within this phase (MED-3).
    Default 2 means at most 2 of the three sub-tasks run concurrently. 1 = serial.
    """
    platform = ti_extract.get("platform", "aws")
    implementor_det = _load_implementor(AGENTS_DIR, "detections", platform)
    implementor_pb  = _load_implementor(AGENTS_DIR, "playbook",    platform)
    implementor_gr  = _load_implementor(AGENTS_DIR, "guardrails",  platform)
    results = {"sigma": [], "kql": [], "detection_notes": [], "playbooks": [], "guardrails": []}

    # Compact JSON for all prompts (~30% smaller than indent=2)
    # attack_for_detections strips implementation details only needed by Phase 5B
    # (implementation steps, cleanup_actions, script_manifest) — saves ~8K tokens/run
    attack_compact = json.dumps(attack_for_detections(attack_plan), separators=(",", ":"))
    ti_compact = json.dumps(ti_for_detections(ti_extract), separators=(",", ":"))

    # ── Build all three prompts ──
    det_prompt = (
        f"TASK: GENERATE DETECTIONS\n\n"
        f"## Output Directory\n"
        f"Write ALL detection files to this exact directory: {out_dir / 'detections'}\n"
        f"Do NOT write to a relative path like 'detections/' — use the full absolute path above.\n\n"
        f"## Attack Plan\n```json\n{attack_compact}\n```\n\n"
        f"## Threat Intelligence\n```json\n{ti_compact}\n```\n\n"
        f"Generate SIGMA rules + KQL for every control_plane technique.\n"
        f"For data_plane techniques, generate detection notes explaining alternatives.\n"
        f"Adapt audit log field names to the platform (CloudTrail for AWS, "
        f"Activity Log for Azure, Okta System Log for identity, etc.)."
    )
    pb_prompt = (
        f"TASK: GENERATE PLAYBOOK\n\n"
        f"## Attack Plan\n```json\n{attack_compact}\n```\n\n"
        f"## Threat Intelligence\n```json\n{ti_compact}\n```\n\n"
        f"Generate a comprehensive SANS PICERL playbook covering all techniques.\n"
        f"Include actual CLI commands for investigation and containment — "
        f"use the appropriate CLI for the platform (aws, az, gcloud, okta, gh, etc.).\n\n"
        f"IMPORTANT: Output the COMPLETE playbook markdown directly in your response. "
        f"Do NOT write to a file. Do NOT use file tools. "
        f"The entire playbook content must appear in your text reply."
    )
    gr_prompt = (
        f"TASK: GENERATE GUARDRAILS\n\n"
        f"## Attack Plan\n```json\n{attack_compact}\n```\n\n"
        f"## Threat Intelligence\n```json\n{ti_compact}\n```\n\n"
        f"Generate preventive guardrail policies appropriate to the platform for every technique. "
        f"Use the platform field from the TI extract to determine policy types "
        f"(AWS: SCP/RCP/IAM boundaries, Azure: Azure Policy/Conditional Access, "
        f"Okta: sign-on/MFA policies, SaaS: OAuth/API token restrictions, etc.)."
    )

    # ── Dispatch 6A, 6B, 6C in parallel (any can be skipped via flags) ──
    if skip_sigma:
        log("PHASE-6A", "Skipping SIGMA/KQL generation (--playbook-only)", "dim")
    if skip_guardrails:
        log("PHASE-6C", "Skipping guardrail generation (--playbook-only)", "dim")
    log("PHASE-6", f"Generating {'playbook only' if skip_sigma and skip_guardrails else 'detections + playbook + guardrails'} in parallel…")

    def run_6a():
        log("PHASE-6A", "Generating detection rules…")
        resp, _ = call_claude(SONNET, implementor_det, det_prompt, "PHASE-6A", timeout=600)
        save(out_dir / "phase6a_raw.md", resp)
        return resp

    def run_6b():
        log("PHASE-6B", "Generating IR playbook…")
        resp, _ = call_claude(SONNET, implementor_pb, pb_prompt, "PHASE-6B", timeout=600)
        return resp

    def run_6c():
        log("PHASE-6C", "Generating guardrail policies…")
        resp, _ = call_claude(SONNET, implementor_gr, gr_prompt, "PHASE-6C", timeout=600)
        return resp

    with ThreadPoolExecutor(max_workers=min(3, max_concurrency)) as pool:
        fut_6a = pool.submit(run_6a) if not skip_sigma else None
        fut_6b = pool.submit(run_6b)
        fut_6c = pool.submit(run_6c) if not skip_guardrails else None

        resp_6a = resp_6b = resp_6c = None
        p6_errors = []
        futures_to_run = []
        if fut_6a: futures_to_run.append(("6A", fut_6a))
        futures_to_run.append(("6B", fut_6b))
        if fut_6c: futures_to_run.append(("6C", fut_6c))
        for name, fut in futures_to_run:
            try:
                r = fut.result()
                if name == "6A": resp_6a = r
                elif name == "6B": resp_6b = r
                else: resp_6c = r
            except Exception as e:
                log(f"PHASE-{name}", f"Failed: {e}", "err")
                p6_errors.append(f"{name}: {e}")
        if p6_errors:
            log("PHASE-6", f"Partial failure: {'; '.join(p6_errors)} — processing available results", "warn")

    # ── Process 6A results ──
    if resp_6a:
        rules_dir = out_dir / "detections"
        rules_dir.mkdir(exist_ok=True)
        for filename, content, lang in extract_all_code_blocks(resp_6a):
            save(rules_dir / filename, content)
            if lang == "yaml":
                results["sigma"].append(filename)
                sv = validate_sigma_rule(content)
                if not sv["valid"]:
                    log("PHASE-6A", f"SIGMA issues in {filename}: {sv['errors']}", "warn")
            elif lang in ("kql", "text") and "kql" in filename.lower():
                results["kql"].append(filename)
            else:
                results["detection_notes"].append(filename)

    # ── 6A disk recovery ──
    # Same pattern as 5A/5B: the det_prompt tells Claude to write files directly
    # to {out_dir}/detections/. If it does, extract_all_code_blocks yields
    # nothing and results stay at 0 even though the files exist on disk.
    # This was the AMBERSQUID "recovered from pre-fix root/detections/" incident.
    if not results["sigma"] and not results["kql"] and not results["detection_notes"]:
        rules_dir = out_dir / "detections"
        if rules_dir.exists():
            for fpath in sorted(rules_dir.iterdir()):
                if not fpath.is_file():
                    continue
                fname = fpath.name
                content = fpath.read_text(encoding="utf-8")
                if fpath.suffix in (".yml", ".yaml"):
                    results["sigma"].append(fname)
                    sv = validate_sigma_rule(content)
                    if not sv["valid"]:
                        log("PHASE-6A", f"SIGMA issues in {fname}: {sv['errors']}", "warn")
                    log("PHASE-6A", f"[+] Recovered {fname} from detections/ (written by Claude Code tools)", "warn")
                elif "kql" in fname.lower():
                    results["kql"].append(fname)
                    log("PHASE-6A", f"[+] Recovered {fname} from detections/ (written by Claude Code tools)", "warn")
                elif fpath.suffix in (".md", ".txt"):
                    results["detection_notes"].append(fname)
                    log("PHASE-6A", f"[+] Recovered {fname} from detections/ (written by Claude Code tools)", "warn")
            if results["sigma"] or results["kql"] or results["detection_notes"]:
                log("PHASE-6A",
                    f"Recovered {len(results['sigma'])} SIGMA, "
                    f"{len(results['kql'])} KQL, "
                    f"{len(results['detection_notes'])} notes from disk", "warn")

    # ── Process 6B results ──
    if resp_6b:
        pb_dir = out_dir / "ir_playbooks"
        pb_dir.mkdir(exist_ok=True)
        actor = ti_extract.get("threat_actor", {}).get("name", "unknown").replace(" ", "_")
        pb_file = f"playbook_{actor}.md"
        save(pb_dir / pb_file, resp_6b)
        results["playbooks"].append(pb_file)

    # ── Process 6C results ──
    gr_count = 0
    if resp_6c:
        gr_dir = out_dir / "guardrails"
        gr_dir.mkdir(exist_ok=True)
        gr_data = extract_json(resp_6c)
        if gr_data:
            save_json(gr_dir / "guardrails.json", gr_data)
            results["guardrails"].append("guardrails.json")
            gr_count = len(gr_data.get("guardrails", []))
        else:
            save(gr_dir / "guardrails_raw.md", resp_6c)

    log("PHASE-6", f"Done: {len(results['sigma'])} SIGMA, {len(results['kql'])} KQL, "
        f"{len(results['detection_notes'])} notes, "
        f"{len(results['playbooks'])} playbooks, {gr_count} guardrails", "ok")

    update_manifest(out_dir, "phase_6", _rate_limit_aware_status(p6_errors), {
        "sigma": len(results["sigma"]), "kql": len(results["kql"]),
        "detection_notes": len(results["detection_notes"]),
        "playbooks": len(results["playbooks"]), "guardrails": gr_count,
    })
    return results


# ══════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════

def _try_recover_from_disk(out_dir, phase_key, log_label, filename, schema_key, meta_fn=None):
    """Auto-recover a phase from a valid on-disk artifact without manual intervention.

    The pipeline can crash *after* writing its output file but *before*
    recording the phase as complete in run_manifest.json — e.g. due to a
    rate-limit exit, an extract_json fragmentation failure, or a signal.
    The next ``--resume`` would then wastefully re-run the entire phase.

    This helper detects that situation automatically:
      1. If ``filename`` doesn't exist in ``out_dir`` → no recovery possible.
      2. Load the file; if it can't be parsed → no recovery.
      3. Validate with ``validate_json_schema``; if critical errors → re-run.
      4. Otherwise: stamp the manifest complete and return the loaded data
         dict so the caller can skip re-running the phase entirely.

    Returns ``None`` whenever recovery is not possible, so callers can use
    the idiomatic pattern::

        data = _try_recover_from_disk(...)
        if data is None:
            data = run_phase(...)
    """
    filepath = out_dir / filename
    if not filepath.exists():
        return None
    try:
        data = load_json(filepath)
    except Exception as exc:
        log(log_label,
            f"Disk recovery: {filename} exists but failed to load ({exc}) — re-running",
            "warn")
        return None
    validation = validate_json_schema(data, schema_key)
    if validation.get("critical_errors"):
        log(log_label,
            f"Disk recovery: {filename} has critical schema errors — re-running phase",
            "warn")
        return None
    meta = meta_fn(data) if meta_fn else {}
    log(log_label,
        f"✅ Recovered valid {filename} from prior run — marking {phase_key} complete automatically",
        "warn")
    update_manifest(out_dir, phase_key, "complete", {"recovered_from_disk": True, **meta})
    return data


def _find_resume_dir(run_id_or_latest: str) -> Path:
    """Locate the output directory for --resume."""
    if run_id_or_latest == "latest":
        if not OUTPUT_DIR.exists():
            raise PipelineError("No output directory found. Nothing to resume.")
        candidates = sorted(
            [d for d in OUTPUT_DIR.iterdir()
             if d.is_dir() and (d / "run_manifest.json").exists()],
            key=lambda d: d.name,
            reverse=True,
        )
        if not candidates:
            raise PipelineError("No previous runs found to resume.")
        return candidates[0]

    target = OUTPUT_DIR / run_id_or_latest
    if not target.exists():
        raise PipelineError(f"Run directory not found: {target}")
    if not (target / "run_manifest.json").exists():
        raise PipelineError(f"No manifest in {target} — cannot resume.")
    return target


def run_pipeline(args, tool_versions: "dict | None" = None):
    """Execute the full pipeline with optional --resume support.

    When resuming, completed phases are skipped and their artifacts loaded
    from disk, saving all the Claude API calls / human approvals already done.

    tool_versions — ``{tool: version_string}`` dict from validate_environment(),
    stamped into the manifest so runs are reproducible (LOW-3).
    """

    # ── Determine output directory (new run vs resume) ──
    if args.resume:
        out_dir = _find_resume_dir(args.resume)
        run_id = out_dir.name
        manifest = load_manifest(out_dir) or {}
        log("PIPELINE", f"Resuming run: {run_id}")

        # Recover original input from manifest if not supplied on CLI
        stored = manifest.get("phases", {}).get("pipeline", {})
        if not args.url and not args.technique:
            stored_input = stored.get("input", "")
            if stored_input.startswith("http"):
                args.url = stored_input
            elif stored_input:
                args.technique = stored_input
            else:
                raise PipelineError(
                    "Cannot determine input from manifest. "
                    "Supply --url or --technique explicitly.")

        # Show what's already done
        phases = manifest.get("phases", {})
        completed = [p for p, d in phases.items()
                     if d.get("status") == "complete" and p != "pipeline"]
        if completed:
            log("RESUME", f"Completed phases: {', '.join(sorted(completed))}", "dim")
    else:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = OUTPUT_DIR / run_id
        out_dir.mkdir(parents=True, exist_ok=True)

    # Load manifest ONCE — subsequent done() checks read the in-memory dict
    # instead of hitting the disk 27+ times on a resume run.
    _manifest: dict = (manifest if args.resume else {})  # type: ignore[possibly-unbound]

    def done(phase: str) -> bool:
        """Return True if this phase completed in a prior run (resume mode only)."""
        if not args.resume:
            return False
        return _manifest.get("phases", {}).get(phase, {}).get("status") == "complete"

    mode = "full-apt" if args.url else "single-technique"
    if not args.resume:
        log("PIPELINE", f"Run: {run_id} | Mode: {mode}")
    log("PIPELINE", f"Output: {out_dir}")

    update_manifest(out_dir, "pipeline", "started", {
        "mode": mode, "input": args.url or args.technique,
        **({"tool_versions": tool_versions} if tool_versions else {}),
    })

    try:
        # ── Phase 0A: Security check (advisory) ──
        if not args.skip_security_check:
            if done("phase_0a"):
                log("PHASE-0A", "Skipping (already complete)", "dim")
            else:
                phase_0a_security_check(out_dir, args.aws_profile, args.aws_region)

        # ── Phase 0B: TI Extraction ──
        if done("phase_0b"):
            log("PHASE-0B", "Skipping — loading ti_extract.json", "dim")
            ti_extract = load_json(out_dir / "ti_extract.json")
        else:
            if args.url:
                # ── Content-hash cache: skip Phase 0B for repeated URLs ──
                # Saves ~180 k tokens / ~$0.54 per repeated run against the
                # same article (both Claude calls + HTTP fetch are skipped).
                cached_ti = _load_ti_cache(args.url)
                if cached_ti is not None:
                    log("PHASE-0B",
                        "Content-hash cache hit — skipping TI extraction "
                        f"({len(cached_ti.get('techniques', []))} techniques "
                        f"from prior run)", "dim")
                    ti_extract = cached_ti
                    save_json(out_dir / "ti_extract.json", ti_extract)
                    update_manifest(out_dir, "phase_0b", "complete", {
                        "source": "content_hash_cache",
                        "techniques": len(ti_extract.get("techniques", [])),
                        "threat_actor": ti_extract.get("threat_actor", {}).get("name", "Unknown"),
                        "tokens": 0,
                    })
                else:
                    # Reuse cached article text if available (saves HTTP fetch on resume)
                    article_path = out_dir / "article.txt"
                    if article_path.exists():
                        article = article_path.read_text(encoding="utf-8")
                        log("FETCH", f"Using cached article ({len(article)} chars)", "dim")
                    else:
                        article = fetch_article(args.url)
                        save(out_dir / "article.txt", article)
                    ti_extract = phase_0b_ti_extraction(article, args.url, out_dir)
                    _save_ti_cache(args.url, ti_extract)
            else:
                ti_extract = phase_0b_single_technique(args.technique, out_dir)

        # ── Rename output dir to include APT name (new runs only) ──
        # e.g. 20260426_053635 → 20260426_053635_AMBERSQUID
        # Makes emulation_output/ navigable without opening manifests.
        if not args.resume:
            actor_raw = ti_extract.get("threat_actor", {}).get("name", "")
            if actor_raw:
                actor_slug = re.sub(r"[^A-Za-z0-9]+", "_", actor_raw.strip()).strip("_").upper()[:30]
                if actor_slug:
                    new_out_dir = OUTPUT_DIR / f"{run_id}_{actor_slug}"
                    out_dir.rename(new_out_dir)
                    out_dir = new_out_dir
                    run_id = out_dir.name
                    log("PIPELINE", f"Output → {out_dir.name}", "dim")

        # ── Human Gate: TI Extract (skip if Phase 1+ already passed) ──
        if not args.auto_approve and not done("phase_1"):
            techs = ti_extract.get("techniques", [])
            summary = "\n".join(
                f"  {t.get('mitre_id','?'):12s} {t.get('name','?'):40s} "
                f"[{t.get('execution_plane','?')}] [{t.get('emulation_category','?')}]"
                for t in techs
            )
            creds = ti_extract.get("credential_chain", [])
            cred_info = "\n".join(
                f"  Phase {c.get('phase','?')}: {c.get('source','?')} → used in {c.get('used_in_phases','?')}"
                for c in creds
            ) if creds else "  No credential chain defined"

            display = f"Techniques:\n{summary}\n\nCredential Chain:\n{cred_info}"
            decision = human_gate("TI-EXTRACT", display,
                f"{len(techs)} techniques extracted. Review ti_extract.json.\nType APPROVED to continue.")
            if decision == "ABORT":
                raise PipelineError("Aborted at TI extraction.")

        # ── Phase 1: Infrastructure Planning ──
        if done("phase_1"):
            log("PHASE-1", "Skipping — loading infra_plan.json", "dim")
            infra_plan = load_json(out_dir / "infra_plan.json")
        else:
            infra_plan = _try_recover_from_disk(
                out_dir, "phase_1", "PHASE-1", "infra_plan.json", "infra_plan",
                lambda d: {"resources": len(d.get("resources", []))},
            )
            if infra_plan is None:
                infra_plan = phase_1_infra_plan(ti_extract, out_dir)

        # ── Cost Estimation (Phase 1 — standing infra only, no attack plan yet) ──
        if not getattr(args, "skip_cost", False):
            try:
                cost_est = estimate_cost(infra_plan, {}, region=args.aws_region)
                save_json(out_dir / "cost_estimate.json", cost_est)
                sc = cost_est["standing_cost"]
                log("COST", (
                    f"Standing infra: ${sc['hourly_usd']:.3f}/hr | "
                    f"${sc['daily_usd']:.2f}/day | "
                    f"${sc['monthly_usd']:.2f}/mo"
                ))
                if cost_est.get("warnings"):
                    for w in cost_est["warnings"]:
                        log("COST", w, "warn")
                update_manifest(out_dir, "phase_cost", "complete", {
                    "hourly": sc["hourly_usd"],
                    "daily": sc["daily_usd"],
                    "monthly": sc["monthly_usd"],
                })
            except Exception as _ce:
                log("COST", f"Cost estimation failed (non-fatal): {_ce}", "warn")

        # ── Phase 2: Infrastructure Review ──
        if done("phase_2"):
            log("PHASE-2", "Skipping — loading infra_plan_approved.json", "dim")
            infra_plan = load_json(out_dir / "infra_plan_approved.json")
        else:
            infra_plan = phase_2_infra_review(ti_extract, infra_plan, out_dir, args.max_iterations)

        # ── Human Gate: Infrastructure (skip if Phase 3+ already passed) ──
        if not args.auto_approve and not done("phase_3"):
            resources = infra_plan.get("resources", [])
            res_list = "\n".join(
                f"  [{r.get('resource_category','?'):14s}] {r.get('name','?'):30s} ({r.get('pulumi_type','?')})"
                for r in resources
            )
            # Prepend cost summary table so reviewer can reject if too expensive
            cost_table_prefix = ""
            _cost_est_path = out_dir / "cost_estimate.json"
            if not getattr(args, "skip_cost", False) and _cost_est_path.exists():
                try:
                    _ce = load_json(_cost_est_path)
                    cost_table_prefix = _ce.get("summary_table", "") + "\n\n"
                except Exception:
                    pass
            decision = human_gate("INFRASTRUCTURE", cost_table_prefix + res_list,
                f"{len(resources)} resources planned. Type APPROVED to continue.")
            if decision == "ABORT":
                raise PipelineError("Aborted at infrastructure review.")

        # ── Phase 3: Attack Planning ──
        if done("phase_3"):
            log("PHASE-3", "Skipping — loading attack_plan.json", "dim")
            attack_plan = load_json(out_dir / "attack_plan.json")
        else:
            attack_plan = _try_recover_from_disk(
                out_dir, "phase_3", "PHASE-3", "attack_plan.json", "attack_plan",
                lambda d: {
                    "steps": len(d.get("attack_chain", [])),
                    "credential_pivots": len(d.get("credential_chain", [])),
                },
            )
            if attack_plan is None:
                attack_plan = phase_3_attack_plan(ti_extract, infra_plan, out_dir)

        # ── Cost Re-estimation (Phase 3 — include transient resources) ──
        if not getattr(args, "skip_cost", False):
            try:
                cost_est = estimate_cost(infra_plan, attack_plan, region=args.aws_region)
                save_json(out_dir / "cost_estimate.json", cost_est)
                sc = cost_est["standing_cost"]
                pr = cost_est["per_run_cost"]
                log("COST", (
                    f"Updated estimate (with attack plan): "
                    f"${sc['hourly_usd']:.3f}/hr standing | "
                    f"~${pr['estimated_usd']:.4f} per run"
                ))
                if cost_est.get("warnings"):
                    for w in cost_est["warnings"]:
                        log("COST", w, "warn")
                update_manifest(out_dir, "phase_cost", "complete", {
                    "hourly": sc["hourly_usd"],
                    "daily": sc["daily_usd"],
                    "monthly": sc["monthly_usd"],
                    "per_run_usd": pr["estimated_usd"],
                })
            except Exception as _ce:
                log("COST", f"Cost re-estimation failed (non-fatal): {_ce}", "warn")

        # ── Phase 4: Attack Plan Review ──
        if done("phase_4"):
            log("PHASE-4", "Skipping — loading attack_plan_approved.json", "dim")
            attack_plan = load_json(out_dir / "attack_plan_approved.json")
        else:
            _recovered_p4 = _try_recover_from_disk(
                out_dir, "phase_4", "PHASE-4", "attack_plan_approved.json", "attack_plan",
                lambda d: {
                    "steps": len(d.get("attack_chain", [])),
                    "credential_pivots": len(d.get("credential_chain", [])),
                },
            )
            if _recovered_p4 is not None:
                attack_plan = _recovered_p4
            else:
                attack_plan = phase_4_attack_review(
                    ti_extract, infra_plan, attack_plan, out_dir, args.max_iterations)

        # ── Human Gate: Attack Plan (skip if Phase 5+ already passed) ──
        if not args.auto_approve and not done("phase_5"):
            steps = attack_plan.get("attack_chain", [])
            step_list = "\n".join(
                f"  {s.get('step',0):2d}. [{s.get('execution_context','?'):16s}] "
                f"{s.get('technique_id','?'):12s} — {s.get('technique_name','?')}"
                for s in steps
            )
            creds = attack_plan.get("credential_chain", [])
            cred_list = "\n".join(
                f"  Phase {c.get('phase','?')}: {c.get('source','?')} "
                f"({c.get('type','?')}) → phases {c.get('used_in_phases','?')}"
                for c in creds
            ) if creds else ""

            display = f"Attack Steps:\n{step_list}"
            if cred_list:
                display += f"\n\nCredential Chain:\n{cred_list}"

            decision = human_gate("ATTACK-PLAN", display,
                f"{len(steps)} steps planned. Type APPROVED to generate code.")
            if decision == "ABORT":
                raise PipelineError("Aborted at attack plan review.")

        # ── Phase 5 + 6: Code Gen + Detections (IN PARALLEL) ──
        impl_results = {}
        det_results = {}
        if not args.plan_only:
            p5_done = done("phase_5")
            p6_done = done("phase_6")

            if p5_done and p6_done:
                log("PHASE-5", "Skipping (already complete)", "dim")
                log("PHASE-6", "Skipping (already complete)", "dim")
            elif p5_done:
                log("PHASE-5", "Skipping (already complete)", "dim")
                det_results = phase_6_detections_and_content(
                    ti_extract, attack_plan, out_dir,
                    skip_sigma=args.playbook_only,
                    skip_guardrails=args.playbook_only,
                    max_concurrency=args.max_concurrency)
            elif p6_done:
                log("PHASE-6", "Skipping (already complete)", "dim")
                impl_results = phase_5_code_generation(
                    ti_extract, infra_plan, attack_plan, out_dir,
                    max_concurrency=args.max_concurrency,
                    test_mode=args.test_mode)
            else:
                log("PIPELINE", "Starting Phase 5 (code gen) + Phase 6 (detections) in parallel…")
                with ThreadPoolExecutor(max_workers=2) as pool:
                    fut_5 = pool.submit(
                        phase_5_code_generation, ti_extract, infra_plan, attack_plan, out_dir,
                        args.max_concurrency, args.test_mode)
                    fut_6 = pool.submit(
                        phase_6_detections_and_content, ti_extract, attack_plan, out_dir,
                        args.playbook_only, args.playbook_only, args.max_concurrency)

                    p56_errors = []
                    try:
                        impl_results = fut_5.result()
                    except Exception as e:
                        log("PHASE-5", f"Failed: {e}", "err")
                        p56_errors.append(f"Phase 5: {e}")
                    try:
                        det_results = fut_6.result()
                    except Exception as e:
                        log("PHASE-6", f"Failed: {e}", "err")
                        p56_errors.append(f"Phase 6: {e}")

                    # Surface rate-limit exits prominently — they mean "restart
                    # after reset time" not a real failure.
                    rate_exits = [e for e in p56_errors if "RATE_LIMIT_EXIT" in e]
                    if rate_exits:
                        reset_hint = rate_exits[0].split("resets at")[-1].strip().rstrip(".")
                        log("PIPELINE",
                            f"Rate limit hit — rerun after {reset_hint} "
                            f"(phases 0-4 will be skipped automatically).", "warn")
                    if p56_errors and not impl_results and not det_results:
                        raise PipelineError(f"Phases 5+6 failed: {'; '.join(p56_errors)}")
                    if p56_errors:
                        log("PIPELINE", f"Partial failure: {'; '.join(p56_errors)}", "warn")

        # ── Final Summary ──
        token_summary = get_token_summary()

        # Count review-loop fallbacks across all phases.
        # `fallback: True` in a phase's manifest entry means the reviewer
        # approved a draft but `extract_json` could not parse it, so the
        # pipeline fell back to the un-revised plan. This is a silent
        # correctness risk — the reviewer may have asked for changes that
        # never made it into the downstream phases.
        run_manifest = load_manifest(out_dir) or {}
        fallback_phases = [
            p for p, meta in run_manifest.get("phases", {}).items()
            if meta.get("fallback")
        ]
        fallback_count = len(fallback_phases)

        update_manifest(out_dir, "pipeline", "complete", {
            "end_time": datetime.now(timezone.utc).isoformat(),
            "tokens": token_summary,
            "fallback_count": fallback_count,
            "fallback_phases": fallback_phases,
        })

        sep = "═" * 60
        print(f"\n{sep}")
        log("PIPELINE", "PIPELINE COMPLETE", "ok")
        print(sep)
        log("SUMMARY", f"Run ID:          {run_id}")
        log("SUMMARY", f"Output:          {out_dir}")

        actor = ti_extract.get("threat_actor", {}).get("name", "Unknown")
        log("SUMMARY", f"Threat Actor:    {actor}")
        log("SUMMARY", f"Techniques:      {len(ti_extract.get('techniques', []))}")
        log("SUMMARY", f"Cred Pivots:     {len(ti_extract.get('credential_chain', []))}")

        if impl_results:
            log("SUMMARY", f"Infra files:     {len(impl_results.get('infra_files', []))}")
            log("SUMMARY", f"Attack scripts:  {len(impl_results.get('attack_files', []))}")
            val_errors = sum(v.get("error_count", 0) for v in impl_results.get("validation", {}).values())
            if val_errors:
                log("SUMMARY", f"Validation:      {val_errors} errors — review needed", "warn")
            else:
                log("SUMMARY", f"Validation:      All passed", "ok")

        if det_results:
            log("SUMMARY", f"SIGMA rules:     {len(det_results.get('sigma', []))}")
            log("SUMMARY", f"KQL queries:     {len(det_results.get('kql', []))}")
            log("SUMMARY", f"IR playbooks:    {len(det_results.get('playbooks', []))}")
            log("SUMMARY", f"Guardrails:      {len(det_results.get('guardrails', []))}")

        log("SUMMARY", f"API calls:       {token_summary['calls']}")
        log("SUMMARY", f"Est. cost:       ${token_summary['estimated_cost_usd']}")
        if fallback_count:
            log("SUMMARY",
                f"Review fallbacks: {fallback_count} "
                f"({', '.join(fallback_phases)}) — reviewer-approved drafts "
                f"failed JSON parsing; un-revised plans were used. Inspect "
                f"phaseN_fallback_raw.md files.", "warn")
        else:
            log("SUMMARY", "Review fallbacks: 0", "ok")
        for model_name, mdata in token_summary.get("per_model", {}).items():
            short = model_name.split("-")[-1] if "-" in model_name else model_name
            log("SUMMARY", f"  {short:12s}   {mdata['calls']} calls, ~{mdata['input_tokens']+mdata['output_tokens']} tokens, ${mdata['cost_usd']}", "dim")
        print(f"{sep}\n")

    except PipelineError as e:
        log("PIPELINE", f"{e}", "err")
        err_str = str(e)
        if "RATE_LIMIT_EXIT" in err_str:
            log("PIPELINE", "Rate-limit exit — auto-recovering completed phases from disk...", "warn")
            if not done("phase_1"):
                _try_recover_from_disk(
                    out_dir, "phase_1", "PHASE-1", "infra_plan.json", "infra_plan",
                    lambda d: {"resources": len(d.get("resources", []))},
                )
            if not done("phase_3"):
                _try_recover_from_disk(
                    out_dir, "phase_3", "PHASE-3", "attack_plan.json", "attack_plan",
                    lambda d: {"steps": len(d.get("attack_chain", [])), "credential_pivots": len(d.get("credential_chain", []))},
                )
            if not done("phase_4"):
                _try_recover_from_disk(
                    out_dir, "phase_4", "PHASE-4", "attack_plan_approved.json", "attack_plan",
                    lambda d: {"steps": len(d.get("attack_chain", [])), "credential_pivots": len(d.get("credential_chain", []))},
                )
        update_manifest(out_dir, "pipeline", "failed", {"error": err_str})
        sys.exit(1)
    except KeyboardInterrupt:
        log("PIPELINE", "Interrupted", "warn")
        update_manifest(out_dir, "pipeline", "interrupted")
        sys.exit(130)


# ══════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="MayaTrail APT Pipeline v2 — Content Authoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pipeline.py --url https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
  python pipeline.py --technique T1078.004
  python pipeline.py --url <url> --plan-only
  python pipeline.py --url <url> --auto-approve
  python pipeline.py --resume                         # resume latest run
  python pipeline.py --resume 20260415_120437          # resume specific run
  python pipeline.py --resume --url <url> --auto-approve  # resume with overrides
        """,
    )

    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument("--url", help="APT article URL (full-apt mode)")
    input_group.add_argument("--technique", help="MITRE technique ID (single-technique mode)")

    parser.add_argument("--resume", nargs="?", const="latest", default=None,
                        metavar="RUN_ID",
                        help="Resume a previous run (default: latest). Skips completed phases.")
    parser.add_argument("--aws-profile", default=None, help="AWS profile for Phase 0A security checks (optional, AWS-only)")
    parser.add_argument("--aws-region", default="us-east-1", help="AWS region for security checks (default: us-east-1, ignored for non-AWS)")
    parser.add_argument("--max-iterations", type=int, default=3, help="Review loop cap (default: 3)")
    parser.add_argument("--max-concurrency", type=int, default=2,
                        help="Max simultaneous Claude calls within a phase (default: 2). "
                             "Set to 1 to serialize all calls and avoid rate-limit bursts (MED-3).")
    parser.add_argument("--plan-only", action="store_true", help="Stop after Phase 4 (no code gen)")
    parser.add_argument("--auto-approve", action="store_true", help="Skip human gates (testing only)")
    parser.add_argument("--skip-security-check", action="store_true", help="Skip Phase 0A advisory check")
    parser.add_argument("--playbook-only", action="store_true",
                        help="Phase 6: generate IR playbook only (skip SIGMA rules and guardrails)")
    parser.add_argument("--skip-cost", action="store_true",
                        help="Skip cost estimation (useful for CI/auto-approve runs without AWS credentials)")
    parser.add_argument("--test-mode", action="store_true",
                        help="Override attack.py delays with 2-5 s values for iterative testing (LOW-2). "
                             "Real APT operational delays (5-60 min) are replaced with short test values.")
    parser.add_argument("--output-dir", default=None, help="Custom output directory")

    args = parser.parse_args()

    if not args.resume and not args.url and not args.technique:
        parser.error("--url or --technique is required (use --resume to continue a previous run)")

    if args.output_dir:
        global OUTPUT_DIR
        OUTPUT_DIR = Path(args.output_dir)

    log("PIPELINE", "Checking environment…")
    tool_versions = validate_environment()

    run_pipeline(args, tool_versions=tool_versions)


if __name__ == "__main__":
    main()
