"""
Technique : aws.impact.bedrock-invoke-model
Tactic    : Impact (T1496)
Source    : https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.bedrock-invoke-model/

Pre-requisites:
  - bedrock:InvokeModel permission.
  - Amazon Bedrock model access enabled for the account in the target region.
    Enable via: AWS Console → Bedrock → Model access → Request access
  - Recommended region: us-east-1 or us-west-2

How the attack works:
  An attacker with access to AWS credentials that have bedrock:InvokeModel
  can invoke foundation models in a loop, generating large inference costs.
  This is analogous to cryptomining but targets LLM billing quota exhaustion.

Detection signal:
  - bedrock:InvokeModel at high volume or from unexpected principals.
  - Sudden spike in Bedrock spend visible in AWS Cost Explorer.
  - CloudTrail records every InvokeModel call.

Revert:
  - Nothing to revert (API calls complete and are billed).
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import json

import boto3
from botocore.exceptions import ClientError


# ── Config ────────────────────────────────────────────────────────────────────

# Titan Text Lite is the cheapest Bedrock model — minimises real cost
MODEL_ID    = "amazon.titan-text-lite-v1"
NUM_CALLS   = 10
REGION      = "us-east-1"

PROMPT_BODY = json.dumps({
    "inputText": "Tell me a one-sentence fact about cloud security.",
    "textGenerationConfig": {
        "maxTokenCount": 50,
        "temperature": 0.7,
    },
})


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(msg: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main(session: "boto3.Session") -> None:
    bedrock  = session.client("bedrock-runtime", region_name=REGION)

    banner(f"Step 1 — Invoke {MODEL_ID} x{NUM_CALLS} (InvokeModel)")
    print(f"  Model  : {MODEL_ID}")
    print(f"  Region : {REGION}")
    print(f"  Calls  : {NUM_CALLS}")
    print()

    success = 0
    failed  = 0

    for i in range(1, NUM_CALLS + 1):
        try:
            response = bedrock.invoke_model(
                modelId=MODEL_ID,
                contentType="application/json",
                accept="application/json",
                body=PROMPT_BODY,
            )
            result_body = json.loads(response["body"].read())
            output_text = (
                result_body.get("results", [{}])[0]
                .get("outputText", "(no output)")
                .strip()
            )
            success += 1
            print(f"  [{i:02d}] {output_text[:100]}")
        except ClientError as exc:
            failed += 1
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException":
                print(f"  [{i:02d}] AccessDenied — ensure bedrock:InvokeModel permission and model access enabled.")
                break
            elif code == "ValidationException":
                print(f"  [{i:02d}] ValidationException — model may not be available in {REGION}.")
                break
            else:
                print(f"  [{i:02d}] ERROR: {code}")

    banner("Complete")
    print(f"  Successful calls : {success}")
    print(f"  Failed calls     : {failed}")
    print()
    print("CloudTrail events: bedrock:InvokeModel x N")
    print("\nDetection guidance:")
    print("  Alert on bedrock:InvokeModel spikes or invocations from unexpected")
    print("  principals.  Monitor Bedrock spend in AWS Cost Explorer daily.")


if __name__ == "__main__":
    main(boto3.Session())


# ── MayaTrail Option-C entry point ─────────────────────────────────────────────

def _session_from_outputs(outputs: dict, region: str) -> boto3.Session:
    """Build a session from the worker-injected assumed-role creds (Option C);
    fall back to the ambient default session when run standalone."""
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
    """Entry point called by the run_emulation_attack Celery task."""
    main(_session_from_outputs(outputs, region))
