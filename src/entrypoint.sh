#!/bin/bash
set -euo pipefail

ACTION="${ACTION:-preview}"
STACK="${STACK:-dev-default}"
STATE_BUCKET="${STATE_BUCKET:-mayatrail-pulumi-state}"
AWS_REGION="${AWS_REGION:-ap-south-1}"

echo " MayaTrail Pulumi Runner"
echo " Action : ${ACTION}"
echo " Stack  : ${STACK}"
echo " State  : s3://${STATE_BUCKET}"
echo " Region : ${AWS_REGION}"

# Login to S3-backed state backend
echo "[1/3] Logging into Pulumi state backend..."
pulumi login "s3://${STATE_BUCKET}" --non-interactive

# Select or create the stack
echo "[2/3] Selecting stack: ${STACK}..."
pulumi stack select "${STACK}" 2>/dev/null || pulumi stack init "${STACK}"

# Set the AWS region config for the stack
pulumi config set aws:region "${AWS_REGION}" --non-interactive

# Execute the requested action
echo "[3/3] Executing: pulumi ${ACTION}..."
echo ""

case "${ACTION}" in
  up)
    pulumi up --yes --non-interactive
    echo ""
    echo "Stack outputs:"
    pulumi stack output --json
    ;;
  destroy)
    pulumi destroy --yes --non-interactive
    ;;
  preview)
    pulumi preview --non-interactive
    ;;
  refresh)
    pulumi refresh --yes --non-interactive
    ;;
  *)
    echo "ERROR: Invalid ACTION '${ACTION}'. Valid options: up, destroy, preview, refresh"
    exit 1
    ;;
esac

echo ""
echo "Done."
