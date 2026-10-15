#!/usr/bin/env bash
#
# Runs on the enterprise app instance, invoked over SSM by the deploy workflow.
# It deploys a single image tag: check out the matching git ref (so bind-mounted
# emulations, nginx.conf and this script match the image code), pull the private
# images using a short-lived token read from SSM, restart the stack, verify it is
# healthy, and remove the registry login so no standing credential is left.
#
# Inputs come from the environment (set by the SSM command the workflow builds):
#   IMAGE_TAG    the tag to run, e.g. sha-<full sha> or v0.3.0
#   GIT_REF      the git ref to check out (the bare sha, or the version tag)
#   AWS_REGION   region of the SSM token parameter
#   TOKEN_PARAM  SSM SecureString parameter holding the short-lived GHCR token
#   GHCR_USER    the GitHub actor the token belongs to
set -euo pipefail

: "${IMAGE_TAG:?IMAGE_TAG is required}"
: "${GIT_REF:?GIT_REF is required}"
: "${AWS_REGION:?AWS_REGION is required}"
: "${TOKEN_PARAM:?TOKEN_PARAM is required}"
: "${GHCR_USER:?GHCR_USER is required}"

REPO_DIR=/home/ec2-user/step1
COMPOSE_FILE=docker-compose-ec2.yaml
export HOME=/home/ec2-user

cd "$REPO_DIR"

echo "== checkout ${GIT_REF} =="
git -c safe.directory='*' fetch origin --tags --prune
git -c safe.directory='*' checkout --quiet "$GIT_REF"

echo "== record IMAGE_TAG in .env =="
umask 077
grep -v '^IMAGE_TAG=' .env > .env.tmp 2>/dev/null || true
mv .env.tmp .env
echo "IMAGE_TAG=${IMAGE_TAG}" >> .env

echo "== GHCR login with the short-lived token from SSM =="
# The token is read into a variable and piped to docker login; it is never
# written to disk or echoed. docker logout at the end removes the stored auth.
TOKEN="$(aws ssm get-parameter --name "$TOKEN_PARAM" --with-decryption \
          --region "$AWS_REGION" --query 'Parameter.Value' --output text)"
printf '%s' "$TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
unset TOKEN

echo "== pull the app images only =="
# Only the images this pipeline builds are pulled with the GHCR token, which is
# scoped to this repo. scout lives in another repo (MayaTrail/scout) and is a
# pinned external dependency; redis and nginx are public. All three are already
# present on the host, so up -d starts them without a pull.
docker compose -f "$COMPOSE_FILE" pull backend worker_enterprise beat ui
docker compose -f "$COMPOSE_FILE" up -d --remove-orphans

echo "== drop the registry login (no standing credential on the host) =="
docker logout ghcr.io || true

echo "== wait for health =="
ok=0
for _ in $(seq 1 36); do
  sleep 5
  backend_health="$(docker inspect -f '{{.State.Health.Status}}' step1-backend-1 2>/dev/null || echo none)"
  running="$(docker compose -f "$COMPOSE_FILE" ps --status running -q | wc -l | tr -d ' ')"
  if [ "$backend_health" = "healthy" ] && [ "$running" -ge 7 ]; then ok=1; break; fi
done

docker compose -f "$COMPOSE_FILE" ps
if [ "$ok" -ne 1 ]; then
  echo "DEPLOY UNHEALTHY: backend=${backend_health} running=${running}"
  docker logs step1-backend-1 --tail 40 2>&1 || true
  exit 1
fi
echo "DEPLOY OK: ${IMAGE_TAG}"
