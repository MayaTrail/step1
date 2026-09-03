# IR Playbook: Lambda Function Code Overwritten — package replaced via `lambda:UpdateFunctionCode`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence — a function's deployment package is replaced, so attacker-supplied code runs on every invocation under the function's execution role |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. Certain code execution with no second act required. The source rule rates it P4 and scopes it to an identity type that excludes most modern principals. |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1525 |
| Services in Scope | Lambda, IAM, CloudTrail, AWS Signer |

**What the technique does:** the actor calls `UpdateFunctionCode` with their own package. The new
code *is* the handler — it runs on every invocation, immediately, with whatever permissions the
function's execution role carries. Unlike most techniques in this set there is no precondition and
no second step.

**Why the usual reflexes miss it.** The first, and the one that matters most, is scoping the rule to
`userIdentity.type:"IAMUser"`: SSO users, federated identities, instance roles and **CI/CD roles**
all arrive as `AssumedRole`, so a compromised deployment pipeline — the most plausible route to this
call — never trips the rule. The second is rating it P4, below the threshold at which anyone reads
it. The third is watching the code hash alone and concluding the function is intact: a handler or
layer change redirects execution while leaving `CodeSha256` unchanged, which is the sibling
technique. The fourth is assuming a rollback is available; it is, but only if versions were
published.

**Detection thesis:** cover every identity type, treat the deployment-role allowlist as the whole
discriminator, and read the code-signing rejections a success filter would discard.

**Adjacent playbooks and a deliberate scope limit.** The **full treatment of this technique** — the
`CodeSha256` drift baseline, the certain-versus-conditional execution reasoning, and the rollback
procedure — is the kit's worked example in `reference/PLAYBOOK.md`, and this playbook does not
restate it. Its complement is `../lambda.defense-evasion.function-configuration-modified/`, which
redirects execution *without* moving the code hash. Granting invoke permission is
`../lambda.persistence.resource-policy-backdoor/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. Lambda management events are **regional** and do not
aggregate into `us-east-1`, so a single-region trail covers only its own region's functions.

**The list of roles that legitimately deploy Lambda code.** This is not a tuning refinement — it is
the entire discriminator. `UpdateFunctionCode` is what every deployment does, so without the list
the rule is either silent or constant.

**Published versions and alias-based invocation.** A published version is immutable, which makes
rollback a one-call alias repoint. Where only `$LATEST` is ever used, the previous package is gone
the moment it is overwritten and recovery means redeploying from source.

Lambda **code signing** with a policy of `ENFORCE`. It converts this technique from a success into a
`CodeVerificationFailedException`, and the refused attempt is a better signal than the success it
prevents.

**Alerting (must be pre-configured)**

- **`UpdateFunctionCode` succeeds from a principal not on the deployment-role allowlist → P0**
- **Code replaced on three or more functions by one principal within an hour → P0**

**Response Tooling**

An IAM principal that can call `lambda get-function`, `list-versions-by-function`, `update-alias`
and `update-function-code` outside the change pipeline, in every region holding functions.

Access to the source repository and build pipeline for the affected function. Where versions were
not published, redeploying from source is the only recovery.

**Known IOC Baselines**

A recorded `CodeSha256` per function per environment, from the build pipeline rather than from AWS.
A hash read from AWS after the fact tells you what is deployed, not what should be.

The identity types your deployments actually use. If they are all `AssumedRole`, that is worth
knowing before an incident rather than during one.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `UpdateFunctionCode` succeeds from a principal not on the deployment-role allowlist | CloudTrail | T1525 |
| P0 | Code replaced on three or more functions by one principal within an hour | Correlation rule | T1525 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `UpdateFunctionCode` rejected with `CodeVerificationFailedException` or `InvalidCodeSignatureException` — the control held, and the attempt is still an attempt | CloudTrail | T1525 |
| P2 | Code and configuration both changed on the same function by the same principal | CloudTrail | T1525 / T1578.005 |
| P2 | `UpdateFunctionCode` from a deployment role at a time that does not match the release schedule | CloudTrail + change record | T1525 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `userIdentity.type:"IAMUser"` only | Excludes SSO, federation, instance roles and CI/CD roles — all `AssumedRole`, and a compromised pipeline is the most plausible route to this call. In most estates the rule has never fired | All identity types, with `IdentityTypes` projected in the query so the size of the gap is visible in real output |
| The pack is inconsistent about it | Two of its four Lambda rules carry the filter and two do not, for the same service and the same class of change | One consistent treatment, with the AWS-service exclusion done through `userIdentity.invokedBy` |
| Rated P4 | This is certain code execution under the function's role, with no precondition and no second act. P4 is below the threshold at which anyone reads it | High, with the deployment-role allowlist as the discriminator |
| Success filter drops the signing rejections | `CodeVerificationFailedException` and `InvalidCodeSignatureException` are the control working. AWS notes the integrity failure blocks deployment *"even if the code signing policy is set to WARN"* | A dedicated rule on those error codes |
| `sourceIPAddress.keyword:/.*amazonaws.com/` | A pipeline-flattened field, and redundant with `userIdentity.invokedBy` | `userIdentity.invokedBy` alone |
| MITRE `T1584` | Compromise Infrastructure is a **Resource Development** technique about compromising third-party infrastructure for use in operations. Overwriting your own function is not that | `T1525 — Implant Internal Image`, matching the kit's reference example for this technique |

The event-name handling is **correct** and worth recording: `/UpdateFunctionCode.*/` matches
`UpdateFunctionCode20150331v2`, which is what CloudTrail emits. Two sibling rules in the same pack
match `AddPermission` without the suffix and therefore cannot fire — the suffix was known here and
dropped there.

**Recommended detection — every identity type, and the rejections a success filter discards.**

```yaml
# Lambda function code overwritten (T1525)
#
# THE RULE MATCHES `userIdentity.type:"IAMUser"` ONLY, WHICH EXCLUDES ALMOST EVERY MODERN PRINCIPAL.
# SSO users, federated identities, EC2 instance roles, Lambda execution roles, CI/CD roles and every
# cross-account path arrive as `AssumedRole`. A compromised role session — the normal shape of a
# cloud intrusion, and the shape a compromised deployment pipeline takes — overwrites the function's
# code without this rule firing once. Two of the four rules in the same pack carry this filter and
# two do not, so the pack is inconsistent with itself about who counts as a principal.
#
# RATED P4, FOR CERTAIN CODE EXECUTION UNDER THE FUNCTION'S ROLE.
# Unlike a configuration change, this replaces the deployment package: the new code IS the handler
# and it runs on every invocation, with the function's execution role. There is no second act
# required and no window in which to intervene.
#
# THE EVENT-NAME WILDCARD IS CORRECT AND WORTH RECORDING. CloudTrail emits
# `UpdateFunctionCode20150331v2`, and this rule's `/UpdateFunctionCode.*/` handles it. Two sibling
# rules in the same pack match `AddPermission` without the suffix and therefore cannot fire — the
# suffix was known here and dropped there.
#
# AND IT MAPS TO `T1584` — Compromise Infrastructure, a RESOURCE DEVELOPMENT technique about
# adversaries compromising third-party infrastructure to use in their own operations. Overwriting
# your own function's code is not that. All four rules in the pack carry it.
#
# WHAT THIS DIRECTORY DELIBERATELY DOES NOT REPEAT: the full treatment of the technique, its
# CodeSha256 drift baseline and its rollback procedure are the kit's worked example in
# `reference/PLAYBOOK.md`. The complementary blind spot is
# ../../lambda.defense-evasion.function-configuration-modified/ — a handler or layer change
# redirects execution while leaving CodeSha256 UNCHANGED, so a defender watching only the code hash
# and a defender watching only the configuration are each blind to the other half.
title: Lambda function code overwritten outside the deployment path
id: 7e40c2b8-15da-4f67-90b3-2c8517ae6d94
name: lambda_function_code_overwritten
status: experimental
description: >-
  UpdateFunctionCode succeeded from a principal that is not a recorded deployment identity. The
  deployment package is replaced, so the new code runs on every invocation under the function's
  execution role — certain code execution, with no second act needed. All identity types are
  matched, because AssumedRole is what a compromised pipeline or federated session looks like.
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html
  - https://attack.mitre.org/techniques/T1525/
tags:
  - attack.persistence
  - attack.t1525
logsource:
  product: aws
  service: cloudtrail
detection:
  # CloudTrail appends a date and version to Lambda event names — `UpdateFunctionCode20150331v2` is
  # the documented form. Match by PREFIX, never by equality.
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith: 'UpdateFunctionCode'
  success:
    errorCode: null
  service_invoked:
    userIdentity.invokedBy|exists: true
  # POPULATE BEFORE DEPLOYING with the roles that own Lambda deployment. This is the entire
  # discriminator — the call itself is what every deploy does.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not service_invoked and not known_provisioners
falsepositives:
  - >-
    A deployment role that is not on the allowlist. That is the list being incomplete rather than
    the rule being wrong, and completing it is the single thing that makes this rule usable.
level: high
---
title: Lambda code overwrite rejected by code signing
id: b93e510f-27c4-4a86-b0d1-e64837f2c50a
name: lambda_code_signing_rejected
status: experimental
description: >-
  An UpdateFunctionCode that failed code-signature validation. AWS returns
  CodeVerificationFailedException when the signature mismatches or has expired and the policy is set
  to ENFORCE, and InvalidCodeSignatureException when the signature fails the integrity check —
  which AWS notes blocks deployment "even if the code signing policy is set to WARN". Either is a
  control working, and an attempt is still an attempt. Any rule filtering on success discards this
  entirely.
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html
  - https://attack.mitre.org/techniques/T1525/
tags:
  - attack.persistence
  - attack.t1525
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith: 'UpdateFunctionCode'
  signing_errors:
    errorCode:
      - 'CodeVerificationFailedException'
      - 'InvalidCodeSignatureException'
      - 'CodeSigningConfigNotFoundException'
  condition: selection and signing_errors
falsepositives:
  - >-
    A genuine signing-pipeline misconfiguration, which produces the same errors. Worth reading every
    time, because the two are indistinguishable at the event and only one is benign.
level: high
---
title: Lambda code overwritten across multiple functions by one principal
id: 4a17d8e6-3b09-42c5-971f-8e05a3d1b7c2
status: experimental
description: >-
  One principal replaced the code of three or more functions within an hour. A single overwrite has
  a deployment reading; a sweep across functions does not, and it is the shape of an actor
  establishing execution broadly rather than a pipeline updating one service.
references:
  - https://attack.mitre.org/techniques/T1525/
tags:
  - attack.persistence
  - attack.t1525
correlation:
  type: value_count
  rules:
    - lambda_function_code_changed
  group-by:
    - userIdentity.arn
  timespan: 1h
  condition:
    gte: 3
    field: requestParameters.functionName
falsepositives:
  - >-
    A monorepo deployment updating several functions in one run, which is exactly this shape.
    Allowlist the pipeline role on the base rule rather than raising the threshold.
level: high
---
title: Lambda function code changed
id: 2d6f9a41-c058-4e73-b912-40ae7c56d183
name: lambda_function_code_changed
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful
  UpdateFunctionCode, including every ordinary deployment. Matched by prefix because CloudTrail
  appends a date and version to Lambda event names.
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html
tags:
  - attack.persistence
  - attack.t1525
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith: 'UpdateFunctionCode'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: tell you what the new code does. The package is not in the
event, and reading it requires `GetFunction`, whose pre-signed URL returns whatever is deployed now
— not what was deployed at the time.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> Lambda management events are **regional** and do not aggregate into `us-east-1` — run these per
> region, and note the version suffix on Lambda event names.

Run Query 1 first; it establishes whether the caller was a deployment identity, which is the whole
discriminator.

#### Query 1 — Reconstruct: who replaced the code, and were they a deployment identity

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in UpdateFunctionCode20150331v2 UpdateFunctionCode \
           UpdateFunctionConfiguration20150331v2 PublishVersion20150331; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      # Failures are NOT filtered out: code signing rejects an overwrite with
      # CodeVerificationFailedException or InvalidCodeSignatureException, and that refusal is the
      # control working — a better signal than the success it prevented.
      | (.errorCode // "OK") as $err
      # The identity TYPE is projected because the source rule required IAMUser. In most estates
      # every real deployment is AssumedRole, which means that rule has never fired.
      | (.userIdentity.type // "?") as $itype
      | "\(.eventTime)  \(.eventName)  \($err)  type=\($itype)  " +
        "fn=\(.requestParameters.functionName // "-")  by=\(.userIdentity.arn)  ip=\(.sourceIPAddress)"'
done | sort
```

Count the `type=` values. If they are all `AssumedRole`, the source rule's `IAMUser` filter means it
has never fired here — which decides whether this is a detection gap or an incident, and it is worth
settling before anything else.

#### Query 2 — Compare the deployed package against the build baseline

```bash
FUNCTION="${1:?function name from Query 1}"
REGION="${AWS_REGION:-us-east-1}"
EXPECT_SHA="${2:?the CodeSha256 your build pipeline recorded for the intended release}"

aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --output json 2>/dev/null \
| jq -r --arg e "$EXPECT_SHA" '
    if .CodeSha256 == $e then "[OK] CodeSha256 matches the build baseline"
    else "[FAIL] CodeSha256 is \(.CodeSha256), expected \($e)" end,
    "  LastModified: \(.LastModified)",
    "  Handler:      \(.Handler)",
    "  ConfigSha256: \(.ConfigSha256)"'

echo
echo "[!] Compare ConfigSha256 as well. A handler or layer change redirects execution WITHOUT"
echo "    moving CodeSha256 — see ../lambda.defense-evasion.function-configuration-modified/."
echo "    A clean code hash is not a clean function."
```

The baseline must come from the **build pipeline**, not from AWS. A hash read from AWS after the
fact tells you what is deployed, which is the thing under suspicion.

#### Query 3 — Is a clean version available to roll back to

```bash
FUNCTION="${1:?function name}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== Published versions (immutable) ==="
aws lambda list-versions-by-function --function-name "$FUNCTION" --region "$REGION" \
  --query 'Versions[].[Version,CodeSha256,LastModified]' --output text 2>/dev/null | sort -V

echo
echo "=== Aliases and what they point at ==="
aws lambda list-aliases --function-name "$FUNCTION" --region "$REGION" \
  --query 'Aliases[].[Name,FunctionVersion]' --output text 2>/dev/null | sed 's/^/  /'

echo
echo "[!] Only \$LATEST is mutable. If the list above shows nothing but \$LATEST, the previous"
echo "    package no longer exists anywhere in AWS and recovery means redeploying from source."
```

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

# For an assumed role the CloudTrail username is the SESSION name: the second slash-separated
# segment after `assumed-role/`, not the role name and not the last segment.
case "$PRINCIPAL" in
  *:assumed-role/*) LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $2}')" ;;
  *)                LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')" ;;
esac

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$LOOKUP" \
  --start-time "$START" --region "$REGION" --max-results 200 \
  --query 'Events[].[EventTime,EventName,EventSource]' --output text 2>/dev/null | sort
```

If the principal is a deployment role, the question moves upstream: what triggered that pipeline run,
and does a corresponding commit and approval exist? A compromised pipeline produces a legitimate-
looking principal doing a legitimate-looking thing.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The function is executing attacker code on every invocation right now. Roll back first; investigate
the package afterwards.

**Break-glass — use the break-glass credential, not the on-call's own.** If the function is
invoked by `$LATEST` and Query 3 shows no published versions, there is nothing to roll back to. In
that case disable the trigger rather than leaving the code running while a redeploy is prepared.

#### Step 1 — Roll back to a published version, if one exists

```bash
FUNCTION="${1:?function name}"
REGION="${AWS_REGION:-us-east-1}"
GOOD_VERSION="${2:?the last known-good version number from Query 3}"
ALIAS="${3:-live}"

# A published version is immutable, so repointing the alias is a clean rollback that does not
# depend on redeploying anything.
if aws lambda update-alias --function-name "$FUNCTION" --name "$ALIAS" \
     --function-version "$GOOD_VERSION" --region "$REGION" >/dev/null 2>&1; then
  echo "[OK] alias $ALIAS now points at version $GOOD_VERSION"
  aws lambda get-alias --function-name "$FUNCTION" --name "$ALIAS" --region "$REGION" \
    --query '{alias:Name,version:FunctionVersion}' --output json
else
  echo "[FAIL] alias $ALIAS not found or update rejected."
  echo "       If callers invoke \$LATEST directly, an alias repoint does not help them —"
  echo "       Step 2 is the containment path instead."
fi
```

#### Step 2 — Where there is no version to return to, stop the function running

```bash
FUNCTION="${1:?function name}"
REGION="${AWS_REGION:-us-east-1}"

# Reserved concurrency of 0 stops all invocations without deleting anything, which preserves the
# malicious package as evidence. It is a blunt instrument and it WILL break callers.
echo "[!] This stops the function entirely. Confirm the outage is acceptable before proceeding."
read -r -p "Set reserved concurrency to 0 on $FUNCTION? [y/N] " ANS
if [ "$ANS" = "y" ]; then
  aws lambda put-function-concurrency --function-name "$FUNCTION" \
    --reserved-concurrent-executions 0 --region "$REGION" \
    && echo "[OK] $FUNCTION will not execute until concurrency is restored"
fi

echo
echo "=== Event source mappings that would keep invoking it ==="
aws lambda list-event-source-mappings --function-name "$FUNCTION" --region "$REGION" \
  --query 'EventSourceMappings[].[UUID,EventSourceArn,State]' --output text 2>/dev/null | sed 's/^/  /'
echo "[!] Concurrency 0 stops execution; it does not disable these mappings, which will keep"
echo "    retrying and may fill a dead-letter queue."
```

#### Step 3 — Preserve the package before it is overwritten again

```bash
FUNCTION="${1:?function name}"
REGION="${AWS_REGION:-us-east-1}"

# GetFunction returns a pre-signed URL for the CURRENT package. It expires in minutes and it will
# return the CLEAN package once you have rolled back — so capture before Step 1 where possible,
# and from the specific version otherwise.
URL="$(aws lambda get-function --function-name "$FUNCTION" --region "$REGION" \
        --query 'Code.Location' --output text 2>/dev/null)"
if [ -n "$URL" ] && [ "$URL" != "None" ]; then
  curl -s -o "./evidence-${FUNCTION}-package.zip" "$URL" \
    && echo "[OK] package saved to ./evidence-${FUNCTION}-package.zip" \
    && shasum -a 256 "./evidence-${FUNCTION}-package.zip" 2>/dev/null
else
  echo "[FAIL] could not obtain a download URL for $FUNCTION"
fi
```

The ordering caveat is the point of this step: once Step 1 has rolled back, `GetFunction` returns
the *clean* package and the evidence is gone. Where the rollback has already happened, the malicious
package exists only if it was published as a version.

#### Step 4 — Contain the principal, and question the pipeline

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"

case "$PRINCIPAL" in
  *:user/*)
    U="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')"
    aws iam list-access-keys --user-name "$U" --query 'AccessKeyMetadata[].AccessKeyId' \
      --output text 2>/dev/null | tr '\t' '\n' | while read -r K; do
        [ -z "$K" ] && continue
        aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive \
          && echo "[OK] key $K deactivated"
      done
    ;;
  *:assumed-role/*)
    # Role name is the FIRST segment after `assumed-role/`; the second is the session name.
    R="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $1}')"
    echo "[!] assumed role: $R — existing session credentials remain valid until expiry."
    echo "    Save as revoke.json and attach with put-role-policy:"
    cat <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"}}}]}
JSON
    echo "[!] If $R is a DEPLOYMENT role, revoking it stops all releases — and the compromise is"
    echo "    probably upstream in the pipeline rather than in AWS. Treat the pipeline as in scope."
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

---

## 4. Eradication

### Remove Attacker Access

#### Establish what the code did, from the role's activity

The package itself is one source; the other is what the function actually did while running it.
Every action it took appears in CloudTrail under the **execution role's** assumed-role sessions, not
under the principal that deployed the code. Query that role over the window between the overwrite
and the rollback — it is the difference between "attacker code ran" and "attacker code did X".

#### Enable code signing with an ENFORCE policy

This converts the technique from a success into a `CodeVerificationFailedException`. It is the one
control that makes the overwrite fail rather than be detected, and the refused attempt is a better
signal than the success it prevents.

#### Publish versions and invoke by alias

Rollback is a one-call alias repoint where versions exist and a redeploy-from-source where they do
not. That difference is decided long before the incident.

#### Deny code changes outside the deployment path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyLambdaCodeChangesOutsideDeployment",
  "Effect": "Deny",
  "Action": ["lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
             "lambda:PublishVersion", "lambda:UpdateAlias"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourDeploymentRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline. Note this does not help when the **deployment role itself** is the
compromised principal, which is the most likely case here; the control for that is code signing and
the pipeline's own integrity.

---

## 5. Recovery

### Restore Clean State

#### Verify the deployed hash matches the build baseline

```bash
FUNCTION="${1:?function name}"
REGION="${AWS_REGION:-us-east-1}"
EXPECT_SHA="${2:?CodeSha256 from the build pipeline}"

CUR="$(aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
        --query 'CodeSha256' --output text 2>/dev/null)"
if [ "$CUR" = "$EXPECT_SHA" ]; then
  echo "[OK] $FUNCTION CodeSha256 matches the build baseline"
else
  echo "[FAIL] $FUNCTION CodeSha256 is $CUR, expected $EXPECT_SHA"
fi
```

#### Verify the configuration was not also changed

```bash
FUNCTION="${1:?function name}"
REGION="${AWS_REGION:-us-east-1}"
EXPECT_HANDLER="${2:?expected handler}"

aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --output json 2>/dev/null \
| jq -r --arg h "$EXPECT_HANDLER" '
    (if .Handler == $h then "[OK] handler unchanged: \(.Handler)"
     else "[FAIL] handler is \(.Handler), expected \($h)" end),
    (if ((.Layers // []) | length) == 0 then "[OK] no layers attached"
     else "[FAIL] \((.Layers | length)) layer(s) attached: \([.Layers[].Arn] | join(", "))" end)'
```

A restored code hash with a changed handler is not recovery — the package is clean and a different
method inside it is running. That is the sibling technique and it leaves this check's first line
green.

#### Confirm concurrency and triggers were restored

```bash
FUNCTION="${1:?function name}"
REGION="${AWS_REGION:-us-east-1}"

C="$(aws lambda get-function-concurrency --function-name "$FUNCTION" --region "$REGION" \
      --query 'ReservedConcurrentExecutions' --output text 2>/dev/null)"
case "$C" in
  0)    echo "[FAIL] reserved concurrency is still 0 — the function cannot run" ;;
  None|"") echo "[OK] no reserved concurrency limit" ;;
  *)    echo "[OK] reserved concurrency: $C" ;;
esac

aws lambda list-event-source-mappings --function-name "$FUNCTION" --region "$REGION" \
  --query 'EventSourceMappings[].[UUID,State]' --output text 2>/dev/null \
| while IFS=$'\t' read -r U S; do
    [ -z "$U" ] && continue
    [ "$S" = "Enabled" ] && echo "[OK] mapping $U enabled" || echo "[FAIL] mapping $U is $S"
  done
```

#### Confirm the corrected detection fires

```bash
FUNCTION="${1:?a NON-PRODUCTION function name}"
REGION="${AWS_REGION:-us-east-1}"

# Redeploy the function's OWN current package. The code is byte-identical, so nothing changes
# behaviourally, but the event is emitted — and it must fire from an AssumedRole session, which is
# exactly the identity type the source rule excluded.
URL="$(aws lambda get-function --function-name "$FUNCTION" --region "$REGION" \
        --query 'Code.Location' --output text 2>/dev/null)"
curl -s -o /tmp/roundtrip.zip "$URL" && \
aws lambda update-function-code --function-name "$FUNCTION" --region "$REGION" \
  --zip-file fileb:///tmp/roundtrip.zip >/dev/null 2>&1 \
  && echo "[OK] identical package redeployed — expect the HIGH rule within 15 min" \
  || echo "[!] redeploy rejected — code signing may be enforcing, which is itself a pass"

rm -f /tmp/roundtrip.zip
aws sts get-caller-identity --query 'Arn' --output text
echo "[!] If the ARN above contains ':assumed-role/' and no alert arrives, the identity-type filter"
echo "    is still in place and the rule is not covering the majority of your principals."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| What identity type made the call? | If `AssumedRole`, the source rule would not have fired, and the coverage gap is the finding. |
| Was the caller a deployment role? | If yes, the compromise is upstream in the pipeline and AWS containment alone does not address it. |
| Were versions published? | Decides whether rollback is an alias repoint or a redeploy from source. |
| Was the package preserved before rollback? | `GetFunction` returns the current package, so rolling back first destroys the evidence. |
| Was code signing enforced? | It would have turned this into a refused attempt rather than a successful overwrite. |
| Did the configuration change too? | A clean code hash with a changed handler is not a clean function. |

### Recommended Guardrails

**Cover every identity type.** This is the single highest-value change. A rule scoped to `IAMUser`
misses SSO, federation, instance roles and the CI/CD role — and the CI/CD role is the most likely
principal for this call.

**Enable code signing with `ENFORCE`.** It makes the overwrite fail rather than be noticed, and the
rejection is a cleaner signal than the success.

**Publish versions and invoke by alias.** Rollback becomes one call, and `$LATEST`-only functions
have no recoverable previous state at all.

**Baseline `CodeSha256` from the build pipeline, not from AWS.** A hash read from AWS after the fact
describes what is deployed, which is the thing in question.

**Watch the configuration alongside the code.** The two techniques are complementary and each is
invisible to the other's baseline.

### Technique Reference

**T1525 — Implant Internal Image.** Verified live at https://attack.mitre.org/techniques/T1525/ on
2026-08-30. This matches the mapping the kit's reference example uses for the same technique, and
`reference/PLAYBOOK.md` carries the fuller treatment of it.

The source rule maps to **`T1584 — Compromise Infrastructure`**, a Resource Development technique
about adversaries compromising third-party infrastructure to use in their own operations.
Overwriting your own function's code is not that, and all four rules in the original pack carry it.

AWS references relied on throughout, all verified 2026-08-30:

- `UpdateFunctionCode` — the code-signing error codes, including that an integrity failure blocks
  deployment even under a `WARN` policy:
  https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html
- `UpdateFunctionConfiguration` — for the complementary technique and the `ConfigSha256` primitive:
  https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.html

### Residual Risk

**A compromised deployment role defeats the allowlist entirely.** The discriminator here is "was the
caller a deployment identity", and if the answer is yes because the pipeline is compromised, this
detection is silent by design. Code signing and pipeline integrity are the controls for that case;
nothing in CloudTrail distinguishes a legitimate release from a malicious one made by the same role.

**Evidence is destroyed by the rollback.** `GetFunction` returns the current package, so an
alias repoint or a redeploy replaces the thing you needed to capture. Preserving it first is a step
that competes directly with stopping the code from running, and the right order depends on the blast
radius.

**`$LATEST`-only functions have no recoverable previous state.** The overwritten package is gone from
AWS the moment it is replaced. Recovery is a redeploy from source, and if the source is also
suspect there is no clean starting point at all.

**The code hash is only half the integrity story.** A function whose `CodeSha256` matches its
baseline can still be executing different code, through a changed handler or an attached layer. That
is `../lambda.defense-evasion.function-configuration-modified/`, and a defender checking only this
playbook's hash will report the function clean.
