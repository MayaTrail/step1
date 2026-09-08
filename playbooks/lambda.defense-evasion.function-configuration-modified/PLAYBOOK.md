# IR Playbook: Lambda Function Configuration Modified — execution redirected via `UpdateFunctionConfiguration`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence evasion and privilege escalation — a function's handler, layers, execution role, network placement or encryption key is changed, redirecting what runs or what it can reach, without modifying the deployment package |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High for a handler or layer change and for an execution-role change; medium for network or key changes. The source rule rates all of it P4 with no content check. |
| MITRE Tactics | Defense Evasion; Privilege Escalation |
| MITRE Techniques | T1578.005; T1525; T1098.003 |
| Services in Scope | Lambda, IAM, KMS, VPC, CloudTrail |

**What the technique does:** the actor calls `UpdateFunctionConfiguration`. That single call changes
twenty different settings, and two of them redirect execution **without touching code**:

| Field | Effect |
|---|---|
| `Handler` | A different method already inside the package now runs |
| `Layers` | Code from a layer — possibly in **another account** — loads with the function |
| `Role` | The function keeps its code and gains a different set of permissions |
| `VpcConfig` | What the function can reach, and which egress controls apply, both change |
| `KMSKeyArn` | Who can read the environment variables and SnapStart snapshots changes |

Because the package is untouched, **`CodeSha256` is unchanged** — so code signing, package-hash
baselines and code-drift detection all still pass.

**Why the usual reflexes miss it.** The first is to baseline on the code hash, which does not move
for any of this; AWS returns `ConfigSha256` in the same response for exactly this reason. The second
is to alert on the call without reading which field changed, which is what the source rule does — a
memory bump and an execution-role swap arrive identically at P4. The third is to look for an IAM
event after a role change: none exists, because no IAM object was modified. The fourth is to expect
environment variable values in the log; AWS states they are *"omitted from AWS CloudTrail logs."*

**Detection thesis:** rate on which field changed, baseline on `ConfigSha256` rather than
`CodeSha256`, and treat a layer ARN from an unrecognised account as the highest-signal shape.

**Adjacent playbooks.** Changing the package itself is
`../lambda.persistence.function-code-overwritten/`. Granting invoke permission is
`../lambda.persistence.resource-policy-backdoor/`. The kit's worked example for code overwrite is
`reference/PLAYBOOK.md`, and its `CodeSha256` drift check is precisely what this technique evades.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. Lambda management events do **not** aggregate into
`us-east-1` — they are recorded regionally, so a single-region trail covers only its own region's
functions.

**A `ConfigSha256` baseline per function, not just `CodeSha256`.** This is the item that decides
whether the technique is detectable at all. `GetFunctionConfiguration` returns both hashes; a drift
check on the code hash alone reports clean through every field in the table above.

The list of AWS accounts whose Lambda layers are legitimately used here. A layer ARN embeds its
owning account, and that number is the only signal that injected code came from outside.

**Alerting (must be pre-configured)**

- **`UpdateFunctionConfiguration` attaching a layer whose ARN belongs to an account not on the recognised list → P0**
- **`UpdateFunctionConfiguration` changing `Handler` — a different method in the same package now runs, with `CodeSha256` unchanged → P0**
- **Configuration changed across three or more functions by one principal within an hour → P0**

**Response Tooling**

An IAM principal that can call `lambda get-function-configuration`,
`update-function-configuration`, `list-layer-versions` and `get-layer-version-policy` outside the
change pipeline, in every region holding functions.

The ability to compare two IAM roles' effective permissions. A role change is the one field here
whose severity cannot be judged from the Lambda event at all.

**Known IOC Baselines**

The roles that own Lambda deployment, populating `known_provisioners`. Infrastructure applies call
this API constantly.

The expected handler string per function. It is a short, stable value and a change to it is
otherwise indistinguishable from any other configuration edit.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | A layer attached whose ARN belongs to an account not on the recognised list — code you cannot read, loading with the function | CloudTrail | T1525 |
| P0 | `Handler` changed — a different method inside the same package now runs, and `CodeSha256` is unchanged | CloudTrail | T1578.005 |
| P0 | Configuration changed across three or more functions by one principal within an hour | Correlation rule | T1578.005 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `Role` changed by a principal not on the provisioner list — permissions change with no IAM event at all | CloudTrail | T1098.003 |
| P2 | `Layers` changed to an account-owned layer, or `KMSKeyArn` changed | CloudTrail | T1578.005 |
| P2 | `VpcConfig` removed — the function returns to Lambda's own network, where VPC egress controls do not apply | CloudTrail | T1578.005 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| No content check on a call that changes twenty settings | `Handler`, `Layers`, `Role`, `Environment`, `VpcConfig`, `KMSKeyArn`, `Runtime`, `Timeout`, `MemorySize`. A memory bump and an execution-role swap arrive as the same alert | Four rules split by field, rated by effect |
| Rated P4 | Two of those fields redirect execution while leaving `CodeSha256` unchanged, so every code-integrity control still passes. P4 is below the threshold at which anyone looks | High for handler, layers and role; medium for network and key |
| It had no detection at all in the directory that carried it | The rule sat in `_source/` of a resource-policy playbook whose five Sigma documents all address `AddPermission`. Scope looked covered and was not | Its own directory, with its own triplet |
| `userIdentity.type:"IAMUser"` on sibling rules in the same pack | Excludes `AssumedRole`, which is SSO, federation and every role session — the majority of modern principals. This rule does not carry that filter, but two of its siblings do | All identity types; the `invokedBy` filter is the correct way to exclude AWS service calls |
| `sourceIPAddress.keyword:/.*amazonaws.com/` | A pipeline-flattened field, and redundant with `userIdentity.invokedBy` which the same rule could have used | `userIdentity.invokedBy` alone |
| MITRE `T1584` | Compromise Infrastructure is a **Resource Development** technique about compromising third-party infrastructure for use in operations. Modifying your own function is not that, and all four rules in the pack carry it | `T1578.005` primary, `T1525` on handler and layers, `T1098.003` on the role change |

**Recommended detection — split by the field that changed, because the fields are not alike.**

```yaml
# Lambda function configuration modified (T1578.005)
#
# THE SOURCE RULE HAS NO CONTENT CHECK ON A CALL THAT CHANGES TWENTY DIFFERENT THINGS, AND RATES IT
# P4. `UpdateFunctionConfiguration` accepts Handler, Layers, Role, Environment, VpcConfig, KMSKeyArn,
# Runtime, Timeout, MemorySize and more. A memory bump and an execution-role swap arrive identically.
#
# TWO OF THOSE FIELDS HIJACK EXECUTION WITHOUT TOUCHING CODE, WHICH IS THE POINT.
#   Handler — "The name of the method within your code that Lambda calls to run your function."
#             Repointing it runs a DIFFERENT function already inside the package.
#   Layers  — "A list of function layers to add to the function's execution environment."
#             A layer is code, its ARN may belong to ANOTHER ACCOUNT, and it loads with the function.
# Neither changes the deployment package, so `CodeSha256` is unchanged and every code-integrity
# check, code-signing policy and package-hash baseline still passes. A detection built on code
# hashes — including the one in reference/PLAYBOOK.md — is structurally blind to both.
#
# THE ANSWER IS `ConfigSha256`, WHICH IS THE CONFIGURATION'S OWN HASH.
# GetFunctionConfiguration returns it alongside CodeSha256. It is the drift primitive for everything
# in this file, and §2 of ../PLAYBOOK.md baselines against it rather than against the code hash.
#
# ENVIRONMENT VARIABLE VALUES ARE NOT IN CLOUDTRAIL. AWS on the response element: "The function's
# environment variables. Omitted from AWS CloudTrail logs." So a rule cannot read what was set, and
# a responder cannot recover it from the event — only GetFunctionConfiguration shows the current
# values, and only if the caller can read them.
#
# AND THE SOURCE RULE MAPS TO `T1584` — Compromise Infrastructure, a RESOURCE DEVELOPMENT technique
# about adversaries compromising third-party infrastructure to use in their own operations. Modifying
# your own Lambda is not that. All four rules in the original pack carry it.
title: Lambda execution hijacked by handler or layer change
id: 5d92c1a7-38e0-4b64-9f27-c081a3e57b4d
name: lambda_execution_hijacked_by_config
status: experimental
description: >-
  UpdateFunctionConfiguration changed the Handler or the Layers. Both redirect what actually runs
  without modifying the deployment package, so CodeSha256 is unchanged and code-signing and
  package-hash controls all still pass. A layer ARN can belong to another account, which makes the
  injected code something the function owner cannot see the contents of.
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.html
  - https://attack.mitre.org/techniques/T1578/005/
  - https://attack.mitre.org/techniques/T1525/
tags:
  - attack.defense-evasion
  - attack.persistence
  - attack.t1578.005
  - attack.t1525
logsource:
  product: aws
  service: cloudtrail
detection:
  # CloudTrail appends a date and version to Lambda event names — the documented form is
  # `UpdateFunctionConfiguration20150331v2`. Match by PREFIX, never by equality.
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith: 'UpdateFunctionConfiguration'
  success:
    errorCode: null
  hijack_fields:
    requestParameters|contains:
      - '"handler"'
      - '"layers"'
  service_invoked:
    userIdentity.invokedBy|exists: true
  condition: selection and success and hijack_fields and not service_invoked
falsepositives:
  - >-
    A deployment that legitimately changes the handler or adds a layer. Common in an IaC estate, and
    the distinguishing question is whether the layer ARN belongs to an account you own — which the
    query surfaces and the rule cannot.
level: high
---
title: Lambda execution role changed
id: c7148ea3-60bf-4d29-85a0-9e6b02f7d158
name: lambda_execution_role_changed
status: experimental
description: >-
  UpdateFunctionConfiguration changed the function's Role. The function keeps running the same code
  and gains a different set of permissions, so this is privilege escalation by way of the compute
  layer rather than the identity layer — and it will not appear in any IAM attach or policy event,
  because no IAM object changed.
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.html
  - https://attack.mitre.org/techniques/T1578/005/
  - https://attack.mitre.org/techniques/T1098/003/
tags:
  - attack.defense-evasion
  - attack.privilege-escalation
  - attack.t1578.005
  - attack.t1098.003
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith: 'UpdateFunctionConfiguration'
  success:
    errorCode: null
  role_changed:
    requestParameters|contains: '"role"'
  service_invoked:
    userIdentity.invokedBy|exists: true
  # POPULATE BEFORE DEPLOYING with the roles that own Lambda deployment.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and role_changed and not service_invoked and not known_provisioners
falsepositives:
  - >-
    A deployment moving a function to a new execution role, which is a normal refactor. The check
    that matters is whether the new role is more permissive than the old one, and that is an IAM
    question the event cannot answer.
level: high
---
title: Lambda network placement or encryption key changed
id: 0e63b48f-a951-4c72-b3d6-72f0158ae9c4
name: lambda_network_or_key_changed
status: experimental
description: >-
  UpdateFunctionConfiguration changed VpcConfig or KMSKeyArn. AWS on VpcConfig: "When you connect a
  function to a VPC, it can access resources and the internet only through that VPC" — so changing
  it changes what the function can reach and which egress controls apply to it. KMSKeyArn encrypts
  the environment variables and SnapStart snapshots, so changing it changes who can read them.
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.html
  - https://attack.mitre.org/techniques/T1578/005/
tags:
  - attack.defense-evasion
  - attack.t1578.005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith: 'UpdateFunctionConfiguration'
  success:
    errorCode: null
  network_or_key:
    requestParameters|contains:
      - '"vpcConfig"'
      - '"kmsKeyArn"'
  service_invoked:
    userIdentity.invokedBy|exists: true
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and network_or_key and not service_invoked and not known_provisioners
falsepositives:
  - >-
    A function being moved into or out of a VPC as part of a normal architecture change. Removing a
    function FROM a VPC is the direction worth reading, because it returns the function to Lambda's
    own network where VPC egress controls do not apply.
level: medium
---
title: Lambda function configuration changed
id: a2f507bc-4e13-49d8-b6c0-31da85e7620f
name: lambda_function_config_changed
status: experimental
description: >-
  Base rule — correlation component and change accounting, never for direct alerting. Any successful
  UpdateFunctionConfiguration. Matched by prefix because CloudTrail appends a date and version to
  Lambda event names.
references:
  - https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.html
tags:
  - attack.defense-evasion
  - attack.t1578.005
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'lambda.amazonaws.com'
    eventName|startswith: 'UpdateFunctionConfiguration'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
title: Lambda configuration changed across multiple functions by one principal
id: 831b0d6e-97c5-4a20-8f14-e6350cb7a2d9
status: experimental
description: >-
  One principal changed the configuration of three or more functions within an hour. A single
  configuration change has many ordinary readings; a sweep across functions does not, and it is the
  shape that matters when a layer is being attached broadly rather than a single function being
  tuned.
references:
  - https://attack.mitre.org/techniques/T1578/005/
tags:
  - attack.defense-evasion
  - attack.t1578.005
correlation:
  type: value_count
  rules:
    - lambda_function_config_changed
  group-by:
    - userIdentity.arn
  timespan: 1h
  condition:
    gte: 3
    field: requestParameters.functionName
falsepositives:
  - >-
    A deployment updating a fleet of functions in one run. Allowlist the pipeline role on the base
    rule rather than raising the threshold.
level: high
```

What this set structurally cannot do: show what an environment variable was set to. AWS omits those
values from CloudTrail entirely, so the rules can see that `Environment` was in the request and
nothing more.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> Lambda management events are **regional** and do not aggregate into `us-east-1` — run these per
> region, and note that CloudTrail appends a version suffix to Lambda event names.

Run Query 1 first; it establishes which field changed, which is the whole triage.

#### Query 1 — Reconstruct: which setting was actually changed

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

# The documented event name is UpdateFunctionConfiguration20150331v2 — lookup-events matches the
# exact string, so query the versioned form as well as the bare one.
for EVT in UpdateFunctionConfiguration20150331v2 UpdateFunctionConfiguration \
           UpdateFunctionCode20150331v2 PublishVersion20150331; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | (.requestParameters | tostring) as $rp
      # Handler and Layers redirect execution WITHOUT changing the package, so CodeSha256 does not
      # move and no code-integrity control fires. That is the pair worth reading first.
      | [ (if ($rp | test("\"handler\"")) then "HANDLER" else empty end),
          (if ($rp | test("\"layers\"")) then "LAYERS" else empty end),
          (if ($rp | test("\"role\"")) then "ROLE" else empty end),
          (if ($rp | test("\"vpcConfig\"")) then "vpc" else empty end),
          (if ($rp | test("\"kmsKeyArn\"")) then "kms" else empty end),
          (if ($rp | test("\"environment\"")) then "env(values-not-logged)" else empty end),
          (if ($rp | test("\"timeout\"|\"memorySize\"")) then "resources" else empty end) ] as $fields
      | "\(.eventTime)  \(.eventName)  fn=\(.requestParameters.functionName // "-")  " +
        "changed=[\($fields | join(","))]  by=\(.userIdentity.arn)  ip=\(.sourceIPAddress)"'
done | sort
```

A row whose `changed=` list is only `resources` is a tuning change. One containing `HANDLER` or
`LAYERS` redirected execution, and the deployment package is byte-identical throughout — so nothing
that watches code will have noticed.

#### Query 2 — Compare against the configuration hash, not the code hash

```bash
FUNCTION="${1:?function name from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --output json 2>/dev/null \
| jq -r '"  CodeSha256:   \(.CodeSha256)",
         "  ConfigSha256: \(.ConfigSha256)",
         "  Handler:      \(.Handler)",
         "  Role:         \(.Role)",
         "  Runtime:      \(.Runtime)",
         "  Layers:       \([.Layers[]?.Arn] | join(", ") // "none")",
         "  VpcConfig:    \(.VpcConfig.VpcId // "not in a VPC")",
         "  KMSKeyArn:    \(.KMSKeyArn // "AWS-owned or AWS-managed key")"'

echo
echo "[!] Compare ConfigSha256 against the recorded baseline — NOT CodeSha256."
echo "    A handler or layer change leaves CodeSha256 identical, so a code-hash drift check reports"
echo "    clean through this entire technique."
```

#### Query 3 — Whose layer is it

```bash
FUNCTION="${1:?function name}"
REGION="${AWS_REGION:-us-east-1}"

aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --query 'Layers[].Arn' --output text 2>/dev/null | tr '\t' '\n' | while read -r ARN; do
    [ -z "$ARN" ] && continue
    # A layer ARN embeds the owning 12-digit account. A layer from an account you do not own is
    # code running in your function whose contents you cannot read.
    ACCT="$(printf '%s' "$ARN" | awk -F: '{print $5}')"
    echo "  layer=$ARN  owner=$ACCT"
    aws lambda get-layer-version-policy --layer-name "$ARN" --region "$REGION" \
      --output json 2>/dev/null | jq -r '"    shared-by-policy: \(.Policy | fromjson | .Statement[].Principal)"' \
      || echo "    (no layer version policy readable — the layer is not shared with you explicitly)"
  done

echo
echo "[!] You cannot download and inspect a layer you do not own. If the owner account is"
echo "    unrecognised, treat the layer as untrusted code and remove it rather than analysing it."
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

Look for `PublishLayerVersion` shortly before the configuration change: an actor who could not reach
an existing layer will have created their own, and that event names the layer they then attached.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore the configuration first — it is one call and it stops the modified function from running
again on the next invocation. Note that in-flight execution environments may persist briefly.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 3 shows a layer
owned by an unrecognised account, the function has been executing third-party code on every
invocation since the change. Remove the layer before investigating what it does — you cannot read it
anyway.

#### Step 1 — Restore the configuration

```bash
FUNCTION="${1:?function name}"
REGION="${AWS_REGION:-us-east-1}"
GOOD_HANDLER="${2:?the expected handler from the baseline}"
GOOD_ROLE="${3:?the expected execution role ARN from the baseline}"

# Preserve the current configuration before overwriting it — it is the evidence, and
# get-function-configuration will not return the previous values afterwards.
aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --output json > "./evidence-${FUNCTION}-config.json" 2>/dev/null \
  && echo "[OK] configuration preserved at ./evidence-${FUNCTION}-config.json"

# Layers are REPLACED wholesale by this call, so passing an empty list removes all of them. Pass the
# baseline's layer ARNs instead if the function legitimately uses any.
aws lambda update-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --handler "$GOOD_HANDLER" --role "$GOOD_ROLE" --layers \
  && echo "[OK] handler and role restored, all layers removed from $FUNCTION" \
  || echo "[FAIL] update rejected — check the role ARN and that the function is not a published version"
```

Passing `--layers` with no values is deliberate and is the safe default here: it removes every layer,
including any the function legitimately needed. Re-add the known-good ones from the baseline
afterwards, rather than trying to preserve a list that may already contain the attacker's.

#### Step 2 — Confirm the configuration hash returned to its baseline

```bash
FUNCTION="${1:?function name}"
REGION="${AWS_REGION:-us-east-1}"
EXPECT_CONFIG_SHA="${2:?the ConfigSha256 from the baseline}"

CUR="$(aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
        --query 'ConfigSha256' --output text 2>/dev/null)"
if [ "$CUR" = "$EXPECT_CONFIG_SHA" ]; then
  echo "[OK] ConfigSha256 matches the baseline"
else
  echo "[FAIL] ConfigSha256 is $CUR, expected $EXPECT_CONFIG_SHA — something else also changed"
fi
```

A mismatch here after restoring the handler, role and layers means a field you have not looked at
also changed — environment variables and `KMSKeyArn` are the usual candidates, and the first of
those is not recoverable from the event.

#### Step 3 — Contain the principal

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
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

#### Step 4 — Establish what the function did while modified

The function ran under the changed configuration on every invocation between the modification and
Step 1. Two questions follow, and they use different evidence:

- **What did it do with its permissions?** If the `Role` changed, the function's CloudTrail activity
  appears under the *new* role's assumed-role sessions, not the old one. Query the new role name.
- **What did it reach on the network?** If a layer was injected, GuardDuty Lambda Protection findings
  (`Backdoor:Lambda/C&CActivity.B`, `Trojan:Lambda/DropPoint`) are the independent signal, and they
  fire on traffic rather than on the configuration.

```bash
NEW_ROLE="${1:?the role the function was changed to, from Query 1}"
START="${2:?modification timestamp}"
END="${3:?restoration timestamp}"
REGION="${AWS_REGION:-us-east-1}"

R="$(printf '%s' "$NEW_ROLE" | awk -F'/' '{print $NF}')"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$R" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --query 'Events[].[EventTime,EventName,EventSource]' --output text 2>/dev/null | sort
```

---

## 4. Eradication

### Remove Attacker Access

#### Baseline `ConfigSha256`, not `CodeSha256`

This is the eradication step that changes whether the technique is detectable next time. Every
code-integrity control in the estate — signing, package hashes, the drift check in
`reference/PLAYBOOK.md` — reports clean through a handler or layer change. `ConfigSha256` is
returned by the same call and moves for all of them.

#### Publish versions and invoke by version

AWS: *"These settings can vary between versions of a function and are locked when you publish a
version. You can't modify the configuration of a published version, only the unpublished version."*

A function invoked by published version or by an alias pointing at one cannot be reconfigured out
from under its callers. That removes the technique rather than detecting it, and it is the durable
fix here.

#### Restrict which layer accounts are usable

There is no AWS control that limits layer ARNs to your own accounts, so this is an SCP and an
inventory question. Enumerate the layers in use across every function and confirm each owning account
— a layer from an account nobody recognises is the finding, and it will not appear in any alert
unless the list exists.

#### Deny configuration changes outside the deployment path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyLambdaReconfiguration",
  "Effect": "Deny",
  "Action": ["lambda:UpdateFunctionConfiguration", "lambda:UpdateFunctionCode",
             "lambda:AddPermission", "lambda:AddLayerVersionPermission"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourDeploymentRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline. Test in a non-production OU first.

---

## 5. Recovery

### Restore Clean State

#### Verify every function's configuration against its baseline

```bash
REGION="${AWS_REGION:-us-east-1}"
BASELINE="${1:?path to a file of 'functionName ConfigSha256' lines}"

FAIL=0
while read -r FN EXPECT; do
  [ -z "$FN" ] && continue
  CUR="$(aws lambda get-function-configuration --function-name "$FN" --region "$REGION" \
          --query 'ConfigSha256' --output text 2>/dev/null)"
  if [ "$CUR" = "$EXPECT" ]; then
    echo "[OK] $FN"
  else
    echo "[FAIL] $FN — ConfigSha256 $CUR, expected $EXPECT"; FAIL=1
  fi
done < "$BASELINE"
[ "$FAIL" -eq 0 ] && echo "[OK] all configurations match baseline" \
                  || echo "[FAIL] configuration drift remains"
```

#### Verify no function carries a layer from an unrecognised account

```bash
REGION="${AWS_REGION:-us-east-1}"
OWN_ACCOUNTS="${1:?space-separated list of account ids you own}"

aws lambda list-functions --region "$REGION" --query 'Functions[].FunctionName' \
  --output text 2>/dev/null | tr '\t' '\n' | while read -r FN; do
    [ -z "$FN" ] && continue
    aws lambda get-function-configuration --function-name "$FN" --region "$REGION" \
      --query 'Layers[].Arn' --output text 2>/dev/null | tr '\t' '\n' | while read -r ARN; do
        [ -z "$ARN" ] && continue
        ACCT="$(printf '%s' "$ARN" | awk -F: '{print $5}')"
        case " $OWN_ACCOUNTS " in
          *" $ACCT "*) echo "[OK] $FN — layer from $ACCT" ;;
          *) echo "[FAIL] $FN — layer from UNRECOGNISED account $ACCT: $ARN" ;;
        esac
      done
  done
```

#### Confirm the corrected detection fires

```bash
FUNCTION="${1:?a NON-PRODUCTION function name}"
REGION="${AWS_REGION:-us-east-1}"

# Exercise a TIMEOUT change first — it must NOT produce a high-severity alert. Then a handler
# change, which must. If both produce the same output, the content check is not deployed and the
# rule is still the source pack's occurrence counter.
ORIG_TIMEOUT="$(aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
                 --query 'Timeout' --output text)"
ORIG_HANDLER="$(aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" \
                 --query 'Handler' --output text)"

aws lambda update-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --timeout $((ORIG_TIMEOUT + 1)) >/dev/null && echo "[OK] timeout changed — expect NO high alert"
sleep 30
aws lambda update-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --handler "$ORIG_HANDLER" >/dev/null && echo "[OK] handler restated — expect the HIGH handler rule"

sleep 30
aws lambda update-function-configuration --function-name "$FUNCTION" --region "$REGION" \
  --timeout "$ORIG_TIMEOUT" >/dev/null && echo "[OK] timeout restored"
```

Restating the handler to its existing value is deliberate: the field appears in the request, so the
rule fires, while the function's behaviour is unchanged throughout.

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Which field changed? | The whole triage. A timeout change and a handler repoint are the same event and different incidents. |
| Did `CodeSha256` move? | It will not have. If the investigation relied on it, the technique was invisible and that is the finding. |
| Was a `ConfigSha256` baseline recorded? | Without one there is nothing to compare against, and drift is unprovable rather than absent. |
| Did a layer come from an account you do not own? | You cannot read its contents, so the only available response is removal. |
| Did the execution role change? | If so, the function's subsequent activity is under a different role's sessions, and no IAM event marks the change. |
| Is the function invoked by `$LATEST` or by a published version? | A published version's configuration is locked and cannot be modified — that is the fix rather than a mitigation. |

### Recommended Guardrails

**Baseline `ConfigSha256`.** Every code-integrity control in the estate reports clean through this
technique. The configuration hash is returned by the same API call and moves for all of it.

**Invoke by published version or alias.** AWS locks a published version's configuration, which
removes the technique for those functions entirely.

**Inventory layer owners.** There is no AWS control restricting which accounts a layer may come
from, so an inventory is the only way a foreign layer becomes visible.

**Alert on the field, not the call.** A rule that reports `UpdateFunctionConfiguration` without
reading the request body cannot distinguish a memory bump from an execution-role swap, and will be
rated at whatever the noisiest case deserves.

**Cover all identity types.** Two sibling rules in the source pack filter on
`userIdentity.type:"IAMUser"`, which excludes every role session — SSO, federation, and the
deployment pipeline itself.

### Technique Reference

**T1578.005 — Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations.** Verified
live at https://attack.mitre.org/techniques/T1578/005/ on 2026-08-30. This is the technique the call
literally performs.

**T1525 — Implant Internal Image** is tagged on the handler and layer case, where the effect is code
implanted into the execution environment. **T1098.003 — Additional Cloud Roles** is tagged on the
execution-role change. Both verified live 2026-08-30.

The source rule maps to **`T1584 — Compromise Infrastructure`**, a Resource Development technique
about adversaries compromising third-party infrastructure for use in their own operations. Modifying
your own Lambda function is not that, and all four rules in the original pack carry it.

AWS references relied on throughout, all verified 2026-08-30:

- `UpdateFunctionConfiguration` — every settable field, the `ConfigSha256` response element, the
  statement that environment variables are omitted from CloudTrail, the VPC connectivity note, and
  the locking of published-version configuration:
  https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionConfiguration.html

### Residual Risk

**Environment variable values are unavailable, permanently.** AWS omits them from CloudTrail by
design. A change to them is visible; its content is not, and no configuration makes it so. Reading
the current values live is the only option, and it does not recover what they were.

**A layer's contents cannot be inspected if you do not own it.** The only available response to a
foreign layer is removal, which means the question "what did it do" is answered from GuardDuty and
network evidence rather than from the code.

**A role change is invisible to every IAM detection.** No IAM object is modified — the function
points elsewhere. Nothing in the IAM playbooks will fire, and the severity depends entirely on a
permissions comparison the Lambda event cannot support.

**Lambda events are regional.** Unlike IAM, they do not aggregate into `us-east-1`, so a
single-region trail covers only its own region's functions and a sweep must iterate every region
holding one.
