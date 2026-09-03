# IR Playbook: Excessive Document Creation Detected — Payload Staging via `ssm:CreateDocument` and the `SSM-SessionManagerRunShell` Override

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Execution / cloud administration command (an SSM document containing attacker-supplied commands is created, then dispatched to managed nodes — or the Session Manager preferences document is rewritten so every session runs it) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** for a write to `SSM-SessionManagerRunShell` or for an executable document that was dispatched; **Medium** for one created and not yet run; **Low** for bulk creation alone. The document runs as root or SYSTEM on every node it reaches, under that node's instance profile — so the blast radius is the fleet the dispatcher targeted, not the account. The source rule rates the volume condition P4, which is defensible for volume and badly wrong for the two single-event cases it cannot see |
| MITRE Tactics | Execution |
| MITRE Techniques | T1651 |
| Services in Scope | Systems Manager (Documents, Run Command, Automation, Session Manager, State Manager), EC2 and any managed node, IAM, CloudTrail, S3 and CloudWatch Logs where session and command output is kept |

**What the technique does:** the actor calls `CreateDocument` with `DocumentType` set to
`Command`, `Automation` or `Session` and a `Content` body carrying the payload —
`aws:runShellScript` with a `runCommand` array, or `aws:executeScript`. The
document is inert until dispatched, so a second call follows: `SendCommand`
against a target set, `StartAutomationExecution`, or `CreateAssociation` to re-run
it on a schedule. The commands execute on each node under that node's instance
profile, usually broader than the actor's own principal. The sharpest variant
needs no dispatch at all: `CreateDocument --name SSM-SessionManagerRunShell
--document-type Session` replaces the document Session Manager reads its
preferences from, whose `shellProfile` runs commands at the start of **every**
session in the Region and whose `s3BucketName` / `cloudWatchLogGroupName` /
`kmsKeyId` fields decide whether those sessions are recorded at all.

**Detection thesis.** The discriminator is `requestParameters.documentType`
together with the document's `name` and the writing principal — an executable type
written by anyone outside the deployment pipeline, and any write at all to
`SSM-SessionManagerRunShell` — not the number of documents created. The source
rule tests only a count of `createdocument` events, so it fires on every
infrastructure-as-code release that ships a runbook set and stays silent for the
single document that owns the fleet.

---

## 1. Preparation

**Logging & Visibility**

- CloudTrail multi-region trail. AWS states "Systems Manager logs all control
  plane operations to CloudTrail as management events"; the only SSM data events
  are `CreateControlChannel` / `OpenControlChannel` on
  `AWS::SSMMessages::ControlChannel` and `RequestManagedInstanceRoleToken` on
  `AWS::SSM::ManagedNode`. Document creation and dispatch are all management
  events, on by default
- `CreateDocument` carries `requestParameters.name`, `.documentType`,
  `.documentFormat`, `.targetType`, `.versionName` and `.tags`, and `resources[]`
  holds `arn:aws:ssm:<region>:<account>:document/<name>`
- **`responseElements` NESTS**: the content hash is
  `responseElements.documentDescription.hash` with `hashType` (`Sha256`)
  alongside — a flat `responseElements.hash` returns null and every hash IOC
  disappears silently. Store the hash at creation; drift from it means
  `UpdateDocument` ran later
- **Document content presence in CloudTrail is unverified.** `Content` is capped at
  64 KB, under CloudTrail's 100 KB `requestParameters` omission threshold, but AWS
  does not document whether `requestParameters.content` is recorded. Fetch it with
  `GetDocument`; do not match on it until you have confirmed it against one real
  event in your own trail
- Dispatch events and their document fields: `SendCommand`
  (`requestParameters.documentName`), `StartAutomationExecution` (`documentName`),
  `StartSession` (`documentName`), `CreateAssociation` / `UpdateAssociation`
  (`name`)
- The Session Manager and Run Command output destinations named in the preferences
  document. If those fields change during the incident, the output of everything
  after the change is gone

**Alerting (must be pre-configured)**

- **A successful write to the document named `SSM-SessionManagerRunShell` by a principal outside the session-admin allowlist → P0**
- **An executable document created outside the deployment pipeline and dispatched by the same principal within 30 minutes → P0**
- **A `Command`, `Automation` or `Session` document created by a principal outside the deployment pipeline → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- **Which principals legitimately perform this action.** The discriminator for this technique is the caller, so this list is not context — it *is* the detection's tuning surface. It should be short, owned, and in version control.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | A successful write to the document named `SSM-SessionManagerRunShell` by a principal outside the session-admin allowlist | CloudTrail (management) | T1651 |
| P0 | An executable document created outside the deployment pipeline and dispatched by the same principal within 30 minutes | CloudTrail (management) | T1651 |
| P1 | A `Command`, `Automation` or `Session` document created by a principal outside the deployment pipeline | CloudTrail (management) | T1651 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `CreateAssociation` or `UpdateAssociation` naming a document created in the previous 24 hours — the scheduled, persistent form | CloudTrail (management) | T1651 |
| P3 | Ten or more successful `CreateDocument` calls by one principal in five minutes | CloudTrail (management) | T1651 |
| P3 | A run of `DocumentAlreadyExists` errors against names the principal never created — document-name enumeration | CloudTrail (management) | T1526 |

### Detection Rule Quality Notes

The source rule counts document creations and inspects nothing about the
documents.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Volume is the only condition | A stack apply that ships fifteen runbooks fires it on every release and it gets muted; one deliberate `Command` document never fires it, because one is not more than ten | Alert on `documentType` and `name` on a single event; keep the count as a `low` secondary |
| `SSM-SessionManagerRunShell` not distinguished | The single highest-value write in this API — code at every session start plus control of session logging — is scored the same as an unused runbook | Dedicated `high` rule on that exact `requestParameters.name` |
| Grouped by `sessionContext.sessionIssuer.userName` | `sessionContext` is present only for role sessions, so every IAM user's events carry a null key and are bucketed together or dropped — an IAM user can create documents indefinitely without the count ever accumulating against them | Group by `userIdentity.arn`, which every event carries |
| No success filter | A principal denied ten times fires the same alert as one that created ten documents, and the work-list contains documents that do not exist | `success: {errorCode: null}` on the base rule and the correlation |
| No dispatch correlation | Creation is staging; the rule cannot say whether the payload ran, which is the question that decides whether hosts are compromised | `temporal_ordered` correlation from creation to `SendCommand` / `StartAutomationExecution` / `StartSession` / `CreateAssociation` |
| No principal filter | Infrastructure-as-code is the only principal that should author documents in bulk, and it is the one guaranteed to trip a volume rule | Allowlist the deployment role explicitly rather than raising the threshold until it stops firing |

**Recommended detection — a write to the Session Manager preferences document.**

```yaml
# Excessive Document Creation Detected (T1651)
#
# The original rule counted `createdocument` events, more than 10 in five minutes,
# grouped by userIdentity.sessionContext.sessionIssuer.userName, with no other
# condition. Volume is the wrong axis. A CloudFormation stack that ships fifteen
# Automation runbooks raises it; the single document that matters — one Command
# document wrapping a shell payload, or a Session document that changes what every
# Session Manager session runs — never does, because one is not more than ten.
#
# The group-by is also empty for IAM users: sessionContext is present only for role
# sessions, so every IAM user collapses into one null bucket or is dropped
# altogether. The rules below group by userIdentity.arn, which every event carries.
#
# The sharpest single event in this API is a write to the Session-type document
# named SSM-SessionManagerRunShell. AWS documents it as the document Session
# Manager stores its preferences in — the log destination (S3 / CloudWatch), the
# KMS key, Run As, and shellProfile, which runs commands at the start of every
# session. Creating it is one call, needs no volume, and both executes code on
# every managed node a session opens on and controls whether that session is
# recorded.
#
# CONTENT IS NOT MATCHED HERE ON PURPOSE. Document content is a request parameter
# capped at 64 KB, well under CloudTrail's 100 KB omission threshold, but AWS does
# not document whether `requestParameters.content` is recorded for CreateDocument.
# A content-matching rule that silently never fires is worse than no rule, so
# content inspection is done with GetDocument in the playbook instead.
title: Session Manager preferences document created or updated
id: 1628fd95-6e5b-4553-9cfe-60f277bd67ca
name: ssm_session_prefs_document_written
status: experimental
description: >-
  A write to the Session-type document SSM-SessionManagerRunShell changes what
  every Session Manager session on every managed node runs at start-up, and where
  or whether that session is logged. One event, no volume required.
references:
  - https://attack.mitre.org/techniques/T1651/
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/session-preferences-shell-config.html
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CreateDocument.html
tags:
  - attack.execution
  - attack.t1651
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName:
      - 'CreateDocument'
      - 'UpdateDocument'
      - 'UpdateDocumentDefaultVersion'
  session_prefs:
    requestParameters.name: 'SSM-SessionManagerRunShell'
  success:
    errorCode: null
  session_admins:                      # tune: the principals that own session preferences
    userIdentity.arn|contains:
      - ':role/ssm-session-admin'
      - ':role/iac-deploy'
  condition: selection and session_prefs and success and not session_admins
falsepositives:
  - A first-time Session Manager configuration, or a deliberate preferences change — both should be traceable to a change record and are rare after initial setup
level: high
---
title: Executable SSM document created outside the deployment pipeline
id: a3295a70-c239-45bc-a47a-335ca4d50bb6
name: ssm_exec_document_created
status: experimental
description: >-
  A Command, Automation or Session document created by a principal that is not the
  deployment pipeline. These are the document types that run code on managed nodes;
  the remaining types are configuration schemas and calendars.
references:
  - https://attack.mitre.org/techniques/T1651/
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CreateDocument.html
tags:
  - attack.execution
  - attack.t1651
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'CreateDocument'
  executable_types:
    requestParameters.documentType:
      - 'Command'
      - 'Automation'
      - 'Session'
  success:
    errorCode: null
  pipeline:                            # tune: principals that legitimately author documents
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/ci-cd'
      - ':role/ssm-runbook-author'
  condition: selection and executable_types and success and not pipeline
falsepositives:
  - An engineer authoring a runbook by hand outside the pipeline — should be rare and attributable
level: medium
---
title: SSM document created then executed by the same principal
id: b86aef22-1ff8-4033-addb-c52203fec5be
status: experimental
description: >-
  An executable document created outside the pipeline and then dispatched to
  managed nodes by the same principal within thirty minutes. Creation alone is
  staging; this is the pair that proves the payload ran.
references:
  - https://attack.mitre.org/techniques/T1651/
tags:
  - attack.execution
  - attack.t1651
correlation:
  type: temporal_ordered
  rules:
    - ssm_exec_document_created
    - ssm_document_dispatched
  group-by:
    - userIdentity.arn
  timespan: 30m
level: high
---
title: SSM document dispatched to managed nodes
id: 3b0c841b-0128-4d73-afcf-a631092fd311
name: ssm_document_dispatched
status: experimental
description: >-
  Base rule — sequence component only, not for direct alerting. A successful call
  that runs an SSM document against nodes or opens a session with it.
references:
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html
tags:
  - attack.execution
  - attack.t1651
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName:
      - 'SendCommand'
      - 'StartAutomationExecution'
      - 'StartSession'
      - 'CreateAssociation'
  success:
    errorCode: null
  condition: selection and success
level: low
---
title: High volume of SSM document creation by one principal
id: f3b0f789-4e1e-4f8f-8eb0-09471a2425da
status: experimental
description: >-
  The corrected form of the original volume rule — successful creations only, and
  grouped by userIdentity.arn rather than a session-issuer field that is absent for
  IAM users. Retained as a secondary signal; the type and content rules above are
  the ones that catch a single deliberate document.
references:
  - https://attack.mitre.org/techniques/T1651/
tags:
  - attack.execution
  - attack.t1651
correlation:
  type: event_count
  rules:
    - ssm_document_created
  group-by:
    - userIdentity.arn
  timespan: 5m
  condition:
    gte: 10
falsepositives:
  - Infrastructure-as-code applying a stack that ships many runbooks at once — allowlist the deployment role, which is the only principal that should do this in bulk
level: low
---
title: SSM document created
id: 99248ed3-9447-4f45-8bfe-691d7930fc7d
name: ssm_document_created
status: experimental
description: >-
  Base rule — count component only, not for direct alerting. A successful
  CreateDocument of any type.
references:
  - https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CreateDocument.html
tags:
  - attack.execution
  - attack.t1651
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ssm.amazonaws.com'
    eventName: 'CreateDocument'
  success:
    errorCode: null
  condition: selection and success
level: low
```

The rule cannot inspect the document's content, because AWS does not document
whether `requestParameters.content` reaches CloudTrail, and a content match that
silently never fires is worse than no rule. Query 2 fetches the content with
`GetDocument` instead and that is where the payload is read. The rule also cannot
see a document created in another account and **shared** into this one — sharing
is `ModifyDocumentPermission`, a different event, and the shared document's
content is not yours to fetch.

---

### Key Investigation Queries

> SSM documents are **regional** — run these in every Region the account uses.
> Extraction uses `--output json | jq -r '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page**; paginate on `NextToken` for a
> busy window.

#### Query 1 — Reconstruct: which documents were written, by whom, and were they run

```bash
REGION="<region>"
START="$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"

for EV in CreateDocument UpdateDocument UpdateDocumentDefaultVersion \
          SendCommand StartAutomationExecution StartSession CreateAssociation; do
  aws cloudtrail lookup-events --region "$REGION" \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$START" --max-results 50 --output json \
  | jq -r '.Events[].CloudTrailEvent | fromjson'
done | jq -s '
  map(select(.errorCode == null))
  | map({
      time:      .eventTime,
      event:     .eventName,
      caller:    (.userIdentity.arn // "unknown"),
      accessKey: (.userIdentity.accessKeyId // "none"),
      session:   ((.userIdentity.arn // "") | split("/") | last),
      sourceIp:  .sourceIPAddress,
      documentName: (.requestParameters.name // .requestParameters.documentName // ""),
      documentType: (.requestParameters.documentType // ""),
      # responseElements NESTS under documentDescription — a flat .hash is null.
      documentHash: (.responseElements.documentDescription.hash // ""),
      targets:      (.requestParameters.targets // []),
      instanceIds:  (.requestParameters.instanceIds // [])
    })
  | map(select(.documentName != ""))
  | sort_by(.time)'
```

Group the output by `documentName`. A name appearing once with
`event: CreateDocument` and never again is staged and unused — bad, but nothing has
run. A name with a create and then a `SendCommand`, `StartAutomationExecution` or
`CreateAssociation` from the same `caller` is the P0 shape: read `targets` and
`instanceIds` for the host list and treat every host in it as compromised until the
command output says otherwise. `documentName: SSM-SessionManagerRunShell` is P0 on
its own, because every session is the dispatch. Record `documentHash` now — it is
the only way to tell later whether the document changed again. `session` is the
last `/` segment of the caller ARN, which for an instance-profile session is the
instance ID.

#### Query 2 — Inspect the content CloudTrail does not reliably record

```bash
REGION="<region>"
DOC_NAME="<document-name-from-Query-1>"

CONTENT="$(aws ssm get-document --region "$REGION" --name "$DOC_NAME" \
            --document-version '$LATEST' --output json)"
RC=$?

if [ "$RC" -ne 0 ] || [ -z "$CONTENT" ]; then
  echo "[!] INCONCLUSIVE — get-document failed for $DOC_NAME. An InvalidDocument error"
  echo "    here means the document is already gone: recover the content from the"
  echo "    creation event or from your configuration backup, not from this call."
else
  printf '%s' "$CONTENT" | jq '{Name, DocumentType, DocumentFormat, DocumentVersion, Status}'
  printf '%s' "$CONTENT" | jq -r '.Content'
fi

# Everything that has ever run this document, and everything scheduled to.
aws ssm list-associations --region "$REGION" \
  --association-filter-list "key=Name,value=$DOC_NAME" --output json \
| jq '[.Associations[] | {AssociationId, Name, Targets, ScheduleExpression, LastExecutionDate}]'

aws ssm list-commands --region "$REGION" --output json \
| jq --arg d "$DOC_NAME" '[.Commands[] | select(.DocumentName == $d)
    | {CommandId, DocumentName, Status, RequestedDateTime, TargetCount, Comment}]'
```

In a `Command` document read the `aws:runShellScript` / `aws:runPowerShellScript`
plugins and their `runCommand` arrays — that is the payload verbatim. In an
`Automation` document read `aws:executeScript` and the `assumeRole`, because the
automation runs with that role's permissions rather than the author's, so the role
is the blast radius. In a `Session` document read `shellProfile` for commands that
run at session start, and `s3BucketName` / `cloudWatchLogGroupName` / `kmsKeyId` to
see whether session recording was redirected or switched off. An association in the
first output is persistence — it re-runs on a schedule and survives deleting nothing
but itself; commands in the second give you `CommandId` values for
`aws ssm list-command-invocations --command-id <id> --details`.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="Automation Command CreateAssociation CreateDocument SendCommand Session StartAutomationExecution StartSession"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "ssm.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

The alerting event named one resource; this asks whether the same principal did the same thing
elsewhere, and whether anyone else did it too. Group by caller rather than by resource: the
question the eradication phase needs answered is *how much of this is one actor's work*, and a
per-resource list cannot say. `access_key` is emitted here because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` regardless of whether it happened — see the caveat in the preamble.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'
```

Keyed on the access key rather than the ARN, because one credential is used across many
sessions and the key is what identifies the credential. The per-service grouping answers the
question this playbook cannot: whether this technique was the objective or one stop on a tour.
A service in that list with no business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID — so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Stop dispatch before you touch the document, and capture the content before you
delete it — an SSM document has no disabled state, so deletion is the only removal
and it is irreversible. If the document is `SSM-SessionManagerRunShell`, deleting
it reverts every session to Session Manager defaults, which is the correct restore
but also silently turns off any legitimate session logging that document
configured; capture it first for that reason too.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Cancel in-flight commands, then preserve and remove the document

```bash
REGION="<region>"
DOC_NAME="<document-name-from-Query-1>"
EVIDENCE_DIR="/tmp/ir-ssm-doc"
mkdir -p "$EVIDENCE_DIR"

# 1. Cancel anything this document still has in flight.
PENDING="$(aws ssm list-commands --region "$REGION" --output json \
           | jq -r --arg d "$DOC_NAME" '.Commands[]
               | select(.DocumentName == $d)
               | select(.Status == "Pending" or .Status == "InProgress")
               | .CommandId')"
if [ -n "$PENDING" ]; then
  for CID in $PENDING; do
    aws ssm cancel-command --region "$REGION" --command-id "$CID"
    echo "[OK] cancelled in-flight command $CID"
  done
else
  echo "[!] no Pending or InProgress commands found for $DOC_NAME — either none ran,"
  echo "    or they have already completed. Query 2's list-commands output is the record."
fi

# 2. Preserve the content BEFORE deleting. Deletion is irreversible.
if aws ssm get-document --region "$REGION" --name "$DOC_NAME" \
     --document-version '$LATEST' --output json > "$EVIDENCE_DIR/$DOC_NAME.json"; then
  echo "[OK] content preserved at $EVIDENCE_DIR/$DOC_NAME.json"
  # 3. Only now remove it.
  aws ssm delete-document --region "$REGION" --name "$DOC_NAME"
  echo "[OK] document $DOC_NAME deleted"
else
  echo "[FAIL] could not read $DOC_NAME — NOT deleting. Removing a document whose"
  echo "       content was never captured destroys the only copy of the payload."
fi
```

Deleting the document does not undo anything it already ran. Every node in
Query 1's `targets` / `instanceIds` remains compromised at the host level and is
handled outside AWS.

#### Step 2 — Contain the principal

```bash
PRINCIPAL_ARN="<caller-arn-from-Query-1>"
POLICY_NAME="IR-SSM-Document-Freeze"

cat > /tmp/ir-ssm-doc-freeze.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "FreezeDocumentAuthoringAndDispatch",
      "Effect": "Deny",
      "Action": ["ssm:CreateDocument", "ssm:UpdateDocument", "ssm:UpdateDocumentDefaultVersion",
                 "ssm:ModifyDocumentPermission", "ssm:SendCommand", "ssm:StartSession",
                 "ssm:StartAutomationExecution", "ssm:CreateAssociation", "ssm:UpdateAssociation"],
      "Resource": "*" }
  ]
}
JSON

case "$PRINCIPAL_ARN" in
  *:user/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $NF}')"
    aws iam put-user-policy --user-name "$IAM_NAME" \
      --policy-name "$POLICY_NAME" --policy-document file:///tmp/ir-ssm-doc-freeze.json
    echo "[OK] freeze applied to IAM user $IAM_NAME" ;;
  *:assumed-role/*|*:role/*)
    IAM_NAME="$(printf '%s\n' "$PRINCIPAL_ARN" | awk -F'/' '{print $2}')"
    aws iam put-role-policy --role-name "$IAM_NAME" \
      --policy-name "$POLICY_NAME" --policy-document file:///tmp/ir-ssm-doc-freeze.json
    echo "[OK] freeze applied to role $IAM_NAME"
    echo "[!] if this role is the deployment pipeline, releases now fail — say so in the channel" ;;
  *:root)
    echo "[!] root credential — no policy denies root. Rotate the root password, remove"
    echo "    any root access key, confirm root MFA." ;;
  *)
    echo "[!] unrecognised principal shape: $PRINCIPAL_ARN — contain manually." ;;
esac
```

`ssm:RunCommand` is not a real IAM action; the action that dispatches a document is
`ssm:SendCommand`. A deny policy naming the wrong one reads as protection and does
nothing.

---

## 4. Eradication

### Remove Attacker Access

- **Delete every association referencing the document first, then the document.**
  An association re-runs on a schedule and outlives its author; deleting the
  document while an association still names it leaves a broken schedule that hides
  the fact anything was ever scheduled. Use `aws ssm delete-association
  --association-id <id>` for each ID Query 2 returned
- **Treat every node in Query 1's `targets` and `instanceIds` as compromised.**
  Pull per-node output with `aws ssm list-command-invocations --command-id <id>
  --details` before anything is rebuilt — the invocation record is the only place
  the command's actual output survives, and it ages out
- **Restore `SSM-SessionManagerRunShell` deliberately, not by omission.** If it was
  the target, recreate it from the preserved copy with the legitimate logging
  destination and shell profile. Leaving it absent reverts to defaults, which
  means no session logging at all
- **Right-size `ssm:CreateDocument`.** Only the deployment pipeline needs it.
  Scope it by resource ARN — `arn:aws:ssm:<region>:<account>:document/<prefix>-*` —
  so an author cannot create a document under a name the fleet already trusts
- **Remove the emergency policy once clean, with a real check** — see §5, which
  asserts rather than assumes it was applied to the right principal

---

## 5. Recovery

### Restore Clean State

#### Verify the document is gone and nothing still schedules it

```bash
REGION="<region>"
DOC_NAME="<document-name-from-Query-1>"

DOCS="$(aws ssm list-documents --region "$REGION" \
        --filters "Key=Name,Values=$DOC_NAME" --output json)"
DRC=$?
ASSOC="$(aws ssm list-associations --region "$REGION" \
         --association-filter-list "key=Name,value=$DOC_NAME" --output json)"
ARC=$?

if [ "$DRC" -ne 0 ] || [ -z "$DOCS" ] || [ "$ARC" -ne 0 ] || [ -z "$ASSOC" ]; then
  echo "[!] INCONCLUSIVE — a listing call failed for $DOC_NAME; neither absence nor"
  echo "    presence is established. Re-run with credentials that hold ssm:ListDocuments"
  echo "    and ssm:ListAssociations before treating this as clean."
else
  NDOC="$(printf '%s' "$DOCS"  | jq '.DocumentIdentifiers | length')"
  NASC="$(printf '%s' "$ASSOC" | jq '.Associations | length')"
  if [ "$NDOC" -eq 0 ] && [ "$NASC" -eq 0 ]; then
    echo "[OK] $DOC_NAME is absent and no association references it"
  else
    echo "[FAIL] $DOC_NAME still present ($NDOC document(s)) with $NASC association(s)"
    printf '%s' "$ASSOC" | jq -r '.Associations[] | "  association \(.AssociationId) schedule \(.ScheduleExpression // "on-demand")"'
  fi
fi
```

Both calls return an empty list as a normal result and a non-zero exit on failure,
so absence is distinguishable from "could not look". Do not substitute
`get-document` here: it raises `InvalidDocument` both when the document is gone and
when the caller cannot see it, and the two are not the same finding.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     eventSource=ssm.amazonaws.com eventName=CreateDocument"
echo "                  requestParameters.name=SSM-SessionManagerRunShell"
echo "                  requestParameters.documentType=Session  errorCode absent"
echo "                  userIdentity.arn=arn:aws:iam::111122223333:user/contractor"
echo "MUST fire on:     CreateDocument documentType=Command by a non-pipeline principal,"
echo "                  followed within 30 minutes by SendCommand naming that document"
echo "MUST NOT fire on: the same CreateDocument with userIdentity.arn containing"
echo "                  :role/iac-deploy (the allowlisted pipeline shipping runbooks)"
echo "MUST NOT fire on: CreateDocument documentType=ChangeCalendar or"
echo "                  ApplicationConfigurationSchema (no execution path)"
echo "MUST NOT fire on: CreateDocument carrying errorCode=DocumentAlreadyExists"
echo "                  (nothing was created; it belongs in the enumeration signal)"
echo "EXPECTED FP, by design: an engineer authoring a runbook by hand outside the"
echo "                  pipeline. Rare and attributable; resolve by change record."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal outside the deployment pipeline could author an executable SSM document | `ssm:CreateDocument` granted on `*` rather than scoped to a document-name prefix owned by the pipeline |
| One call could change what every Session Manager session runs and where it is logged | No resource-level deny on the `SSM-SessionManagerRunShell` document name, and no alert on writes to it |
| Whether the payload ran was not answerable from the alert | Detection stopped at creation; the dispatch events that name the document were never correlated to it |
| Every IAM user's creations aggregated into one bucket | The volume rule grouped on `sessionContext.sessionIssuer.userName`, which is absent for IAM-user principals |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Protect the Session Manager preferences document by name. The resource ARN is
// wildcarded across Region and account, which is fine — wildcards ARE expanded in
// the Resource element. The principal allowlist is wildcarded too and therefore
// needs ArnNotLike: Deny + ArnNotEquals against a wildcard fails CLOSED and locks
// out the session admins along with everyone else.
{
  "Sid": "ProtectSessionManagerPreferencesDocument",
  "Effect": "Deny",
  "Action": ["ssm:CreateDocument", "ssm:UpdateDocument",
             "ssm:UpdateDocumentDefaultVersion", "ssm:DeleteDocument"],
  "Resource": "arn:aws:ssm:*:*:document/SSM-SessionManagerRunShell",
  "Condition": {
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/ssm-session-admin" }
  }
}
```

- **Scope `ssm:CreateDocument` by name prefix.** Grant the pipeline
  `arn:aws:ssm:<region>:<account>:document/<org>-*` and nobody else the action at
  all. AWS already reserves the `aws`, `amazon`, `amzn`, `AWSEC2`,
  `AWSConfigRemediation` and `AWSSupport` prefixes, so a document cannot
  impersonate an AWS-owned one — the gap is your own naming convention
- **Turn on `ssm:SessionDocumentAccessCheck`**, which forces `StartSession` to
  verify the caller holds explicit permission on the session document it names.
  Without it, a document one principal authored is usable by another
- **Send Session Manager and Run Command output to a log destination the SSM
  principals cannot write to**, so redirecting `s3BucketName` in the preferences
  document cannot quietly retarget the audit trail into an attacker-controlled
  bucket

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1651 — Cloud Administration Command |
| MITRE tactic | Execution (TA0002) |
| Primary API | `ssm:CreateDocument` → `ssm:SendCommand` / `StartAutomationExecution` / `StartSession` / `CreateAssociation` |
| Event source | `ssm.amazonaws.com` — **management** events, recorded by default. Verified: AWS states "Systems Manager logs all control plane operations to CloudTrail as management events", and the only SSM data-event resource types are `AWS::SSMMessages::ControlChannel` and `AWS::SSM::ManagedNode` |
| Key discriminator | `requestParameters.documentType` in (`Command`, `Automation`, `Session`) plus a writing principal outside the pipeline — or `requestParameters.name == SSM-SessionManagerRunShell`, which needs no other condition |
| Ground-truth signal | `responseElements.documentDescription.hash` (`hashType: Sha256`) — **nested**, a flat path is null |
| "Was it used" pivot | `SendCommand` / `StartAutomationExecution` / `StartSession` / `CreateAssociation` naming the document; then `ListCommandInvocations --details` for per-node output |
| Blast radius | Every managed node the dispatcher targeted, running as root or SYSTEM under that node's instance profile. For `SSM-SessionManagerRunShell`, every node anyone opens a session to, plus the session audit trail |
| Content in logs | Capped at 64 KB, under CloudTrail's 100 KB omission threshold, but presence of `requestParameters.content` is **not documented** — fetch with `GetDocument`, do not match on it |
| Error strings | `DocumentAlreadyExists`, `DocumentLimitExceeded` (500 active documents), `MaxDocumentSizeExceeded` (64 KB), `InvalidDocumentContent`, `InvalidDocumentSchemaVersion`, `NoLongerSupportedException`, `TooManyUpdates`, `InternalServerError`; denials as `AccessDenied` and `AccessDeniedException` — match both |

**MITRE mapping note.** The source rule maps T1082 (*System Information
Discovery*) under TA0007. Creating a document discovers nothing — it stages a
payload for execution through a cloud management service, which is exactly what
T1651 (*Cloud Administration Command*) describes, under Execution (TA0002). The
directory slug keeps the source's `discovery` label so the register stays
navigable against the alert set; the mapping in the Classification table and in
the shipped rules is T1651. The one place Discovery is genuinely right here is the
`DocumentAlreadyExists` enumeration row in the trigger table, which is T1526
(*Cloud Service Discovery*) — a different signal from the one the source rule
matches.

### Residual Risk

**Deleting the document does not undo what it ran.** Anything a dispatched
document executed on a managed node is a host-level compromise: a shell, a cron
entry, a modified binary, a credential harvested from the instance profile. That
work happens on the hosts, and none of it is visible in the SSM control plane.

**Command output ages out.** `ListCommandInvocations` is the only place the
per-node result of a Run Command survives if output was not sent to S3 or
CloudWatch Logs, and it does not keep it indefinitely. If the preferences document
was rewritten to drop the logging destination, the output of everything after that
change never existed anywhere.

**Documents shared from another account are not yours to inspect.**
`ModifyDocumentPermission` shares a document into this account; the content lives in
the owning account and `GetDocument` may return `InvalidDocument`. For those the only
record is the dispatch events on your side. Likewise, if the eradication order was
reversed — document deleted before its associations — the association list becomes the
only surviving evidence that anything was scheduled, naming a document nobody can read.
