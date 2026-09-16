# IR Playbook: SNS Topic Deleted — `DeleteTopic` leaves alarms firing into nothing

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence impairment — a notification topic is deleted, and every control publishing to it stops reaching anyone without producing an error |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical when the topic carried alerts or security notifications; high for bulk deletion or a deletion never recreated; medium for a refused attempt. The source rule is P4 and rates every deletion identically. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685 (primary); T1489 (the availability half) |
| Services in Scope | SNS, CloudWatch, GuardDuty, Config, CloudTrail |

**What the technique does:** the actor deletes the topic that carries notifications. Nothing errors.
The CloudWatch alarms publishing to it keep evaluating, keep transitioning to `ALARM`, and keep
reporting themselves as healthy — AWS states plainly that CloudWatch "doesn't test or validate the
actions that you specify, nor does it detect any ... Amazon SNS errors resulting from an attempt to
invoke nonexistent actions."

One topic is frequently the path for several independent controls at once: CloudWatch alarms,
GuardDuty finding notifications, Config rules, Security Hub, Budgets. Deleting it removes all of them
in one call.

The second is the severity
— a P4 for the action that silently removes the alerting path. The third is treating recovery as
recreating the topic, when every subscription went with it and email and HTTP/S endpoints must be
re-confirmed by their owners. The fourth is trusting the event: `DeleteTopic` is idempotent, so a
success is not evidence the topic existed.

**Detection thesis:** rate on what the topic carried, alert on the refused case the source excludes,
and rebuild the alarm inventory rather than the topic list.

**Adjacent playbooks.** Topic policy changes are `../sns.persistence.topic-policy-modified/`.
Encryption changes are `../sns.impact.server-side-encryption-for-aws-sns-topics-was-disabled/` and
`../sns.impact.a-less-secure-server-side-encryption-policy-created/`. Topics created public are the
two `../sns.collection.sns-topic-was-created-with-public-*` playbooks.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `DeleteTopic` is control-plane and logged by default.

**An inventory of every topic and what publishes to it** — CloudWatch alarms, GuardDuty notification
configurations, Config delivery channels, Security Hub, Budgets — refreshed on a schedule. Once the
topic is gone, this is the only way to know what stopped working, and rebuilding it after the fact is
the slowest part of the response.

**An inventory of every subscription, including protocol and endpoint.** Recreating a topic does not
recreate them, and email and HTTP/S endpoints need their owners to confirm again.

**A heartbeat through the alerting topic.** A synthetic alarm that fires on a schedule and is expected
to arrive is the only control that detects this without depending on the deletion event at all.

**Alerting (must be pre-configured)**

- **`DeleteTopic` on a topic that is a CloudWatch alarm action or a security notification path → P0**
- **Three or more distinct topics deleted by one principal in thirty minutes → P1**
- **`DeleteTopic` outside the provisioning path, with no matching `CreateTopic` afterwards → P1**
- **`DeleteTopic` refused → P2**

**Response Tooling**

An IAM principal that can call `sns create-topic`, `sns subscribe`, `sns set-topic-attributes` and
`cloudwatch describe-alarms` outside the change pipeline.

**Known IOC Baselines**

The provisioning roles that tear down environments, and the topic naming conventions that identify an
alerting path. Name matching is a proxy for "is an alarm target" and it is imperfect, which is why the
inventory above matters more.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `DeleteTopic` on a topic that is a CloudWatch alarm action or a GuardDuty notification target | CloudTrail + alarm inventory | T1685 |
| P1 | Three or more distinct topics deleted by one principal within thirty minutes | Correlation rule | T1685 |
| P1 | `DeleteTopic` outside the provisioning path with no matching `CreateTopic` afterwards | CloudTrail | T1489 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `DeleteTopic` refused — excluded by the source rule's error filter | CloudTrail | T1685 |
| P2 | A successful `DeleteTopic` on an ARN that is not in the topic inventory — a sprayed guess | CloudTrail + inventory | T1685 |
| P3 | Any `DeleteTopic` outside the provisioning path | CloudTrail | T1489 |

### Detection Rule Quality Notes

The source rule is one immediate query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Rated P4 | It silently removes the notification path for several controls at once. CloudWatch reports nothing | Critical when the topic carried alerts |
| No content or context on the topic | The topic carrying security notifications and the one carrying build notifications are rated identically | A name-based alerting-topic rule, and an inventory check in §5 |
| No threshold | One decommission and a walk across every topic in the account are the same alert | A three-topics-in-thirty-minutes correlation |
| `NOT _exists_:errorCode` | The call is **idempotent** — deleting a topic that does not exist succeeds. Every sprayed ARN therefore looks like a successful deletion, and a refused attempt is invisible | A rule for the refused case, and an inventory check to separate real deletions from guesses |

**What the source gets right:** the event name is correctly cased, which two sibling SNS rules in this
source set do not manage — see `../_ground-truth/sns.md` §5.

**Recommended detection — rated on what the topic carried, with the refused case restored.**

```yaml
# SNS topic deleted (T1685)
#
# DELETING A TOPIC IS DEFENCE IMPAIRMENT, NOT AN OUTAGE. AWS: "CloudWatch doesn't test or validate the
# actions that you specify, nor does it detect any ... Amazon SNS errors resulting from an attempt to
# invoke nonexistent actions." The alarm still evaluates, still transitions to ALARM, still shows as
# healthy — and the notification is dropped silently. One topic is frequently the path for CloudWatch
# alarms, GuardDuty notifications, Config rules and Security Hub at once.
#
# THE CALL CANNOT FAIL. AWS: "This action is idempotent, so deleting a topic that does not exist does
# not result in an error." With the source rule's `NOT _exists_:errorCode` filter, an actor spraying
# guessed ARNs produces a stream of alerts that all look like successful deletions.
#
# AND IT TAKES THE SUBSCRIPTIONS WITH IT. Recovery is not recreating the topic: every subscription
# must be recreated and email and HTTP/S endpoints RE-CONFIRMED BY THE SUBSCRIBER.
# See ../../_ground-truth/sns.md §3 and §4.
title: SNS alerting topic deleted
id: 555d1b3f-2ec9-4a25-84e2-aaaae41c3cdf
status: experimental
description: >-
  A topic whose name identifies it as an alerting or security notification path was deleted. Every
  CloudWatch alarm, GuardDuty notification and Config rule publishing to it now fails silently —
  CloudWatch does not validate alarm actions and reports nothing when the target is gone.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_DeleteTopic.html
  - https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
  - https://attack.mitre.org/techniques/T1685/
tags:
  - attack.defense-evasion
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sns.amazonaws.com
    eventName: DeleteTopic
    errorCode: null
  # POPULATE with this account's naming conventions for notification topics. Name matching is a proxy
  # for "this topic is an alarm target" and it is imperfect — the authoritative test is the CloudWatch
  # alarm inventory, which a rule cannot reach. §5 of the playbook rebuilds that inventory properly.
  selection_alerting:
    requestParameters.topicArn|contains:
      - 'alarm'
      - 'alert'
      - 'security'
      - 'guardduty'
      - 'oncall'
      - 'incident'
  condition: selection and selection_alerting
falsepositives:
  - Decommissioning a retired alerting path, which should be identifiable from a change record and
    from the alarms having been removed first
level: critical
---
name: sns_topic_deleted
title: SNS topic deleted
id: 383c591a-c0be-4d5a-a55d-8c65de008242
status: experimental
description: >-
  DeleteTopic returned success outside the provisioning path. Note that the call is idempotent, so a
  success is not evidence the topic existed — a sprayed ARN produces the same event. Base rule for the
  correlation below.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_DeleteTopic.html
  - https://attack.mitre.org/techniques/T1685/
tags:
  - attack.defense-evasion
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sns.amazonaws.com
    eventName: DeleteTopic
    errorCode: null
  filter_provisioning:
    userIdentity.arn|contains:
      - 'PlatformAutomation'
      - 'iac-deploy'
  condition: selection and not filter_provisioning
falsepositives:
  - Environment teardown, which is the common explanation and is confirmed by a change record rather
    than by the event
  - An actor spraying guessed topic ARNs, every one of which succeeds
level: low
---
# Three or more in thirty minutes is a sweep. The source rule has no threshold at all, so a single
# decommission and a walk across every topic in the account produce the same alert.
title: SNS topics deleted in bulk by one principal
id: 4c021ab6-abc7-49d7-b27f-e17d6aa51e8e
status: experimental
description: >-
  One principal deleted three or more distinct topics within thirty minutes. Because DeleteTopic is
  idempotent, some of these ARNs may never have existed — the count is an upper bound on the damage
  and a lower bound on the intent.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_DeleteTopic.html
  - https://attack.mitre.org/techniques/T1685/
tags:
  - attack.defense-evasion
  - attack.t1685
correlation:
  type: value_count
  rules:
    - sns_topic_deleted
  group-by:
    - userIdentity.arn
  timespan: 30m
  condition:
    gte: 3
    field: requestParameters.topicArn
falsepositives:
  - A planned decommission of an entire environment, identifiable from a change record naming the same
    topic ARNs
level: high
---
# The refused case. The source rule excludes errors, so a deletion the permissions caught leaves no
# alert — and this is one of the few SNS calls where refusal genuinely means the guardrail worked.
title: SNS topic deletion refused
id: 4514e46b-48cf-4839-a589-ec269431f5e2
status: experimental
description: >-
  DeleteTopic returned an error. Since the call is idempotent against a non-existent topic, an error
  here is almost always authorization — a principal that tried to remove a topic and was stopped.
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_DeleteTopic.html
  - https://attack.mitre.org/techniques/T1685/
tags:
  - attack.defense-evasion
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sns.amazonaws.com
    eventName: DeleteTopic
  filter_success:
    errorCode: null
  condition: selection and not filter_success
falsepositives:
  - A teardown pipeline racing itself, where a second worker deletes a topic already removed — though
    that case returns success rather than an error, so it is rarer than it sounds
level: medium
```

What this set structurally cannot do: know which topics were alarm targets. A detection rule cannot
read the CloudWatch inventory, so it keys on names as a proxy. §2 Query 2 does it properly.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> SNS is **regional**, and so are CloudWatch alarms. `DeleteTopic` is control-plane and logged by
> default.

Run Query 2 before Query 1 if alerting may be affected — it establishes what is currently broken, and
that is the thing with ongoing consequence.

#### Query 1 — Reconstruct: what was deleted, and was it recreated

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in DeleteTopic CreateTopic Unsubscribe; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | .requestParameters as $r
      | "\(.eventTime)  \(.eventName)  " +
        "result=\(if .errorCode then .errorCode else "SUCCESS" end)  " +
        "topic=\(($r.topicArn // $r.name // "-") | split(":") | last)  " +
        "by=\(.userIdentity.arn)"'
done | sort

cat <<'NOTE'

[!] A SUCCESS on DeleteTopic is NOT evidence the topic existed. AWS: "This action is idempotent, so
    deleting a topic that does not exist does not result in an error." An actor spraying guessed ARNs
    produces successes for every one. Cross-check each name against your topic inventory before
    counting it as damage.
[!] A CreateTopic with the same name shortly afterwards is usually a redeploy — but SNS rejects reuse
    of a recently deleted ARN for a period, so check whether that CreateTopic actually succeeded.
NOTE
```

#### Query 2 — What is now publishing into nothing

```bash
REGION="${AWS_REGION:-us-east-1}"

# Every existing topic ARN, so anything referenced but absent is a dangling target.
aws sns list-topics --region "$REGION" --query 'Topics[].TopicArn' --output text 2>/dev/null \
  | tr '\t' '\n' | sort > /tmp/sns-existing-$$.txt

echo "=== CloudWatch alarms whose actions reference an SNS topic ==="
aws cloudwatch describe-alarms --region "$REGION" --output json 2>/dev/null \
| jq -r '.MetricAlarms[], (.CompositeAlarms // [])[]
    | . as $a
    | (($a.AlarmActions // []) + ($a.OKActions // []) + ($a.InsufficientDataActions // []))[]
    | select(startswith("arn:aws:sns:"))
    | "\($a.AlarmName)\t\(.)"' \
| while IFS="$(printf '\t')" read -r NAME ARN; do
    [ -z "$ARN" ] && continue
    if grep -qxF "$ARN" /tmp/sns-existing-$$.txt; then
      echo "[OK] $NAME -> ${ARN##*:}"
    else
      echo "[FAIL] $NAME -> ${ARN##*:} — TOPIC DOES NOT EXIST; this alarm notifies nobody"
    fi
  done
rm -f /tmp/sns-existing-$$.txt

cat <<'NOTE'

[!] This is the authoritative answer, and it is the reason the incident is quiet. AWS: "CloudWatch
    doesn't test or validate the actions that you specify, nor does it detect any ... Amazon SNS
    errors resulting from an attempt to invoke nonexistent actions." Every [FAIL] alarm above still
    evaluates, still transitions to ALARM, and still shows as healthy in the console.
[!] Check the other publishers too — they do not appear in describe-alarms:
      aws guardduty list-publishing-destinations --detector-id <id>
      aws configservice describe-delivery-channels
      aws budgets describe-budgets --account-id <acct>       # notification SNS targets
NOTE
```

#### Query 3 — What the deleted topic's subscriptions were

```bash
REGION="${AWS_REGION:-us-east-1}"
TOPIC_NAME="${1:?deleted topic name from Query 1}"
START="$(date -u -v-90d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '90 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

echo "[!] The subscriptions are gone with the topic — list-subscriptions-by-topic cannot help now."
echo "    Reconstruct them from the Subscribe events in the trail:"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Subscribe \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg t "$TOPIC_NAME" '.Events[].CloudTrailEvent | fromjson
    | select((.requestParameters.topicArn // "") | endswith(":" + $t))
    | "  \(.eventTime)  \(.requestParameters.protocol)  \(.requestParameters.endpoint)"' | sort -u

cat <<'NOTE'

[!] Recreating the topic does NOT recreate these. Each has to be resubscribed, and EMAIL and HTTP/S
    endpoints must be RE-CONFIRMED by the subscriber — the responder cannot complete those alone, so
    start the confirmation requests early and track which have been accepted.
NOTE
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

`DeleteAlarms`, `StopLogging`, `DeleteDetector` or `DeleteTrail` in the same window is the same intent
against the other halves of the alerting chain, and each has its own playbook. A topic deleted
**before** the activity it would have reported is the ordering that matters most — check what the
principal did after the deletion, not only before.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The topic is gone and cannot be restored. What can be restored is the alerting path, and until it is,
every alarm pointing at it is failing silently.

**Break-glass — use the break-glass credential, not the on-call's own.** Recreate the topic under the
same name first — every alarm still references the old ARN, and an ARN is deterministic from the
account, region and name, so recreating the topic under the same name makes those alarms work again
without editing a single alarm.

#### Step 1 — Recreate the topic under the same name

```bash
REGION="${AWS_REGION:-us-east-1}"
NAME="${1:?deleted topic name from Query 1}"

aws sns create-topic --name "$NAME" --region "$REGION" --query 'TopicArn' --output text 2>/dev/null \
  && echo "[OK] $NAME recreated — alarms referencing the old ARN work again, because the ARN is" \
  && echo "     derived from account, region and name" \
  || echo "[FAIL] create-topic failed. SNS rejects reuse of a recently deleted ARN for a period —" \
     && echo "     retry with backoff rather than choosing a different name, which would require" \
     && echo "     editing every alarm."
```

Choosing a different name is the tempting shortcut and it is the expensive one: every alarm, every
GuardDuty publishing destination and every Config delivery channel would have to be repointed.

#### Step 2 — Restore the access policy and encryption

```bash
REGION="${AWS_REGION:-us-east-1}"
TOPIC="${1:?new topic ARN}"
POLICY_FILE="${2:-}"
KMS_KEY="${3:-}"

echo "[!] A recreated topic has SNS's DEFAULT policy and NO encryption. Anything that published to"
echo "    the old topic under a resource-policy grant — GuardDuty, Config, EventBridge — cannot"
echo "    publish until that grant is restored."

if [ -n "$POLICY_FILE" ] && [ -f "$POLICY_FILE" ]; then
  aws sns set-topic-attributes --topic-arn "$TOPIC" --attribute-name Policy \
    --attribute-value "file://$POLICY_FILE" --region "$REGION" >/dev/null 2>&1 \
    && echo "[OK] access policy restored from $POLICY_FILE"
else
  echo "[!] No baseline policy supplied — restore it before declaring the path recovered."
fi

if [ -n "$KMS_KEY" ]; then
  aws sns set-topic-attributes --topic-arn "$TOPIC" --attribute-name KmsMasterKeyId \
    --attribute-value "$KMS_KEY" --region "$REGION" >/dev/null 2>&1 \
    && echo "[OK] encryption restored"
fi
```

#### Step 3 — Resubscribe, and track the confirmations

```bash
REGION="${AWS_REGION:-us-east-1}"
TOPIC="${1:?new topic ARN}"
shift
# Pass pairs from Query 3: protocol endpoint protocol endpoint ...
while [ "$#" -ge 2 ]; do
  PROTO="$1"; EP="$2"; shift 2
  ARN="$(aws sns subscribe --topic-arn "$TOPIC" --protocol "$PROTO" --notification-endpoint "$EP" \
          --region "$REGION" --query 'SubscriptionArn' --output text 2>/dev/null)"
  case "$ARN" in
    PendingConfirmation) echo "[!] $PROTO $EP — awaiting confirmation BY THE SUBSCRIBER; chase it" ;;
    arn:*)               echo "[OK] $PROTO $EP — active immediately" ;;
    *)                   echo "[FAIL] $PROTO $EP — subscribe failed" ;;
  esac
done
```

Lambda and SQS subscriptions activate immediately. Email and HTTP/S do not, and the alerting path is
not restored until their owners click through — which is why §1 asks for the subscription inventory in
advance.

#### Step 4 — Contain the principal

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

---

## 4. Eradication

### Remove Attacker Access

#### Run a heartbeat through the alerting topic

A synthetic alarm that fires on a schedule, publishes to the alerting topic, and is expected to arrive
is the only control that detects this failure mode without depending on the deletion event. It also
catches the quieter variants — a subscription removed, an endpoint that stopped accepting, an
encryption key the topic can no longer use.

#### Deny deletion of alerting topics

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyDeletionOfAlertingTopics",
  "Effect": "Deny",
  "Action": ["sns:DeleteTopic"],
  "Resource": ["arn:aws:sns:*:*:*alarm*", "arn:aws:sns:*:*:*security*",
               "arn:aws:sns:*:*:*guardduty*", "arn:aws:sns:*:*:*oncall*"],
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. The role name must be a role
that genuinely exists — an `ArnNotLike` against a non-existent role denies the action to everyone.
Unlike most SCP guardrails in this set, this one is scoped by **resource** rather than only by
principal, which means the naming convention has to be real and enforced or the protection is
imaginary. Test in a non-production OU first.

#### Keep the topic-to-publisher inventory current

Which alarms, detectors, rules and budgets publish to which topic is not derivable after the fact from
SNS — the topic is gone. A scheduled export of `describe-alarms`, `list-publishing-destinations` and
`describe-delivery-channels` is what turns the recovery from archaeology into a restore.

#### Separate alerting topics from application topics

A single topic used for both means an environment teardown legitimately deletes the alerting path, and
the alert for it becomes routine — which is how a real one gets dismissed.

---

## 5. Recovery

### Restore Clean State

#### Verify no alarm points at a topic that does not exist

```bash
REGION="${AWS_REGION:-us-east-1}"

aws sns list-topics --region "$REGION" --query 'Topics[].TopicArn' --output text 2>/dev/null \
  | tr '\t' '\n' | sort > /tmp/sns-live-$$.txt

FAIL=0
aws cloudwatch describe-alarms --region "$REGION" --output json 2>/dev/null \
| jq -r '.MetricAlarms[], (.CompositeAlarms // [])[]
    | . as $a
    | (($a.AlarmActions // []) + ($a.OKActions // []))[]
    | select(startswith("arn:aws:sns:")) | "\($a.AlarmName)\t\(.)"' \
| while IFS="$(printf '\t')" read -r NAME ARN; do
    [ -z "$ARN" ] && continue
    grep -qxF "$ARN" /tmp/sns-live-$$.txt \
      && echo "[OK] $NAME" \
      || echo "[FAIL] $NAME -> ${ARN##*:} still missing"
  done
rm -f /tmp/sns-live-$$.txt
```

#### Verify every subscription is confirmed

```bash
REGION="${AWS_REGION:-us-east-1}"
TOPIC="${1:?topic ARN}"

aws sns list-subscriptions-by-topic --topic-arn "$TOPIC" --region "$REGION" --output json 2>/dev/null \
| jq -r '.Subscriptions[]
    | if .SubscriptionArn == "PendingConfirmation"
      then "[FAIL] \(.Protocol)  \(.Endpoint) — NOT confirmed; this endpoint receives nothing"
      else "[OK] \(.Protocol)  \(.Endpoint)" end'
```

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"
NAME="detection-test-alarm-$$"

# Deliberately include "alarm" in the name so the alerting-topic rule is the one exercised. Creating
# and deleting a throwaway topic touches nothing real.
ARN="$(aws sns create-topic --name "$NAME" --region "$REGION" --query 'TopicArn' --output text 2>/dev/null)"
[ -n "$ARN" ] && echo "[OK] created $ARN"

sleep 10
aws sns delete-topic --topic-arn "$ARN" --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] deleted — expect the CRITICAL alerting-topic alert, not a P4"

# And the idempotency point, which is the source rule's blind spot: this call succeeds against a
# topic that no longer exists and produces an identical CloudTrail event.
aws sns delete-topic --topic-arn "$ARN" --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] deleted AGAIN, successfully — proving a success is not evidence the topic existed"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Was the topic a CloudWatch alarm action or a security notification target? | It is the whole severity, and CloudWatch reports nothing when the target is gone. |
| Did the ARN ever exist in the topic inventory? | `DeleteTopic` is idempotent, so a sprayed guess produces the same successful event. |
| Was the topic recreated under the same name? | The ARN is derived from account, region and name, so the same name restores every alarm without editing one. |
| Which subscriptions were lost, and are they confirmed again? | Email and HTTP/S endpoints need their owners to accept, so recovery is not in the responder's hands. |
| Did the principal act after the deletion? | A topic deleted before the activity it would have reported is the ordering that matters. |
| Was the access policy restored? | A recreated topic has SNS's default policy, so GuardDuty and Config cannot publish until the grant is back. |

### Recommended Guardrails

**Run a heartbeat through the alerting topic.** It is the only control that detects this without
depending on the deletion event, and it catches the quieter variants too.

**Recreate under the same name.** The ARN is deterministic, so the same name repairs every reference
at once; a different name means editing every alarm.

**Keep the topic-to-publisher inventory.** After the deletion, SNS cannot tell you what published to
the topic — nothing can.

**Separate alerting topics from application topics.** Sharing them makes a legitimate teardown delete
the alerting path, and the alert for it becomes routine.

**Alert on the refused case.** The source rule's error filter hides the attempt that the permissions
caught, which is the one clean signal this technique produces.

### Technique Reference

**T1685 — Disable or Modify Tools.** Verified live at https://attack.mitre.org/techniques/T1685/ on
2026-08-31. Removing the channel that carries security notifications impairs the tooling without
touching the tooling itself.

**T1489 — Service Stop.** Verified live 2026-08-31. It covers the availability half — the application
notifications that also stopped.

Any currency check that tests only reachability passes it, which is why IDs have to be
checked against their names.

AWS references relied on throughout, all verified 2026-08-31:

- `DeleteTopic` — "Deletes a topic and all its subscriptions", and "This action is idempotent, so
  deleting a topic that does not exist does not result in an error":
  https://docs.aws.amazon.com/sns/latest/api/API_DeleteTopic.html
- CloudWatch alarms — "CloudWatch doesn't test or validate the actions that you specify, nor does it
  detect any ... Amazon SNS errors resulting from an attempt to invoke nonexistent actions":
  https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html

Service-wide verified behaviour shared by the `sns.*` playbooks authored against it is in
`../_ground-truth/sns.md`.

### Residual Risk

**The alerting gap outlives the response.** Recreating the topic is fast; getting every email and
HTTP/S subscriber to confirm again is not, and the path is not restored until they do.

**Nothing reports the gap while it exists.** Alarms show as healthy throughout, so the only evidence
is the inventory comparison in Query 2 or a heartbeat that failed to arrive.

**A successful deletion may have deleted nothing.** Idempotency means the event count is an upper
bound on damage, and separating real deletions from sprayed guesses needs an inventory that predates
the incident.

**Publishers other than CloudWatch are easy to miss.** GuardDuty publishing destinations, Config
delivery channels, Security Hub and Budgets do not appear in `describe-alarms`, and each has to be
checked separately.
