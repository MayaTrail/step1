# Detection Note: T1136.003 (Create an IAM User with an Admin Policy)

**Signal:** `iam:CreateUser` followed by an admin grant and `CreateAccessKey`,
by the same principal, within minutes.

**Naming discrepancy worth knowing:** the technique is called "inline admin
policy", but `attack.py` uses a **managed** policy (`AttachUserPolicy` with
`AdministratorAccess`), not inline `PutUserPolicy`. Both variants are covered
here, an attacker can use either, and a rule watching only one misses half.

**Content, not event names.** The original rule matched all seven routine IAM
user-lifecycle events with a bare `condition: selection`, firing on every
onboarding, key rotation and offboarding while inspecting neither which policy
was attached nor the sequence. `ListAccessKeys`, `DeleteAccessKey`,
`DetachUserPolicy` and `DeleteUser` are dropped, the last three are the
attacker's own cleanup or ordinary offboarding.

## Two admin paths

| Path | Event | How to match |
|---|---|---|
| Managed | `AttachUserPolicy` | `requestParameters.policyArn` against the admin ARN list |
| Inline | `PutUserPolicy` | Decode `policyDocument`, match `"Action":"*"` |

The inline path **requires a decode step**: `policyDocument` is URL-encoded in
the raw event, so a substring match on `"Action":"*"` fails against the raw
field (quotes become `%22`, the asterisk `%2A`).

## Nested response paths

Two fields that silently return `null` if the flat path is used:

```
CreateUser       -> responseElements.user.userName
CreateAccessKey  -> responseElements.accessKey.accessKeyId
```

Both matter for triage: the first identifies the user created, the second is
the credential you must disable.

## Sequence vs single event

The admin grant alone is worth a `critical` alert. The **sequence**,
create → grant → issue key, is the unambiguous backdoor fingerprint and
distinguishes a net-new backdoor from a privilege escalation on an existing
user. The verdict logic separates those two cases, because they call for
different response: one user gets deleted, the other gets its privileges
reverted and its owner contacted.

**Teardown ordering note:** a user cannot be deleted while policies remain
attached and keys remain active. Detach, delete keys, then delete the user.

**Guardrail lever:** `iam:PolicyARN` is a real condition key, an SCP can deny
attaching specific admin policy ARNs while permitting ordinary policy
management.

**Error strings:** IAM denials surface as `AccessDenied` /
`AccessDeniedException`. Not `Client.`-prefixed like EC2.

**MITRE:** T1136.003 (*Create Account: Cloud Account*) is precise, no caveat.

**Severity:** manifest MEDIUM; IR view **High**, a standing admin backdoor
with its own credentials.

**GuardDuty:** `Persistence:IAMUser/UserPermissions`, confirm the exact
finding-type string against your GuardDuty configuration before relying on it
in automation.

## Tuning the allowlist

The rule ships `:role/REPLACE-ME-*` placeholders, not defaults. They match
nothing, so an unedited rule has no exclusions at all and alerts on the routine
activity it is supposed to ignore.

Derive the real list from your own trail. The principals that show up
repeatedly, across weeks rather than once, are your automation:

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-90d +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
  --start-time "$START" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | .userIdentity.arn' | \
  sort | uniq -c | sort -rn
```

Keep the recurring service and pipeline roles. Leave out anything human unless
it is a documented break-glass path, since a human name on the allowlist is a
standing hole in the rule.

Re-check the list when provisioning changes. A retired pipeline role left in
place is dead weight; a new one missing from it produces the false-positive
wave that gets a rule muted.

## Why the Sigma and the KQL disagree

The Sigma rule filters by caller identity, using the allowlist above. The KQL
does not filter by identity at all. It keys on the create-user, grant-admin,
issue-credentials sequence against one target user inside ten minutes.

That is deliberate, not an oversight. The KQL needs no knowledge of your role
names, so it is useful on the first day in an account nobody has profiled yet.
The cost is that an actor who spreads those three steps across hours falls
outside the bin.

Deploy either, or both. Do not expect them to fire on the same set of events,
and do not treat a disagreement between them as a bug.

**Files here:**
- `sigma_t1136.003.yml`, five documents: managed admin attach (`critical`),
  inline admin policy (`critical`), the `temporal_ordered` backdoor sequence
  (`critical`), and two base rules (`low`). The inline rule needs a pipeline
  that URL-decodes `policyDocument`.
- `kql_t1136.003.kql`, covers both admin paths and the sequence in one query,
  with the correct nested response paths.

Full response procedure is in `../PLAYBOOK.md`.
