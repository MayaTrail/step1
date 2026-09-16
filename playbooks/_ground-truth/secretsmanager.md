# AWS Secrets Manager — verified service behaviour

Audited 2026-08-30 against AWS documentation. Every claim below is quoted or directly derived from
a cited page. Shared by every `secretsmanager.*` playbook; do not restate it in each one.

Sources:
- https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html
- https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
- https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CancelRotateSecret.html
- https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
- https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html

---

## 1. Every Secrets Manager call is a management event — there are no data events to buy

AWS states plainly: "AWS CloudTrail records **all** API calls for Secrets Manager as events."

There is no data-plane/control-plane split here. `GetSecretValue` and `BatchGetSecretValue` — the
calls that actually disclose credentials — are recorded in every account with a trail, at no extra
cost and with no configuration.

This is the opposite of S3 and DynamoDB, where the equivalent read operations are data events that
are off by default. Any `secretsmanager.*` playbook can therefore state its coverage without the
"if data events were purchased" caveat that those services require.

## 2. Secret values are never in the log

`GetSecretValue` returns `SecretString` or `SecretBinary` in its **response**, and CloudTrail does
not record Secrets Manager response elements containing the value. AWS's own warning is about the
request side: "Do not include sensitive information in request parameters because it might be
logged."

So the log answers *which secret was read, by whom, and when* — never *what the value was*. A
responder cannot confirm from CloudTrail alone that a specific credential was disclosed; they can
only confirm that the call that discloses it succeeded. Treat a successful `GetSecretValue` as
disclosure.

## 3. `ListSecrets` returns metadata, and the metadata is the reconnaissance product

The response carries `Name`, `ARN`, `Description`, `Tags`, `RotationEnabled`, `RotationRules`,
`LastAccessedDate`, `LastChangedDate` and `LastRotatedDate` — and no secret value.

Each of those is useful to an actor before they retrieve anything:

| Field | What it tells an actor |
|---|---|
| `Name` / `Description` | Which systems exist — `prod-payments-db`, `stripe-live-key` |
| `Tags` | Environment, owner, criticality, often verbatim |
| `RotationEnabled: false` | Which stolen values will stay valid indefinitely |
| `LastAccessedDate` | Which secrets are live and which are abandoned |
| `LastRotatedDate` | How long the current value has already been in use |

A rule that treats listing as harmless because "no value was returned" has misread what the call
returns.

## 4. `DeleteSecret` denies access immediately and destroys later

The two halves of this call are usually conflated:

- **Recovery window.** Minimum 7 days, default 30. Secrets Manager stamps a `DeletionDate` and the
  secret can be recovered with `RestoreSecret` at any point before it.
- **`ForceDeleteWithoutRecovery: true`.** No window, no `RestoreSecret`, gone. It cannot be combined
  with `RecoveryWindowInDays` in the same call.

The trap is in between: **"When a secret is scheduled for deletion, you cannot retrieve the secret
value."** The outage starts the moment the call succeeds, not thirty days later. Every consumer
calling `GetSecretValue` begins failing immediately, so a scheduled deletion is an availability
incident on the spot regardless of the window.

Replicas are the exception in the other direction: "When you delete a replica, it is deleted
immediately."

## 5. Cancelling rotation can block rotation from being restarted

`CancelRotateSecret` "turns off automatic rotation, and if a rotation is currently in progress,
cancels the rotation." Turning it back on means calling `RotateSecret` — but AWS warns that
cancelling mid-rotation "can leave the `VersionStage` labels in an unexpected state", leaving an
orphaned `AWSPENDING` version, and that "**failing to clean up a cancelled rotation can block you
from starting future rotations**."

So the response to this technique is not one call. It is: find the orphaned version with
`ListSecretVersionIds`, clear `AWSPENDING` with `UpdateSecretVersionStage`, then `RotateSecret`.
Skipping the cleanup produces a rotation that silently refuses to start.

## 6. Four different calls change which value is operative

Staging labels track versions: `AWSCURRENT` is what `GetSecretValue` returns by default,
`AWSPREVIOUS` is the version before it, `AWSPENDING` is a rotation in flight.

| Call | How it changes `AWSCURRENT` |
|---|---|
| `UpdateSecret` | Writes a new version, moves `AWSCURRENT` to it |
| `PutSecretValue` | Writes a new version, moves `AWSCURRENT` to it |
| `UpdateSecretVersionStage` | **Writes nothing.** Moves `AWSCURRENT` to a version that already exists |
| Rotation | Stages `AWSPENDING`, then promotes it to `AWSCURRENT` |

`UpdateSecretVersionStage` is the quiet one: an actor who once had a value staged can make it
operative again without calling any write API. A rule that watches only `UpdateSecret` sees one of
the four.

Whenever `AWSCURRENT` moves, Secrets Manager automatically moves `AWSPREVIOUS` to the version it
came from.

**Old versions are retained, and that is the recovery lever.** Secrets Manager "keeps 100 of the most
recent versions, but it keeps all secret versions created in the last 24 hours." So `AWSPREVIOUS` is
one version deep, but the versions behind it are still reachable by `VersionId` — recovery from a
tampered secret is `ListSecretVersionIds` followed by `GetSecretValue --version-id`, not a race
against the next rotation.

The quota is the other edge: writing more than once every ten minutes creates versions faster than
Secrets Manager removes them, and the secret eventually hits its version limit.

## 7. Lowercase event names in this source set cannot fire

`deletesecret` and `updatesecret` appear as `eventName` values in the source rules. CloudTrail emits
`DeleteSecret` and `UpdateSecret`. On a case-sensitive field the lowercase forms match nothing. This
is the same defect class seen across the wider source set — see `dynamodb.md` §5.

## 8. `sessionIssuer.userName` is the role name, not the session

For an assumed role, `userIdentity.sessionContext.sessionIssuer.userName` holds the **role** name.
Every concurrent session of that role shares it. Grouping a threshold by that field therefore counts
all sessions of a role together — twenty sessions with one denial each look identical to one session
with twenty.

The discriminating value is the session name: the second `/`-separated segment of
`userIdentity.arn` after `assumed-role/`. Two rules in this source set group the same service by
different keys with no stated reason.

## MITRE currency, verified 2026-08-30

| ID | Name | Status |
|---|---|---|
| T1526 | Cloud Service Discovery | live |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | live |
| T1485 | Data Destruction | live |
| T1489 | Service Stop | live |
| T1098 | Account Manipulation | live |
| T1556 | Modify Authentication Process | live |
| T1565.001 | Data Manipulation: Stored Data Manipulation | live |

`T1110 — Brute Force` is mapped by one source rule to `AccessDenied` bursts. Brute force is guessing
credentials. An `AccessDenied` from Secrets Manager is returned to a principal whose credential
already worked and whose **authorization** failed, so the technique does not apply and the tactic
label of Initial Access is wrong in the same way — the actor is already inside.

`T1552 — Unsecured Credentials` is mapped by the listing rules. Secrets Manager is a credential store
being used as designed; nothing about it is unsecured. `T1555.006` is the technique for retrieving
from it.
