# Detection Note — T1486 (Data Encrypted for Impact)

**Signal:** `PutKeyPolicy` — the one route to unreadable data that has no window and no service-side
undo.

## Two logic defects that partly cancel

**The negation is inverted.** The rule ends `NOT bypassPolicyLockoutSafetyCheck:"false"`. That
parameter is optional, so on an ordinary call it is **absent** — not present-and-false. `NOT
field:"false"` is therefore true for every ordinary call, and the rule fires on all of them.

**The `policyName` clause is a no-op that also drops events.** AWS: "The only valid value is
`default`." It can never exclude a policy by name, but it does require the field to be present, so
callers who omit the optional parameter are silently dropped.

The first defect makes the rule fire on everything; the second narrows it back to callers who passed
`--policy-name`. The alert volume looks plausible while the rule detects neither what it claims nor a
stable subset of it — which is why neither defect was noticed.

## What the rule is reaching for is real

`BypassPolicyLockoutSafetyCheck: true` has one documented purpose: "only when you intend to prevent
the principal that is making the request from making a subsequent `PutKeyPolicy` request on the KMS
key." Correcting the negation is all it takes to get that signal.

## The case the rule never reaches

`PutKeyPolicy` **replaces** the policy; it does not merge. A principal is removed by being left out —
no distinct event, no diff, only the new document.

And key-policy access is not something IAM can compensate for:

> "Unless the key policy explicitly allows it, you cannot use IAM policies to allow access to a KMS
> key. Without permission from the key policy, IAM policies that allow permissions have no effect."

So a submitted policy without the `arn:aws:iam::<account>:root` statement removes IAM-delegated
access for the entire account in one call, and no IAM change restores it. `kms_key_policy_no_root`
tests for that directly.

## Response levers

**Read the submitted document, not the event name.** Everything that matters is in
`requestParameters.policy`, and it is raw JSON on the request side — the percent-encoded convention
applies to response elements, not here.

**Key policies are Regional.** A sweep in one region may be one of several, and a multi-Region key's
replicas each carry their own policy.

**This is the one path with no window.** `DisableKey` reverses instantly, `ScheduleKeyDeletion` has 7
to 30 days, and imported material can be re-imported by whoever holds it. A key policy that locks
everyone out is recoverable only through AWS Support.

**MITRE:** the source maps `T1565 — Data Manipulation`. Removing key access alters no data; the
ciphertext is byte-identical. `T1486 — Data Encrypted for Impact` (verified live 2026-08-30).
`T1531 — Account Access Removal` was considered and set aside: it concerns accounts, not resource
keys.

**GuardDuty:** no finding type covers KMS key-policy changes.

**Files here:**
- `sigma_t1486.yml` — four documents: the lockout bypass with the negation corrected (critical), a
  submitted policy with no account-root statement (high), `kms_key_policy_changed` as the
  informational base rule with no `policyName` clause, and a three-keys-in-thirty-minutes correlation
  (high).
- `kql_t1486.kql` — tests the submitted document for the root statement and for external accounts,
  and flags a policy stripped to a single statement by its length.

Full response procedure is in `../PLAYBOOK.md`.
