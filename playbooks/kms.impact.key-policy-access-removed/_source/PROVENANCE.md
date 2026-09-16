# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One rule: Possible Key Access Removal |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

## Two logic defects that partly cancel, which is why neither was noticed

**The negation is inverted.** The rule ends
`NOT requestParameters.bypassPolicyLockoutSafetyCheck:"false"`. The parameter is **optional** and
defaults to false, so on an ordinary `PutKeyPolicy` it is not present at all — the field is not
`"false"`, it is missing. `NOT field:"false"` is therefore **true** for every ordinary call, and the
rule fires on all of them. What it meant to say is `= true`.

**The `policyName` clause is a no-op that also drops events.** AWS: "If no policy name is specified,
the default value is `default`. The only valid value is `default`." So `policyName:"default"` can
never exclude a policy by name — but it does require the field to be **present**, and callers who
omit the optional parameter produce a `requestParameters` block without it. Those events are silently
dropped.

The two defects push in opposite directions. The first makes the rule fire on everything; the second
narrows it back to callers who happened to pass `--policy-name`. The result is an alert volume that
looks plausible while the rule is detecting neither what it claims nor a stable subset of it.

## What the rule is reaching for is real and worth detecting

`BypassPolicyLockoutSafetyCheck: true` is not an ordinary parameter. AWS: "Setting this value to true
increases the risk that the KMS key becomes unmanageable. Do not set this value to true
indiscriminately," and use it "only when you intend to prevent the principal that is making the
request from making a subsequent `PutKeyPolicy` request on the KMS key." That is a defender's signal,
and correcting the negation is all it takes to get it.

**The larger case the rule does not reach at all** is a policy that simply omits the
`arn:aws:iam::<account>:root` statement. `PutKeyPolicy` **replaces** the policy rather than merging
it, so a principal is removed by being left out — no distinct event, no diff, only the new document.
And because "without permission from the key policy, IAM policies that allow permissions have no
effect", removing that statement cuts off every IAM-delegated principal in the account at once, with
no IAM change able to restore it. Covered here by testing the submitted policy for the root
statement.

**MITRE:** the source maps `T1565 — Data Manipulation`. Removing access to a key alters no data — the
ciphertext is byte-identical before and after. What changes is whether anyone can read it, which is
`T1486 — Data Encrypted for Impact`. `T1531 — Account Access Removal` was considered and set aside:
it concerns accounts, not resource keys. Both verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case. `DisableKey` is
`../../kms.impact.kms-key-disabled/` and `ScheduleKeyDeletion` is
`../../kms.impact.kms-key-scheduled-deletion/`; both remove access to a key, but each has a distinct
reversal path and its own playbook already. Key **creation** is `../../kms.impact.key-created/`. This
playbook owns the policy path, which is the only one of the four with no built-in window and no
service-side undo.

**Tier:** 1, on criterion 3 of `07-TIERS.md` — *the blast radius is not in the event*.

Service ground truth for the `kms.*` playbooks authored against it is in `../../_ground-truth/kms.md`,
audited 2026-08-30. §3 and §4 cover the two defects; §5 covers key-policy authority.
