# AWS KMS — verified service behaviour

Audited 2026-08-30 against AWS documentation. Every claim below is quoted or directly derived from
a cited page. Shared by the `kms.*` playbooks authored against it; do not restate it in each one.

Sources:
- https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
- https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html
- https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteImportedKeyMaterial.html
- https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
- https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html

---

## 1. There are four ways to make ciphertext unreadable, and they are not equivalent

| Call | Effect | Reversible |
|---|---|---|
| `DisableKey` | Key unusable | Instantly, with `EnableKey` |
| `ScheduleKeyDeletion` | Key unusable, destroyed after 7–30 days | With `CancelKeyDeletion`, before the date |
| `PutKeyPolicy` | Specific principals lose access; the key is untouched | By restoring the policy — if you can still call `PutKeyPolicy` |
| `DeleteImportedKeyMaterial` | Key unusable **immediately** | Only by re-importing **the same key material** |

The last one has no waiting period at all. AWS: it "deletes the key material... making the KMS key
temporarily unusable", moving the key to `PendingImport`, and "to restore the usability of the KMS
key, reimport the same key material."

"Temporarily" assumes you have the material. For a key created with `Origin: EXTERNAL` by someone
else, only they do — which makes this the fastest and least recoverable of the four, and the only one
with no window in which to react.

## 2. `Origin: EXTERNAL` means AWS never holds the key material

`CreateKey` with `Origin: EXTERNAL` creates a key with **no key material**. The creator then calls
`GetParametersForImport` and `ImportKeyMaterial` to supply their own.

The consequence for a defender: the material protecting the data exists outside AWS, in the hands of
whoever imported it. Every other KMS key type keeps material that "never leaves AWS KMS unencrypted".

## 3. `PolicyName` has exactly one valid value, so filtering on it is a false negative

AWS: "The name of the key policy. If no policy name is specified, the default value is `default`. **The
only valid value is `default`.**"

A detection clause of `requestParameters.policyName:"default"` therefore excludes nothing — but it
does require the field to be **present**. Callers who omit the optional parameter produce a
`requestParameters` block without it, and the clause silently drops those events. A filter that looks
protective is a false-negative source.

## 4. `BypassPolicyLockoutSafetyCheck` is absent, not false, when unused

The default is `false` and AWS's guidance is blunt: "Setting this value to true increases the risk
that the KMS key becomes unmanageable. Do not set this value to true indiscriminately." It exists for
one purpose — "when you intend to prevent the principal that is making the request from making a
subsequent `PutKeyPolicy` request on the KMS key."

Because it is optional, it is **missing from `requestParameters` entirely** on an ordinary call. A
rule written as `NOT bypassPolicyLockoutSafetyCheck:"false"` therefore matches every ordinary call:
the field is not `"false"`, it is not there at all. The correct test is for the value `true` being
present.

The same parameter exists on `CreateKey`, where it produces a key that is unmanageable from birth.

## 5. A key policy is authoritative, and IAM cannot compensate for it

AWS: "Every KMS key must have exactly one key policy." And the sentence that decides the response to
any key-policy incident:

> "Unless the key policy explicitly allows it, you cannot use IAM policies to allow access to a KMS
> key. Without permission from the key policy, IAM policies that allow permissions have no effect."

The asymmetry is complete: an IAM policy can **deny** access to a key without the key policy's
involvement, but it can never **grant** it. So a `PutKeyPolicy` that omits the
`arn:aws:iam::<account>:root` statement removes IAM-delegated access for every principal in the
account at once, and no IAM change restores it.

`PutKeyPolicy` **replaces** the policy; it does not merge. A principal is removed by being left out,
which produces no distinct event and no diff in the log — only the new document.

Two further properties matter during a response:

- **Key policies are Regional**, unlike IAM policies. A multi-Region key's replicas each carry their
  own.
- The account root user "is the only principal that cannot be deleted unless you delete the AWS
  account", which is why the default policy names it and why removing that statement is the
  lockout.

## 6. The canonical AWS ransomware pattern uses a key the victim does not own

Re-encrypting S3 objects or EBS volumes with a KMS key held in the **attacker's** account, then
revoking the grant, leaves the data intact and unreadable. No key is created in the victim account,
so an in-account `CreateKey` rule sees nothing.

The detectable artifact is on the data side: objects or volumes whose `KMSKeyId` names an account
that is not yours. The in-account equivalent is §2 — an `Origin: EXTERNAL` key whose material the
actor imported and can delete.

## 7. `createkey` is not an event name

CloudTrail emits `CreateKey`. Two rules in this source set match the lowercase form and neither can
fire. Same defect class as `dynamodb.md` §5.

## 8. Multi-Region keys widen the blast radius by design

`CreateKey` with `MultiRegion: true` produces a key that `ReplicateKey` can copy into other regions,
sharing key ID and key material. A policy change or a material deletion on the primary is not
confined to the region it happened in.

## MITRE currency, verified 2026-08-30

| ID | Name | Status |
|---|---|---|
| T1486 | Data Encrypted for Impact | live |
| T1485 | Data Destruction | live |
| T1489 | Service Stop | live |
| T1531 | Account Access Removal | live |

`T1565 — Data Manipulation` is mapped by one source rule to key-policy changes. Removing access to a
key alters no data — the ciphertext is byte-identical before and after. What changes is whether
anyone can read it, which is `T1486`.
