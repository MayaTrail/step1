# Detection Note — T1489 / T1486 (KMS Key Disabled)

**Signal:** `DisableKey` succeeding on a customer managed KMS key from a principal outside the
key-administration allowlist — once, or across three or more distinct keys by one principal
inside ten minutes.

**Disabling a key is the reversible half of key-based destruction, and reversibility is the
whole reason this is a separate use case from scheduled deletion.** `DisableKey` moves the key
to `Disabled`, cryptographic operations start failing with
`DisabledException: <key ARN> is disabled.`, and `EnableKey` puts it back with nothing lost.
There is no waiting period, no deadline and no irreversible step anywhere in the response. The
sibling `../../kms.impact.kms-key-scheduled-deletion/` starts a 7–30 day clock after which
every ciphertext under the key is permanently unrecoverable, so its containment is
deadline-bound and its recovery has an ordering constraint this one does not have. Same
service, same principal, same one-line API call — different response, therefore different
playbook.

**What the original rules got wrong** — there are two of them, and they are the same query at
two thresholds. Both match `eventName:"disablekey"` in **lower case**, which is not the form
CloudTrail writes; AWS's own published example carries `"eventName": "DisableKey"`. The source
set is internally inconsistent about this — its `PutKeyPolicy` rule is cased correctly while
its `disablekey`, `createkey` and `schedulekeydeletion` rules are not — so this is a defect in
these rules rather than a platform lower-casing convention, and on a case-sensitive field
match it means the rules return nothing at all. Neither rule filters to successful calls, so a
principal denied on twenty keys produces the same alert volume as one that disabled twenty.
Neither looks at who called. And the single-event rule is rated **P4**, the lowest priority in
the set, for an event that is an immediate outage for whatever depends on the key.

## The thing that does not break is the trap

AWS: when a KMS key becomes unusable the effect is "almost immediate (subject to eventual
consistency)" for **new** cryptographic operations, but the effect on **data keys already
issued** under it "is delayed until the KMS key is used again". Their worked example is an
encrypted EBS volume: the data key lives in the Nitro hardware while the volume is attached,
so disk I/O continues, nothing errors, and the failure appears only when the volume is next
attached to an instance — which may be days later, during a scaling event or an instance
replacement.

Two consequences for the response, and both are in `../PLAYBOOK.md`:

- **A quiet CloudTrail is not a clean result.** Counting `DisabledException` events after the
  disable measures what has already broken, never what is going to.
- **Re-enabling the key is the complete technical fix.** Nothing needs re-encrypting, no data
  key needs reissuing, and there is no residual cryptographic damage — which is exactly what
  is *not* true of the deletion sibling.

## Every event here is a customer managed key

AWS managed keys cannot be managed by the account that holds them: *"you cannot change any
properties of AWS managed keys, rotate them, change their key policies, or schedule them for
deletion"*. AWS owned keys are not in your account and are not auditable by you at all. So
there is no AWS-managed-key noise to filter out — and equally, no `keyManager` field on the
`DisableKey` event to filter on. `keyManager` is a `DescribeKey` response field
(`KeyMetadata.KeyManager`, values `CUSTOMER` or `AWS`), not an event field.

## Field shapes, verified against AWS's published event examples

| Field | Shape |
|-------|-------|
| `eventSource` | `kms.amazonaws.com` for every KMS operation, management plane |
| `requestParameters.keyId` | **Caller-typed** — a bare key ID, a key ARN or an alias, whatever the caller passed |
| `responseElements.keyId` | The normalised **key ARN**, flat, added by AWS in December 2022 to `DisableKey` and `EnableKey` entries even though neither API returns a value |
| `resources[].ARN` | The key ARN, with `resources[].type` = `AWS::KMS::Key`. The most reliable identity on any KMS event |

The correlation counts distinct `requestParameters.keyId` because that is the only key
identifier present on a **failed** call, and because a correlation must count a request-side
field to be portable. A caller alternating ID and ARN forms inflates the distinct count and can
never deflate it — for a volume rule that failure direction is safe.

## Response levers

**Error strings:** `DisableKey` itself throws `DependencyTimeoutException`, `InvalidArnException`,
`KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`, plus the common
`AccessDeniedException`. IAM-evaluated denials surface as `AccessDenied` without the suffix, so
match both prefix-tolerantly (A7) and confirm against a real denied event in your own trail.

The errors that matter more are the ones the *consumers* get, because they are the blast
radius: `DisabledException: <key ARN> is disabled.` for a key in `Disabled`, and — for a key in
`PendingDeletion` — **either** `DisabledException: <key ARN> is pending deletion (or pending
replica deletion).` **or** `KMSInvalidStateException: <key ARN> is pending deletion`. A
responder grepping only for `KMSInvalidStateException` misses half of the second case.

**GuardDuty:** There is **no GuardDuty finding type specific to a KMS key being disabled.** Do not build the
response on one existing.

**MITRE:** The source maps **T1486 / TA0040** — *Data Encrypted for Impact*. T1486 is live, and the
consequence framing is defensible: data becomes inaccessible and an extortion demand is the
usual next move. But the adversary encrypts nothing here, which is what T1486 describes.

The corrected primary is **T1489 — Service Stop** (Impact, TA0040), whose platform list
includes **IaaS** and whose description explicitly covers disabling a service in a cloud
environment to render it unavailable to legitimate users. That is precisely what a `DisableKey`
does: one control-plane call, reversible, and every dependent service stops. **T1486** is kept
as a second tag because the extortion reading is the reason this is alerted on at all.

For the destructive sibling the mapping is different again — see
`../../kms.impact.kms-key-scheduled-deletion/detections/detection_note_t1485.md`, which maps
**T1485 Data Destruction** with **T1490 Inhibit System Recovery** as the second reading.

**Severity:** **High**, against the source's **P4** for the single event. P4 means triage-when-convenient for
a condition that is either an active outage or an actor establishing that it can cause one. The
merged volume variant is **P0**, above the source's P3, because three keys in ten minutes has
no benign explanation that a change record cannot immediately settle.

**Files here:**

- `sigma_t1489.yml` — three documents: the disable itself (`high`, with a POPULATE allowlist),
  the denied attempt (`low`, kept deliberately so probing is never counted as impact), and a
  `value_count` correlation firing `high` at three distinct keys in ten minutes. The
  correlation is where the merged volume rule lives.
- `kql_t1489.kql` — joins each disable to the `DisabledException` errors that followed it and
  to the `EnableKey` that reversed it, so blast radius and current state are visible in one
  row, and explains why a zero in the fallout column is not a clean result.

Full response procedure is in `../PLAYBOOK.md`.
