# Detection Note: T1555 (Retrieve a High Number of Secrets Manager Secrets via Batch)

**Signal:** a single principal disclosing many distinct secrets in a short
window, via `BatchGetSecretValue`, via looped `GetSecretValue`, or both.

**Count secrets, not calls.** Severity for this technique scales with the
number of secrets disclosed. One `BatchGetSecretValue` call can return 20
secrets, so event-counting understates the incident by an order of magnitude.

**The counting trap:** `BatchGetSecretValue` *also* emits one per-secret
`GetSecretValue` event. Counting distinct `requestParameters.secretId` on
`GetSecretValue` alone is therefore complete and self-deduplicating. Summing
`GetSecretValue` events with an expanded `secretIdList` from the batch event
double-counts by roughly 2x. Every query here counts the single source.

**Enumeration vs retrieval:** `ListSecrets` is routine and high-frequency
(consoles, IaC, inventory tooling). It is correlation context only, never a
standalone trigger. The original rule ORed it with the batch API, which both
flooded the queue and destroyed the distinction.

**Don't watch only the batch API:** an attacker looping `GetSecretValue`
achieves the same outcome, and every pre-2023 tool does exactly that. The
volume rule covers both.

**Denial filtering is load-bearing:** the base rule for the volume correlation
filters `errorCode: null`. Without it, a principal racking up 20 `AccessDenied`
responses trips the same alert as a successful bulk disclosure, a probe and a
breach must not share a severity.

**Error strings:** Secrets Manager errors are *not* `Client.`-prefixed the way
EC2 errors are, and denials surface two ways depending on where they are
evaluated, an IAM-policy denial as `AccessDenied`, a resource-policy denial as
`AccessDeniedException`. Match both, plus `ResourceNotFoundException` and
`DecryptionFailure`. Confirm the exact strings against a real denied event in
your account.

**Severity:** the manifest rates this MEDIUM; the IR view is **High**, the
technique discloses live secret plaintext.

**GuardDuty:** no finding type specific to this technique.

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
  --lookup-attributes AttributeKey=EventName,AttributeValue=BatchGetSecretValue \
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
does not filter by identity at all. It keys on retrieval volume, more than
fifteen distinct secrets read by one principal inside ten minutes.

That is deliberate, not an oversight. The KQL needs no knowledge of your role
names, so it is useful on the first day in an account nobody has profiled yet.
The cost is that a patient actor reading a few secrets an hour stays under the
threshold.

Deploy either, or both. Do not expect them to fire on the same set of events,
and do not treat a disagreement between them as a bug.

**Files here:**
- `sigma_t1555.yml`, three documents: the batch-API rule (`high`), the
  `value_count` volume correlation (`high`), and its base rule (`low`, not for
  direct alerting).
- `kql_t1555.kql`, the volume detection for backends without Sigma
  correlation support. Same logic.

Full response procedure is in `../PLAYBOOK.md`.
