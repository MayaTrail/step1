# Detection Note: T1059 (Execute Malicious Code via EC2 User Data)

**Signal:** `ec2:ModifyInstanceAttribute` rewriting `userData` on an existing
instance, classically bracketed by `StopInstances` before and `StartInstances`
after, since user-data cannot be modified while an instance is running.

**Detect the write and the sequence, never the brackets alone.** `Stop` and
`Start` fire on every routine maintenance window. The original rule matched all
three event names independently, which flooded the queue while never expressing
the ordered sequence that actually defines the attack.

**`userData` is the discriminator.** A bare `ModifyInstanceAttribute` match
also catches security-group and termination-protection changes. Confirm the
exact request-parameter field name against a sample event in your account.

**IMPORTANT, this payload is usually latent, not immediate.** Default
cloud-init runs user-data **once per instance-id**. A plain stop/start does
**not** re-run injected user-data. For the injected code to execute, one of
these must hold:

- the payload uses `#cloud-boothook`, or overrides module frequency to
  `always`
- cloud-init state was cleared on the host (`cloud-init clean`)
- the volume/AMI is used to launch a *fresh* instance (new instance-id)

Treat a user-data rewrite as a **staged** root-code-execution capability. That
makes it no less serious, it will fire on the next rebuild, but it changes
the triage question from "did it run?" to "when will it run, and has anything
already rebuilt?"

**Field-shape gotcha for the sequence query:** `instanceId` is a direct request
parameter on `ModifyInstanceAttribute`, but on `Stop`/`StartInstances` it is
nested under `instancesSet.items[]`. The grouping key must normalise both or
the sequence never assembles.

**Error strings:** EC2 CloudTrail errors carry a `Client.` prefix. Two are
worth watching: `Client.UnauthorizedOperation`, and
`Client.IncorrectInstanceState`, the latter is a user-data modify attempted
against a *running* instance, i.e. an actor who did not know to stop it first.

**Relationship to the read technique:** this is the WRITE inverse of
`aws_discovery_ec2_download_user_data`. An actor who reads user-data for
credentials and one who writes it for execution use adjacent APIs; correlating
both against one principal is a strong signal.

**Severity:** manifest MEDIUM; IR view **High**, the technique yields
arbitrary code execution as root on the instance.

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
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyInstanceAttribute \
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
does not filter by identity at all. It keys on the stop, modify-user-data,
start sequence against a single instance inside one window.

That is deliberate, not an oversight. The KQL needs no knowledge of your role
names, so it is useful on the first day in an account nobody has profiled yet.
The cost is that an actor who rewrites user-data without cycling the instance
is not caught until something else reboots it.

Deploy either, or both. Do not expect them to fire on the same set of events,
and do not treat a disagreement between them as a bug.

**Files here:**
- `sigma_t1059.yml`, four documents: the user-data write rule (`high`), the
  `temporal_ordered` sequence correlation (`high`), and the two bracketing base
  rules (`low`, never deployed standalone).
- `kql_t1059.kql`, sequence detection with the instanceId normalisation, plus
  a note on catching the write alone.

Full response procedure is in `../PLAYBOOK.md`.
