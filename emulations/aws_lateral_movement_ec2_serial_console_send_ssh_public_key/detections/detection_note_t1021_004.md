# Detection Note: T1021.004 (Usage of EC2 Serial Console to Push an SSH Public Key)

**Signal:** `ec2-instance-connect:SendSerialConsoleSSHPublicKey`, a niche API
with essentially no routine use. A **single call by a non-operator is P0**.

## What makes this different from EC2 Instance Connect

The two techniques look similar and are not. Three genuine differences:

**1. It is out-of-band.** The serial console bypasses security groups and
NACLs entirely, and the session does **not** appear in VPC Flow Logs. The
inbound-22 correlation that provides the highest-confidence evidence for
Instance Connect **does not exist here**. The control plane is the only record
that anything happened.

**2. There is an account-level gate.** Serial console access is disabled by
default and must be enabled account-wide before any key push can succeed. That
makes `ec2:EnableSerialConsoleAccess` both the earliest warning and the more
serious event of the two, it is a persistent security downgrade for **every
instance in the account**, not just the target.

Consequently the top containment action is
`disable-serial-console-access`, not anything instance-specific.

**3. A single call is already P0.** No fan-out threshold is needed to justify
escalation, though the sweep correlation is included for scope assessment.

## Operational notes

**Cleanup gotcha:** tearing down the emulation does **not** re-disable account
serial console access. Verify and disable it explicitly, or the account is left
permanently downgraded by a test.

**A blocked attempt is still an incident.** `SerialConsoleAccessDisabled` means
the account gate stopped the actor, a successful control, not a non-event. The
principal still tried and should be investigated.

**Use a long lookback.** `EnableSerialConsoleAccess` may precede the key push
by days. A 24-hour window will show the push with no explanation of how it
succeeded; the queries here use 7 days.

**Error strings:** `ec2-instance-connect` errors are service-specific,
`AccessDeniedException`, `SerialConsoleAccessDisabled`,
`SerialConsoleSessionLimitExceeded`, `ThrottlingException`. **Not**
`Client.`-prefixed like core EC2.

**MITRE note:** same caveat as EC2 Instance Connect, the manifest maps
T1021.004 (*Remote Services: SSH*), but **T1021.008** (*Direct Cloud VM
Connections*) is the precise fit. Both tags are carried. The
`EnableSerialConsoleAccess` rule additionally carries Defense Evasion.

**Severity:** manifest MEDIUM; IR view **High**, a network-bypassing console
foothold on the instance.

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
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendSerialConsoleSSHPublicKey \
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
does not filter by identity at all. It keys on the action and its outcome
alone, because serial console use is rare enough to be worth alerting on
unconditionally.

That is deliberate, not an oversight. The KQL needs no knowledge of your role
names, so it is useful on the first day in an account nobody has profiled yet.
The cost is that an account that genuinely uses the serial console for
recovery will need the identity filter added back.

Deploy either, or both. Do not expect them to fire on the same set of events,
and do not treat a disagreement between them as a bug.

**Files here:**
- `sigma_t1021_004.yml`, three documents: non-operator key push (`high`), the
  account-enable precursor (`critical`), and the fan-out correlation
  (`critical`).
- `kql_t1021_004.kql`, covers push, enable and disable together over a 7-day
  window, and distinguishes gate-blocked attempts.

Full response procedure is in `../PLAYBOOK.md`.
