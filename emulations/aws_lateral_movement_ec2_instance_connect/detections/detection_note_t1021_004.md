# Detection Note: T1021.004 (Usage of EC2 Instance Connect on Multiple Instances)

**Signal:** `ec2-instance-connect:SendSSHPublicKey` from a principal outside
the operator allowlist, especially to several instances, or for the `root` OS
user.

## The property that shapes everything

The pushed key is **ephemeral**: valid for roughly 60 seconds, and it leaves
**no artifact** in the instance's `authorized_keys`. Auditing host key files
after the fact finds nothing at all.

Detection therefore has to be:

- **control plane**, the `SendSSHPublicKey` call itself, and
- **network** - VPC Flow Logs showing inbound tcp/22 ACCEPT to the instance
  within ~60s of the push.

Do not send a responder to audit host keys; there is nothing there to find.

**The push is permission, not access.** On its own, `SendSSHPublicKey` proves a
key was authorised, not that anyone logged in. The Flow Log correlation is what
upgrades it to a confirmed session, and it is the highest-confidence signal
available for this technique.

## Discriminators

| Field | Reading |
|---|---|
| `userIdentity.arn` not in operator allowlist | The base signal, fires on a single instance |
| ≥2 distinct `instanceId` in 15 min | The fan-out the technique is named for |
| `instanceOSUser == "root"` | Direct privileged foothold, not a normal login |
| `eventName: OpenTunnel` | EIC Endpoint variant, see below |

**Threshold of 2, not 3.** Pushing keys to even two instances in a quarter hour
is not how administration works.

**Scope `os_users` to successful pushes.** Including denied attempts inflates
the set with users the actor never actually reached.

**The EIC Endpoint variant matters.** `OpenTunnel` reaches instances in
**private subnets** with no public IP and no bastion. A rule watching only
`SendSSHPublicKey` misses that path entirely.

**Prevention lever:** `ec2:osuser` is a real IAM condition key, you can permit
Instance Connect while forbidding key pushes for `root`.

**Error strings:** `ec2-instance-connect` errors are service-specific,
`AccessDeniedException`, `EC2InstanceNotFoundException`,
`EC2InstanceStateInvalidException`, `ThrottlingException`. They are **not**
`Client.`-prefixed like core EC2.

**Flow Log field caution:** in the **default** format, field 13 is the action
(ACCEPT/REJECT) and the last field is the log status. Custom formats reorder
these, check your format string rather than assuming positions.

**Emulation naming mismatch:** the display name says "Multiple Instances" but
`attack.py` pushes to exactly one. The fan-out rule still matters for real
incidents; just do not expect the emulation to trip it.

**MITRE note:** T1021.004 (*Remote Services: SSH*) is partly apt - EC2 Instance
Connect genuinely does use SSH, unlike SSM Session Manager. But **T1021.008**
(*Direct Cloud VM Connections*) names this mechanism explicitly and is more
precise. Both tags are carried.

**Severity:** manifest MEDIUM; IR view **High**, the technique yields a real
interactive SSH shell.

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
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendSSHPublicKey \
  --start-time "$START" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | .userIdentity.arn' | \
  sort | uniq -c | sort -rn

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=OpenTunnel \
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
does not filter by identity at all. It keys on fan-out, the number of distinct
instances one principal pushes keys to inside fifteen minutes.

That is deliberate, not an oversight. The KQL needs no knowledge of your role
names, so it is useful on the first day in an account nobody has profiled yet.
The cost is that a single push to a single instance still surfaces, but only
at the weakest verdict.

Deploy either, or both. Do not expect them to fire on the same set of events,
and do not treat a disagreement between them as a bug.

**Files here:**
- `sigma_t1021_004.yml`, three documents: non-operator key push (`high`), the
  fan-out `value_count` correlation (`critical`), and the EIC Endpoint tunnel
  rule (`high`).
- `kql_t1021_004.kql`, all signals in one query with root/fan-out/tunnel
  verdicts, plus the Flow Log correlation guidance.

Full response procedure is in `../PLAYBOOK.md`.
