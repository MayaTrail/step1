# Detection Note — T1059 (Execute Malicious Code via EC2 User Data)

**Signal:** `ec2:ModifyInstanceAttribute` rewriting `userData` on an existing
instance — classically bracketed by `StopInstances` before and `StartInstances`
after, since user-data cannot be modified while an instance is running.

**Detect the write and the sequence, never the brackets alone.** `Stop` and
`Start` fire on every routine maintenance window. The original rule matched all
three event names independently, which flooded the queue while never expressing
the ordered sequence that actually defines the attack.

**`userData` is the discriminator.** A bare `ModifyInstanceAttribute` match
also catches security-group and termination-protection changes. Confirm the
exact request-parameter field name against a sample event in your account.

**IMPORTANT — this payload is usually latent, not immediate.** Default
cloud-init runs user-data **once per instance-id**. A plain stop/start does
**not** re-run injected user-data. For the injected code to execute, one of
these must hold:

- the payload uses `#cloud-boothook`, or overrides module frequency to
  `always`
- cloud-init state was cleared on the host (`cloud-init clean`)
- the volume/AMI is used to launch a *fresh* instance (new instance-id)

Treat a user-data rewrite as a **staged** root-code-execution capability. That
makes it no less serious — it will fire on the next rebuild — but it changes
the triage question from "did it run?" to "when will it run, and has anything
already rebuilt?"

**Field-shape gotcha for the sequence query:** `instanceId` is a direct request
parameter on `ModifyInstanceAttribute`, but on `Stop`/`StartInstances` it is
nested under `instancesSet.items[]`. The grouping key must normalise both or
the sequence never assembles.

**Error strings:** EC2 CloudTrail errors carry a `Client.` prefix. Two are
worth watching: `Client.UnauthorizedOperation`, and
`Client.IncorrectInstanceState` — the latter is a user-data modify attempted
against a *running* instance, i.e. an actor who did not know to stop it first.

**Relationship to the read technique:** this is the WRITE inverse of
`aws_discovery_ec2_download_user_data`. An actor who reads user-data for
credentials and one who writes it for execution use adjacent APIs; correlating
both against one principal is a strong signal.

**Severity:** manifest MEDIUM; IR view **High** — the technique yields
arbitrary code execution as root on the instance.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1059.yml` — four documents: the user-data write rule (`high`), the
  `temporal_ordered` sequence correlation (`high`), and the two bracketing base
  rules (`low`, never deployed standalone).
- `kql_t1059.kql` — sequence detection with the instanceId normalisation, plus
  a note on catching the write alone.

Full response procedure is in `../PLAYBOOK.md`.
