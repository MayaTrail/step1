# Detection Note: T1552.005 (Retrieve EC2 Windows Password Data)

**Signal:** `ec2:GetPasswordData` called at rate by a single principal,
especially against nonexistent or unexpected instance IDs.

**Why occurrence alone is not the signal:** retrieving a Windows administrator
password is a normal, documented operation. Any rule that alerts 1:1 on this
event will fire on routine provisioning and be muted within a week. The
deployable detections threshold on *rate* and split on `errorCode`.

**Discriminators:**

| Observation | Reading |
|---|---|
| `errorCode` absent, at volume | Mass credential retrieval, passwords disclosed |
| `Client.InvalidInstanceID.NotFound` at volume | Instance-ID enumeration (guessing, no inventory) |
| `Client.UnauthorizedOperation` | Permission probing |

A burst can be both: an actor who probes 40 IDs and lands on 3 real Windows
hosts shows a high NotFound ratio *and* real disclosures. Treat any
`Succeeded > 0` as retrieval first, regardless of the ratio.

**Error-string caveat:** EC2 writes CloudTrail `errorCode` with a `Client.`
prefix. The unprefixed form (`InvalidInstanceID.NotFound`) is the *boto3*
`Error.Code` seen in `attack.py`; a CloudTrail rule keyed on it matches
nothing. The Sigma uses `errorCode|contains` to tolerate both, confirm the
exact string against a sample event before deploying.

**MITRE note:** T1552.005 is canonically *Unsecured Credentials: Cloud Instance
Metadata API*, which describes IMDS access rather than this EC2 control-plane
call. The mapping is inherited from the upstream technique catalogue and is
imprecise; it is retained here for traceability.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1552.005.yml`, four documents: two base rules (`level: low`, not for
  direct alerting) and the two `event_count` correlations that are the actual
  detections.
- `kql_t1552.005.kql` - Sentinel / Log Analytics threshold query with triage
  fields projected. Not valid CloudWatch Logs Insights.

Full response procedure, including the CLI hunt queries and the containment
sequence, is in `../PLAYBOOK.md`.
