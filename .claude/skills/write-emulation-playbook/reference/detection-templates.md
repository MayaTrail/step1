# Detection templates

Canonical shapes for the three `detections/` files. Copy the structure, not the
content — the discriminator is always technique-specific.

---

## Choosing the shape

Work out what actually distinguishes the attack from normal use, then pick:

| The signal is… | Use | Example |
|---|---|---|
| A rare event | Single rule, bare selection (justify it) | `EnableSerialConsoleAccess` |
| A field value inside the event | Single rule + content match | `attribute=userData`, `withDecryption=true`, admin `policyArn` |
| Volume of events | `event_count` correlation | GetPasswordData burst, Bedrock flood |
| Volume of **distinct things** | `value_count` correlation | secrets read, instances touched, distinct actions |
| An ordered sequence | `temporal_ordered` correlation | Stop → Modify(userData) → Start |
| Two things co-occurring | `temporal` correlation | login profile + privilege grant |
| A set membership (org accounts, approved layers) | **KQL only** — Sigma cannot express it | external-account trust |

If you cannot name the discriminator in one sentence, you do not have a
detection yet — go back to `attack.py`.

---

## sigma_<technique>.yml

Multi-document. Base rules are `level: low` and exist only to be referenced.

```yaml
# <Technique name> (<TID>)
#
# WHAT WAS WRONG: <one paragraph — the original rule matched X with a bare
# condition: selection, which fires on every legitimate Y>
#
# <Any structural constraint the reader must know before editing: URL-encoding,
# nested response paths, keys that cannot co-occur.>
title: <Base rule title>
id: <keep the ORIGINAL rule's id here for traceability>
name: <snake_case_name>            # referenced by the correlation below
status: experimental
description: >-
  Base rule. Fires on every <event> by design and is NOT for direct alerting —
  deploy the correlation that references it.
references:
  - <upstream technique URL>
tags:
  - attack.<tactic>
  - attack.<tid>
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: '<service>.amazonaws.com'
    eventName: '<Action>'
  success:
    errorCode: null                # matches when ABSENT = the call succeeded
  condition: selection and success
falsepositives:
  - <the legitimate case this fires on — be specific>
level: low
---
title: <The deployable detection>
id: <new uuid>
status: experimental
description: >-
  <What crossing this threshold means, in incident terms.>
tags:
  - attack.<tactic>
  - attack.<tid>
correlation:
  type: value_count                # or event_count / temporal_ordered / temporal
  rules:
    - <snake_case_name>            # must match a `name:` above
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 15                        # tune to the emulation's own counts
    field: requestParameters.<id>  # value_count only — DISTINCT things
level: high
```

**Content-inspection variant** — when the discriminator is in the event:

```yaml
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'DescribeInstanceAttribute'
    requestParameters.attribute: 'userData'    # THE discriminator
  allowlisted:
    userIdentity.arn|contains:
      - ':role/provisioning'
      - ':role/ci-'
  condition: selection and not allowlisted
```

**Two events, different field names** — must be OR'd sibling blocks:

```yaml
  update_doc:
    requestParameters.policyDocument|contains: '<account-id>'
  create_doc:
    requestParameters.assumeRolePolicyDocument|contains: '<account-id>'
  condition: selection and (update_doc or create_doc)
```

---

## kql_<technique>.kql

Requirements: a time bound, a real discriminator, triage fields projected, and
a `Verdict` column. A header comment explaining what makes it deployable.

```kql
// <Technique name> (<TID>)
//
// <Why this is the deployable form: the discriminator, and what the original
// query lacked.>
//
// Dialect: Sentinel / Azure Log Analytics KQL. NOT CloudWatch Logs Insights —
// summarize, make_set, case(), bin() and the AWSCloudTrail table do not exist
// there.
let OrgAccounts = dynamic(["111111111111"]);   // REPLACE with your org account IDs
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "<service>.amazonaws.com"
| where EventName == "<Action>"
| where isempty(ErrorCode)                     // succeeded, not merely attempted
| extend Req = parse_json(RequestParameters)   // dynamic JSON DOES need parsing
| extend Target = tostring(Req.<field>)
| summarize
    Count      = dcount(Target),               // count what measures severity
    TargetSet  = make_set(Target, 20),
    SourceIPs  = make_set(SourceIpAddress, 10),
    FirstSeen  = min(TimeGenerated),
    LastSeen   = max(TimeGenerated)
    by UserIdentityArn, bin(TimeGenerated, 10m)
| where Count > 5                              // tune to your baseline
| extend Verdict = case(
    <worst condition>,  "<WHAT IT MEANS> — P0",
    <lesser condition>, "<WHAT IT MEANS> — investigate",
    "REVIEW")
| project TimeGenerated, UserIdentityArn, Count, TargetSet, SourceIPs, Verdict
| order by Count desc
//
// WHAT THIS CANNOT SEE: <the gap — data-plane events, token counts, content —
// and where to get it instead.>
```

**Reminders that bite:**
- `contains`, never `has`, for CIDRs / paths / ARNs / anything punctuated
- `SessionIssuerUserName` is a flattened column — do not `parse_json` it
- `_GetWatchlist('Name')`, never a bare `_Name`
- `url_decode()` before matching structure inside a policy document

---

## detection_note_<technique>.md

The reasoning layer. An analyst reads this to understand *why* the rule looks
the way it does.

```markdown
# Detection Note — <TID> (<Technique name>)

**Signal:** <one sentence — what actually distinguishes this from normal use>

**<The core insight>** — the single most important thing about detecting this.
Often a constraint: the payload is latent, the content is not in CloudTrail,
the credential cannot be revoked.

## Discriminators

| Field | Reading |
|---|---|
| <field> | <what it tells you> |

## <Traps section — name it for the specific trap>

<The thing that silently breaks a rule here: URL-encoding, nested response
paths, whole-term matching, data-plane invisibility.>

**Error strings:** <the exact forms for this service>

**MITRE note:** <mapping caveat if the manifest is imprecise — state the
canonical name and why it does or does not fit>

**Severity:** manifest <X>; IR view **<Y>** — <one-line justification>

**GuardDuty:** <finding type, or "no finding type specific to this technique">

**Files here:**
- `sigma_<tid>.yml` — <N> documents: <what each is for>
- `kql_<tid>.kql` — <what it covers>

Full response procedure is in `../PLAYBOOK.md`.
```

---

## Severity calibration

Be honest, including when honesty lowers the rating. A console user with no
policy attached is genuinely Medium — say so, and say what would escalate it.

| Level | Use for |
|---|---|
| `critical` | Confirmed compromise, or a grant to any principal (`*`) |
| `high` | Durable persistence, credential disclosure, code execution |
| `medium` | Recon with a clear follow-on, capability probing |
| `low` | Base rules; corroborating context; anything expected to fire routinely |

A base rule that fires constantly by design **must** be `low`, and its
description must say it is not for direct alerting. That is what stops someone
deploying it standalone and muting the whole rule set a week later.
