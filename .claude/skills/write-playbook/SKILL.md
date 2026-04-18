---
name: write-playbook
description: Reads a simulation/emulation script, enumerates every distinct AWS API call, and generates a standalone IR playbook for each API call following the Maya Playbook Framework. Deduplicates against existing playbooks.
argument-hint: [path-to-simulation e.g. src/simulations/attach_role_policy.py or apt/scarleteel_emulation/attack.py]
user-invocable: true
allowed-tools: Read, Grep, Glob, WebSearch, Write
---

## Step 1: Load the Simulation

Read the simulation source file to understand the exact attack flow:

```
Read $ARGUMENTS
```

If the argument does not contain a path separator or file extension, try `src/simulations/$ARGUMENTS.py` as a fallback for backwards compatibility.

If the file does not exist, list available simulations with `Glob src/simulations/*.py` and `Glob apt/**/attack.py` and tell the user which paths are valid. Do not proceed without a valid simulation file.

Also read the example playbook for tone and format guidance:
```
Read .claude/skills/write-playbook/example-playbook.md
```

## Step 2: Enumerate AWS API Calls & Deduplicate

From the simulation code, enumerate **every distinct AWS API call** made via boto3. For each call, identify:
- The AWS service (e.g., `sts`, `iam`, `s3`, `kms`)
- The API call name (e.g., `AssumeRole`, `AttachRolePolicy`, `GetCallerIdentity`)
- The planned playbook ID using format `PB-AWS-[SERVICE]-[APICall]-01` (e.g., `PB-AWS-STS-AssumeRole-01`)

Present the full list to the user with planned playbook IDs.

**Deduplication check:** Read the playbook registry to check for existing playbooks:
```
Read playbooks/index.json
```

For each API call, check if an entry with a matching `api_call` field already exists in `playbooks.*.api_call`. If a playbook already exists for a given API call, report it as "SKIP (exists)" and do not regenerate it. Only generate playbooks for API calls that don't already have one.

## Step 3: Generate One Playbook Per API Call

For **each** API call that needs a new playbook, generate a complete standalone playbook in Markdown. Each playbook is a **self-contained, reusable module** — it must not depend on the context of any specific simulation.

Write each playbook to `playbooks/aws/<service>/PB-AWS-[SERVICE]-[APICall]-01.md` (service name lowercase, e.g., `playbooks/aws/iam/PB-AWS-IAM-ENUM-01.md`). Create the service subdirectory if it doesn't exist.

Each playbook MUST begin with a YAML frontmatter block (fenced by `---`) containing machine-readable metadata for orchestrator chaining:

```yaml
---
id: aws-[service]-[action]       # e.g., aws-sts-assumerole
api_call: [Service]:[Action]     # e.g., sts:AssumeRole
required_inputs:
  - <VARIABLE_NAME>              # Data needed to investigate this event
provided_outputs:
  - <VARIABLE_NAME>              # Data produced for downstream playbooks
---
```

The `required_inputs` are variables the playbook expects to be populated before execution. The `provided_outputs` are variables this playbook produces that downstream playbooks can consume. Use UPPERCASE_UNDERSCORE format for all variable names.

After the frontmatter, each playbook must contain all of the following sections:

---

### Section 1: Governance & Metadata

| Field | Instruction |
|---|---|
| **Playbook Name** | Descriptive name scoped to this single API call |
| **Playbook ID** | `PB-AWS-[SERVICE]-[APICall]-01` |
| **Version** | Start at 1.0 |
| **Scenario** | One-sentence description of the unauthorized use of this specific API call |
| **Trigger** | What fires the alert (CloudTrail event for this specific `eventName`) |
| **Severity Matrix** | Three tiers with concrete, measurable conditions: |
| | **CRITICAL:** [condition] - Action: Wake CISO & Legal immediately |
| | **HIGH:** [condition] - Action: Immediate IR team response |
| | **MEDIUM:** [condition] - Action: Next-business-day triage |
| **Prerequisites** | IAM roles needed, logs that must be enabled, tools required |
| **MITRE ATT&CK Mapping** | Technique ID, name, and tactic category for this specific API call |
| **Stakeholders** | Who must be notified (Legal, PR, CISO, Engineering) |
| **SLA Target** | Triage time in minutes |
| **Compliance** | Whether this triggers GDPR/CCPA/SOC2 reporting clocks |

### Section 2: Triage & Validation (The "Is It Real?" Gate)

**Step 2.1: Automated Enrichment**

List the exact checks an analyst must perform, scoped to this API call:
- [ ] Identity Context: Is this a privileged user? Service account? Are they on vacation?
- [ ] Asset Context: Is this Production or Dev? What data classification?
- [ ] Threat Intel: Is the source IP known malicious?
- [ ] API-call-specific enrichment checks (e.g., for `AssumeRole`: is the assumed role expected for this identity?)

Include exact CLI commands for each enrichment step.

**Step 2.2: Decision Logic (IF/THEN Gates)**

Write concrete decision branches specific to this API call:
- IF [benign condition] → Mark False Positive & Close
- IF [malicious condition] → Proceed to Containment Level [X]
- IF [ambiguous condition] → Proceed to Investigation

### Section 3: Containment Strategy (Graduated Response)

Every containment action MUST have a rollback command. Containment is scoped to blocking/reversing **this specific API action**.

| Level | Condition | Action Command (The Block) | Rollback Command (The Fix) |
|---|---|---|---|
| **L1 (Soft)** | [low-impact trigger] | [Exact CLI command] | [Exact CLI command to undo] |
| **L2 (Hard)** | [confirmed threat] | [Exact CLI command] | [Exact CLI command to undo] |
| **L3 (Nuclear)** | [worst case] | [Exact CLI command] | [Exact CLI command to undo] |

**CRITICAL CHECK:** Before executing L2 or L3, confirm the asset is NOT tagged `Critical-Production-App`.

### Section 4: Investigation & Forensics (The Deep Dive)

**4.1 Scope Assessment**
- List affected resources specific to this API call
- Check for related activity by the same identity
- Volume/impact analysis with exact CLI commands

**4.2 Root Cause Analysis**
- Provide an Athena or CloudWatch Logs Insights query filtering by this specific `eventName`
- The query must target exactly this API call in CloudTrail

**4.3 Evidence Preservation**
1. Create forensic bucket with exact CLI command
2. Enable encryption and block public access
3. Copy relevant CloudTrail logs filtered to this `eventName`

### Section 5: Recovery & Hardening

1. **Sanitize** - Rotate credentials, revoke sessions, delete compromised keys (exact CLI commands)
2. **Restore** - Steps to recover from damage this specific API call can cause
3. **Harden (The "Never Again" Fix)** - Specific preventive controls to block unauthorized use of this API call (SCPs, IAM conditions, etc.)
4. **Verify** - A test to confirm the attack vector is closed
5. **Post-Mortem** - Detection gap analysis for this specific API call

### Detection Rule (Sigma Format)

Each playbook includes exactly **one Sigma rule** detecting this specific API call:

```yaml
title: [Descriptive rule name for this API call]
id: [UUID]
status: experimental
level: [critical|high|medium|low]
description: [What this rule detects — scoped to this single API call]
author: MayaTrail
date: YYYY/MM/DD
references:
  - https://mayatrail.tech
tags:
  - attack.[tactic]
  - attack.t[technique_id]
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: [service].amazonaws.com
    eventName: [this specific API call]
  condition: selection
falsepositives:
  - [Legitimate scenarios that could trigger this]
```

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Relevance to This API Call |
|---|---|---|---|
| T1234 | [Name] | [Tactic] | [How this API call maps to this technique] |

---

## Step 4: Update the Playbook Registry

After generating all playbooks, update `playbooks/index.json` by adding a new entry for each generated playbook:

```json
"PB-AWS-[SERVICE]-[APICall]-01": {
  "api_call": "[service]:[APICall]",
  "service": "[SERVICE]",
  "cloud": "AWS",
  "path": "aws/[service]/PB-AWS-[SERVICE]-[APICall]-01.md",
  "mitre": ["T1234"],
  "version": "1.0",
  "required_inputs": ["VARIABLE_NAME"],
  "provided_outputs": ["VARIABLE_NAME"]
}
```

Read the existing `playbooks/index.json`, add the new entries to the `playbooks` object, and write it back using the Edit tool.

## Step 5: Summary Table

After generating all playbooks, output a summary table:

```
## Playbook Generation Summary for `<simulation-name>`

| # | AWS API Call | Playbook ID | Status |
|---|---|---|---|
| 1 | sts:GetCallerIdentity | PB-AWS-STS-GetCallerIdentity-01 | Generated / Skipped (exists) |
| 2 | sts:AssumeRole | PB-AWS-STS-AssumeRole-01 | Generated / Skipped (exists) |
| ... | ... | ... | ... |
```

## Output Quality Standards

- Each playbook must read like it was written by a senior incident responder, not an AI
- **Parameterization standards:**
  - All placeholders MUST use `UPPERCASE_UNDERSCORE` format: `<ACCOUNT_ID>`, `<USERNAME>`, `<ROLE_NAME>`
  - Never hardcode simulation-specific values (session names, regions, usernames) in CLI commands or investigation steps
  - Common shared variables across playbooks: `<USERNAME>`, `<ACCOUNT_ID>`, `<INCIDENT_ID>`, `<REGION>`, `<CLOUDTRAIL_BUCKET>`, `<INCIDENT_START_TIME>`, `<INCIDENT_DATE>`, `<CALLER_ARN>`
- CLI commands must be copy-pastable (use `<PLACEHOLDER>` for environment-specific values)
- Severity conditions must be measurable (">10GB", "PII detected", "public bucket"), never vague ("suspicious activity")
- The containment table must be balanced: every Action has a Rollback, no exceptions
- Sigma rules must be valid YAML that passes sigma-cli validation
- Each playbook is fully self-contained — an analyst can use it without any other playbook
