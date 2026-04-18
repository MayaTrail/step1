---
name: write-campaign
description: Reads an emulation script, extracts the ordered API call chain, looks up existing standalone playbooks in index.json, and generates two campaign-level playbooks — chronological and alert-driven (StopLogging-first). Requires standalone playbooks to already exist.
argument-hint: [path-to-emulation-script e.g. apt/scarleteel_emulation/attack.py]
user-invocable: true
allowed-tools: Read, Grep, Glob, Write, Edit, Bash
---

## Step 1: Load the Emulation Script

Read the emulation source file to understand the full attack flow:

```
Read $ARGUMENTS
```

If the file does not exist, tell the user and stop. Do not guess at the attack chain.

## Step 2: Extract Ordered API Calls and Phases

From the emulation code, extract **every distinct AWS API call** in execution order. Group them into attack phases based on the code structure (functions, comments, sequential blocks).

For each API call, record:
- **Phase number and name** (e.g., Phase 1: Initial Access, Phase 2: Reconnaissance)
- **AWS service** (e.g., `iam`, `s3`, `cloudtrail`, `secretsmanager`)
- **API call** (e.g., `ListUsers`, `StopLogging`, `GetSecretValue`)
- **The standalone playbook ID** it maps to: `PB-AWS-[SERVICE]-[APICall]-01`

Also extract from the code:
- Source IPs used (if hardcoded or parameterized)
- Principals / roles involved
- Timing relationships between phases
- Any host-level activity (not AWS API — e.g., cryptominer deployment, iptables, Docker commands)
- The **highest-signal event** — the single API call most likely to trigger an alert (typically `StopLogging`, `CreateUser` from compute, or `GetSecretValue` on prod secrets)

Present the full ordered list to the user before proceeding.

## Step 3: Check Standalone Playbook Coverage

Read the playbook registry:

```
Read playbooks/index.json
```

For each API call extracted in Step 2, check if a matching standalone playbook exists (match on `api_call` field). Report coverage:

```
## Standalone Playbook Coverage

| # | Phase | API Call | Standalone Playbook | Status |
|---|---|---|---|---|
| 1 | Phase 1 | sts:GetCallerIdentity | PB-AWS-STS-GetCallerIdentity-01 | ✅ EXISTS |
| 2 | Phase 2 | iam:ListUsers | PB-AWS-IAM-ListUsers-01 | ✅ EXISTS |
| 3 | Phase 3 | ec2:DescribeInstances | — | ❌ MISSING |
```

**If any API calls are missing standalone playbooks:**
- List all missing API calls
- Tell the user: "Run `/write-playbook` for the simulation first, or I can generate only the campaign playbooks for the API calls that have coverage."
- Ask if they want to proceed with partial coverage or stop

**Do not generate standalone playbooks in this skill.** That is the job of `/write-playbook`.

## Step 4: Read Standalone Playbook Frontmatter

For each standalone playbook that EXISTS, read its frontmatter to extract:
- `required_inputs` — what data this playbook needs
- `provided_outputs` — what data this playbook produces

This builds the **data flow chain**: output of one playbook feeds into the next.

```
Read playbooks/aws/<service>/PB-AWS-[SERVICE]-[APICall]-01.md
```

Only read the frontmatter (first ~15 lines) — do not read the full playbook content.

## Step 5: Determine Campaign Metadata

From the emulation code and the extracted API calls, determine:

1. **Campaign name** — derive from the emulation directory or filename (e.g., `scarleteel_emulation` → `SCARLETEEL`)
2. **Campaign version** — if prior versions exist in `playbooks/campaigns/`, increment (e.g., V1 exists → this is V2)
3. **MITRE ATT&CK tactics covered** — aggregate from all chained playbooks
4. **Highest-signal event** — the single API call that anchors the alert-driven playbook (pick the one with zero/lowest false positive rate: `StopLogging` > `CreateUser` from compute > `DeleteUser` > `GetSecretValue` from compute > everything else)
5. **Filename pattern**: `<CAMPAIGN_NAME>-V<N>-CHRONOLOGICAL.md` and `<CAMPAIGN_NAME>-V<N>-STOPLOGGING-FIRST.md`

## Step 6: Generate Chronological Campaign Playbook

Write to `playbooks/campaigns/<CAMPAIGN_NAME>-V<N>-CHRONOLOGICAL.md`.

### Structure

**Frontmatter:**

```yaml
---
id: aws-campaign-<name>-v<n>
campaign: <CAMPAIGN_NAME>
required_inputs:
  - INCIDENT_START_TIME
  - ACCOUNT_ID
  - REGION
  - COMPROMISED_INSTANCE_ID
provided_outputs:
  - ATTACKER_SOURCE_IP
  - COMPROMISED_ROLE_ARN
  - <other outputs aggregated from all chained playbooks>
chained_playbooks:
  - PB-AWS-<each standalone in order>
---
```

**Body — MUST include all of these sections:**

### Section 1: Governance & Metadata

| Field | Content |
|---|---|
| Playbook Name | `<Campaign Name> Campaign Response (Chronological)` |
| Type | Campaign-Level (chains per-API-call playbooks) |
| Scenario | One paragraph describing the full attack chain from initial access to final objective |
| Trigger | Compound trigger: "Any TWO or more of:" followed by the top 3-5 most suspicious events |
| MITRE ATT&CK Tactics | Aggregated from all phases |

Include:
- **Key Differences table** if a prior version exists (v1 vs v2 comparison)
- **SLA table** (Acknowledge / Contain / Resolve targets)
- **Severity matrix** with compound conditions spanning multiple phases
- **Related Playbooks** links to the alert-driven version and any prior/next campaign versions

### Section 2: Attack Timeline & Phase Walkthrough

For each phase, write:

```markdown
### Phase N: <Phase Name> — <MITRE Tactic>

**What happens:** One paragraph describing what the attacker does in this phase and WHY.

**API calls in this phase:**

| Time | API Call | Standalone Playbook | Key Indicator |
|---|---|---|---|
| T+0s | iam:ListUsers | [PB-AWS-IAM-ListUsers-01](../aws/iam/PB-AWS-IAM-ListUsers-01.md) | EC2 role calling IAM recon |

**Data flow:** Outputs from this phase (`PROVIDED_OUTPUT`) feed into Phase N+1.

**Investigative focus:** What to look for in this phase — the non-obvious signals.
```

For host-level activity (not AWS API calls), document it in the relevant phase but note "No CloudTrail evidence — host forensics only."

### Section 3: Cross-Phase Correlation

- **Source IP analysis** — document all IPs used across phases (IPv4, IPv6, expected instance IP vs attacker IP)
- **Principal chain** — how the attacker's identity changes across phases (instance role → created user → bait user)
- **Timing analysis** — gaps between phases, what the attacker was doing during gaps
- **Data flow diagram** showing how `provided_outputs` chain between standalone playbooks

### Section 4: Campaign-Level Containment

Graduated response that considers the FULL campaign, not individual API calls:

| Level | Condition | Actions |
|---|---|---|
| L1 | Early detection (Phase 1-2 only) | Revoke compute role sessions |
| L2 | Mid-chain detection (Phase 3-4) | L1 + isolate EC2 + re-enable logging |
| L3 | Full compromise detected (Phase 5-6) | L2 + rotate all secrets + delete backdoor users + notify legal |

### Section 5: Recovery & Hardening

- Aggregate hardening recommendations from all chained standalone playbooks
- Prioritize by impact (P1/P2/P3)
- Include SCPs that would break the ENTIRE kill chain at the earliest phase

### Detection Rules (Sigma)

Generate 2-3 **campaign-level** Sigma rules that detect the COMBINATION of events (not individual API calls — those are in the standalone playbooks):

1. **Compound rule:** Two or more suspicious API calls from the same principal within a time window
2. **Sequence rule:** Specific attack sequence (e.g., ListUsers → CreateUser → DeleteUser within 5 minutes)
3. **Behavioral rule:** EC2 role performing IAM + SecretsManager operations (unusual service combination)

### MITRE ATT&CK Coverage Table

Full mapping of every technique across all phases.

## Step 7: Generate Alert-Driven Campaign Playbook

Write to `playbooks/campaigns/<CAMPAIGN_NAME>-V<N>-STOPLOGGING-FIRST.md`.

This playbook starts from the **highest-signal event** and works outward. It is NOT just a reordered chronological — it's a different investigation methodology.

### Structure

**No YAML frontmatter** — this is an investigation guide, not an orchestrator target.

**Opening:**

```markdown
# <Campaign Name> Incident Response — Alert-Driven Investigation

> **Start here when you get paged.** This playbook begins from the highest-signal alert
> (`<HIGHEST_SIGNAL_EVENT>`) and works backward and forward to reconstruct the full attack.
> For the chronological kill-chain walkthrough, see [<CAMPAIGN>-CHRONOLOGICAL](<file>.md).
```

**ASCII diagram** showing attack order vs investigation order (see SCARLETEEL-V2-STOPLOGGING-FIRST.md for the format).

**Steps — always in this order:**

1. **Step 0: Restore visibility** — re-enable whatever the attacker disabled (CloudTrail, GuardDuty, etc.)
2. **Step 1: Extract pivot fields** from the anchor alert (principal ARN, source IP, timestamp)
3. **Step 2: Scope the blast radius** — what permissions does the compromised principal have?
4. **Step 3: Backward pivot on principal** — what did this principal do BEFORE the alert?
5. **Step 4: Blind window analysis** — what happened AFTER the attacker blinded you? (check alternative logs: VPC Flow Logs, S3 access logs, CloudWatch, GuardDuty backlog)
6. **Step 5: Source IP pivot** — find ALL principals used from the attacker's IP (catches lateral movement)
7. **Step 6: Lateral movement detection** — check for new users, new access keys, assumed roles
8. **Step 7: Initial access reconstruction** — trace back to the entry point (IMDS, container, exposed service)
9. **Step 8: Containment decisions** — graduated response based on what you found
10. **Step 9: Evidence preservation** — forensic bucket, log export, EC2 AMI snapshot

Each step MUST have:
- Executable AWS CLI commands with `<PLACEHOLDER>` parameters
- Clear decision gates (IF/THEN) for escalation
- Links to the relevant standalone playbook for deep-dive on individual API calls

## Step 8: Update index.json

Add both new campaign playbooks to `playbooks/index.json`:

```json
"<CAMPAIGN>-V<N>-CHRONOLOGICAL": {
  "type": "campaign",
  "campaign": "<Campaign Name>",
  "service": "Multi-Service",
  "cloud": "AWS",
  "path": "campaigns/<CAMPAIGN>-V<N>-CHRONOLOGICAL.md",
  "mitre": ["<aggregated techniques>"],
  "version": "1.0",
  "required_inputs": ["INCIDENT_START_TIME", "ACCOUNT_ID", "REGION", "COMPROMISED_INSTANCE_ID"],
  "provided_outputs": ["<aggregated outputs>"],
  "chained_playbooks": ["<all standalone IDs in order>"]
},
"<CAMPAIGN>-V<N>-STOPLOGGING-FIRST": {
  "type": "campaign-alert-driven",
  "campaign": "<Campaign Name>",
  "service": "Multi-Service",
  "cloud": "AWS",
  "path": "campaigns/<CAMPAIGN>-V<N>-STOPLOGGING-FIRST.md",
  "mitre": ["<aggregated techniques>"],
  "version": "1.0",
  "required_inputs": ["INCIDENT_START_TIME", "ACCOUNT_ID", "REGION", "TRAIL_NAME"],
  "provided_outputs": ["<aggregated outputs>"]
}
```

## Step 9: Update Cross-References

Update the `### Related Playbooks` section in every standalone playbook that is part of this campaign to include a link to the new campaign playbooks.

## Step 10: Summary

Output:

```markdown
## Campaign Playbook Generation Summary

**Campaign:** <Name> V<N>
**Emulation source:** <path>
**Phases:** <N>
**API calls:** <N> total, <N> covered by standalone playbooks, <N> missing
**Generated:**
- `playbooks/campaigns/<CAMPAIGN>-V<N>-CHRONOLOGICAL.md` — <N> phases, <N> chained playbooks
- `playbooks/campaigns/<CAMPAIGN>-V<N>-STOPLOGGING-FIRST.md` — <N> investigation steps, anchor: <event>
**Updated:** `playbooks/index.json` with 2 new entries
```

## Output Quality Standards

- Campaign playbooks must read like they were written by a senior IR lead who has personally investigated this attack
- Every phase must explain the attacker's INTENT, not just the API call
- The alert-driven playbook must be usable by an oncall analyst at 3 AM who has never seen this campaign before
- All CLI commands must be copy-pastable with `<PLACEHOLDER>` parameters
- Cross-references between the two campaign playbooks must be bidirectional
- If CloudTrail logs from the emulation exist (e.g., `ct_full.json`), ground the playbook in real timestamps and IPs from those logs
- Host-level activity (miners, bots, iptables) must be documented even though it has no CloudTrail evidence
- The data flow chain (required_inputs → provided_outputs) between standalone playbooks must be explicitly documented
