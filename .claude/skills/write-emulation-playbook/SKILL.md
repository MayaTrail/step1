---
name: write-emulation-playbook
description: Writes the six-phase IR PLAYBOOK.md and the matching detections/ rule set (sigma + kql + note) for a single atomic emulation. Enforces the detection-quality rules that keep rules deployable instead of noisy. Use for emulation-level playbooks under emulations/<name>/; use write-playbook instead for per-API PB-AWS-* playbooks.
argument-hint: [path to an emulation dir, e.g. emulations/aws_persistence_iam_backdoor_user]
user-invocable: true
allowed-tools: Read, Grep, Glob, Bash, WebSearch, Write, Edit
---

This skill produces **two coupled artifacts** for one emulation:

1. `<emulation>/PLAYBOOK.md` — a six-phase incident-response playbook
2. `<emulation>/detections/` — `sigma_<technique>.yml`, `kql_<technique>.kql`,
   `detection_note_<technique>.md`

They must agree. The playbook's §2 explains *why* the detection logic is what
it is; the `detections/` files are that logic, deployable. Shipping a good
playbook next to a noisy rule is the specific failure this skill exists to
prevent.

**Not to be confused with `write-playbook`**, which generates the per-API-call
`PB-AWS-<SERVICE>-<Action>-01.md` family under `playbooks/aws/`. Different
artifact, different audience. This one is per *emulation*.

---

## Step 1 — Read the emulation before writing anything

Read all four, in this order:

```
Read <emulation>/MANIFEST.py        # tier, severity, MITRE mapping, display name
Read <emulation>/attack.py          # the ACTUAL API calls, params, error handling
Read <emulation>/infra/__main__.py  # what exists before the attack runs
Read <emulation>/detections/        # whatever rules ship today
```

Then read the format reference:

```
Read emulations/ambersquid/PLAYBOOK.md
```

That file is the structural bar. Mirror its skeleton.

**Facts you must extract from `attack.py`, not assume:**

- Every API call, with its exact request parameters
- Every exception it catches — those error codes become detection logic
- Concrete counts (how many instances / secrets / users it touches). Detection
  thresholds must fire on these; see rule 35.

**Do not proceed on assumption.** If you cannot confirm a field path, an event
source, or whether a call is management- or data-plane, verify it against AWS
documentation. An unverified assumption about `bedrock:InvokeModel` once
inverted an entire detection thesis and required a full rewrite.

## Step 2 — Audit the shipped rules honestly

Most shipped `detections/` files are auto-derived and share the same defect:
`eventName` matched against a list with `condition: selection`, no threshold,
no content inspection.

Classify what you find, in the playbook's own words:

| Verdict | Meaning |
|---|---|
| **Broken** | Cannot fire correctly, or fires on the wrong events entirely |
| **Noisy** | Fires correctly but so often it will be muted within a week |
| **Signal-inverted** | Bundles the attacker's *cleanup* or a benign read as a trigger |
| **Good** | Genuinely deployable — say so plainly and extend rather than replace |

The last category is real and rare. Do not manufacture criticism of a rule
that is already correct.

## Step 3 — Write PLAYBOOK.md

Follow this skeleton exactly:

1. `# IR Playbook: <NAME> — <one-line characterization>`
2. `## Classification` — table: Incident Type, Threat Actor, Attribution,
   Platform, Severity, MITRE Tactics, MITRE Techniques
3. `## 1. Preparation` — Prerequisites Before This Incident, under bold
   subheads: Logging & Visibility / Alerting (must be pre-configured) /
   Response Tooling / Known IOC Baselines
4. `## 2. Identification`
   - `### Detection Triggers (prioritized)` — split into
     `#### HIGH-CONFIDENCE — Always Indicate Compromise` and
     `#### MEDIUM-CONFIDENCE — May Indicate Compromise`, each a table with
     columns Priority (P0–P3) | Event / Signal | Source | MITRE
   - `### Detection Rule Quality Notes` — a table of Issue | Impact |
     Correction for the shipped rules, then the corrected rule logic
   - `### Key Investigation Queries` — numbered `#### Query N — <purpose>`
     bash blocks using real `aws cloudtrail lookup-events` / `aws logs
     filter-log-events` + `jq`, with inline `#` comments
5. `## 3. Containment` — `### Immediate Actions (first 15 minutes)`, numbered
   `#### Step N — <action>`. **Ordering matters**: restore logging, disable
   credential, revoke sessions, kill compute, isolate. Disable before delete —
   preserve evidence.
6. `## 4. Eradication` — `### Remove Attacker Access` + `####` subsections
7. `## 5. Recovery` — verification blocks printing `[OK]` / `[FAIL]` / `[!]`
8. `## 6. Lessons Learned` — Root Cause Analysis table (Finding | Contributing
   Control Failure), Recommended Guardrails (SCP snippets, least privilege,
   detection improvements), Known IOCs table

Conventions: `---` between top-level sections; shell vars UPPERCASE with
`<placeholder>` values; every destructive command guarded by an existence
check; multi-region sweeps loop `aws ec2 describe-regions`; commands
copy-pasteable, never pseudocode.

## Step 4 — Write the detections/ trio

Read the canonical shapes first:

```
Read .claude/skills/write-emulation-playbook/reference/detection-templates.md
```

**`sigma_<technique>.yml`** — usually multi-document:
- base rule(s) at `level: low`, carrying `name:`, explicitly *not for direct
  alerting*
- the `correlation:` document(s) that are the real detection
- keep the original rule's `id:` on the first document so history is traceable
- a header comment stating what was wrong with the original and why

**`kql_<technique>.kql`** — the deployable log-platform query. Must have a time
bound, a real discriminator, and a `Verdict` column an analyst can triage from.
State the dialect: Sentinel/Log-Analytics KQL is **not** CloudWatch Logs
Insights.

**`detection_note_<technique>.md`** — the reasoning: what the signal is, which
field is the discriminator, the traps, MITRE caveats, severity, and a pointer
to `../PLAYBOOK.md`.

## Step 5 — Run the pre-flight checks

These are not optional. Every one exists because it was missed and caught in
review.

```
Read .claude/skills/write-emulation-playbook/reference/authoring-rules.md
```

Then validate the Sigma mechanically:

```bash
python .claude/skills/write-emulation-playbook/scripts/validate_sigma.py "<emulation>/detections/*.yml"
```

It checks YAML parsing, that every `correlation.rules` entry resolves to a real
`name:`, UUID format, id uniqueness, and bare `condition: selection` at
medium-or-above severity.

Manual checks the script cannot do:

- [ ] **Field paths verified** against a real CloudTrail event shape — not
      guessed. Create-style IAM responses nest (`responseElements.accessKey.accessKeyId`).
- [ ] **Every `<...-from-Query-N>` placeholder** appears in Query N's *final*
      output, including through any `jq group_by | map({...})` stage
- [ ] **Every "from Query N" cross-reference** points at a query that actually
      produces that value
- [ ] **KQL `has`/`has_any` operands** are pure alphanumeric — anything
      punctuated (CIDRs, paths, ARNs, commands with spaces) needs `contains`
- [ ] **Sigma selection blocks are siblings** under `detection:`, not nested
- [ ] **Two keys in one selection block can co-occur on a single event** — if
      not, they must be OR'd sibling blocks
- [ ] **Thresholds fire on the emulation's own counts** from `attack.py`
- [ ] **No `<placeholder>` bare in a shell `for ... in`** word list

## Step 6 — Report

State plainly:

- What was wrong with the shipped rules, per rule
- Any MANIFEST mismatch (severity, MITRE technique name or mapping) — **report,
  do not silently fix**; MANIFESTs are usually out of scope
- Anything you could not verify, flagged as unverified rather than asserted

---

## Output quality standards

- Written like a senior incident responder, not an AI. No filler, no
  restating the obvious.
- **State limitations plainly.** "Sigma cannot count array length inside a
  single event; the volume detection is the KQL" is more useful than a rule
  that silently fails to convert.
- **Never invent a correlating signal.** Verify follow-on telemetry exists
  before building a rule on it.
- **Label dialects honestly.** Say which engine each query targets.
- Placeholders that need local values (account IDs, role names) must be
  commented as such — `# REPLACE with your org account IDs`.
- Every threshold gets a "tune to your baseline" note. Thresholds are the
  first thing a deploying team has to change.
- **No vendor or product attribution** in any generated content.
