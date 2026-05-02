## TASK: GENERATE PLAYBOOK

Generate an IR playbook in markdown following SANS PICERL.

Include ACTUAL CLI commands for every investigation and containment step — use the appropriate CLI for the platform:
- AWS: `aws` CLI commands (cloudtrail lookup-events, iam delete-access-key, etc.)
- Azure: `az` CLI commands (az monitor activity-log list, az ad user delete, etc.)
- GCP: `gcloud` commands (gcloud logging read, gcloud iam service-accounts delete, etc.)
- Okta: Okta API curl commands or Okta CLI
- GitHub: `gh` CLI or GitHub API curl commands
- M365: Microsoft Graph API calls

Reference the SPECIFIC audit events from the attack plan.

Structure:
```markdown
# IR Playbook: {APT_NAME} — {Platform}

## Classification
| Field | Value |
|-------|-------|
| Incident Type | ... |
| Threat Actor | ... |
| Platform | {aws / azure / gcp / okta / github / m365 / multi_cloud} |
| Severity | Critical |
| MITRE Tactics | ... |

## 1. Preparation
What should be in place before this incident.

## 2. Identification
### Detection Triggers (prioritized)
HIGH-CONFIDENCE: [table of audit events that ALWAYS indicate compromise]
MEDIUM-CONFIDENCE: [table of events that MIGHT indicate compromise]

### Key Investigation Queries
[Platform-appropriate CLI commands for searching audit logs]

## 3. Containment
### Immediate Actions (first 15 minutes)
[Exact CLI commands to disable compromised credentials, revoke sessions, isolate resources]

## 4. Eradication
### Remove Attacker Access
[Delete backdoor accounts, rotate credentials, revoke tokens/sessions]

## 5. Recovery
### Restore Clean State
[Re-enable security services, verify no persistence mechanisms remain]

## 6. Lessons Learned
[Link to guardrails, what would have prevented this]
```
