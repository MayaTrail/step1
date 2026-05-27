# SCARLETEEL 2.0 — Incident Response Playbook

Based on the real-world SCARLETEEL campaign (Sysdig Threat Research Team, 2023).
Reference: https://sysdig.com/blog/cloud-breach-terraform-data-theft/

---

## Overview

SCARLETEEL is a sophisticated cloud attack that chains container exploitation
with AWS credential theft to achieve lateral movement, data exfiltration, and
persistent access via a Lambda backdoor.

| Attribute            | Value                                |
|----------------------|--------------------------------------|
| Threat Actor         | Unknown (financially motivated)      |
| First Observed       | 2023                                 |
| Target Environment   | Kubernetes / ECS on AWS              |
| Primary Goal         | Crypto mining + IP theft             |
| Phases               | 6                                    |
| Estimated Duration   | 20 minutes (emulation)               |
| Auto-Destroy TTL     | 4 hours                              |

---

## Phase 1 — Initial Access

**Technique:** Container RCE via exposed web application  
**MITRE:** T1190 — Exploit Public-Facing Application

### What the attacker does
Exploits a Remote Code Execution vulnerability in a publicly accessible
containerised application.  In the original campaign, a misconfigured
Jupyter notebook and a custom web shell were the initial vectors.

### Detection signals
- Unexpected outbound network connections from the container
- Process execution anomalies (shell spawned from web server process)
- CloudTrail: `GetCallerIdentity` calls from an unusual IP

### IR steps
1. Isolate the affected container — detach from the network or stop it.
2. Capture a memory dump and container filesystem before termination.
3. Review container runtime logs for the RCE payload and source IP.
4. Check for any lateral tooling downloaded (curl, wget, nc binaries).

---

## Phase 2 — Credential Access

**Technique:** IMDSv1 credential theft  
**MITRE:** T1552.005 — Cloud Instance Metadata API

### What the attacker does
From inside the compromised container, makes an HTTP GET to the EC2 Instance
Metadata Service at `169.254.169.254/latest/meta-data/iam/security-credentials/`
to retrieve the IAM role's temporary credentials (access key, secret key,
session token).  IMDSv1 does not require a PUT pre-flight, making it trivially
accessible from any process inside the instance.

### Detection signals
- CloudTrail: `GetCallerIdentity` from an IP that is not the EC2 instance IP
- Unusual `AssumeRole` calls shortly after the initial credential issue
- VPC Flow Logs: outbound requests to `169.254.169.254` from the container

### IR steps
1. Immediately revoke the stolen credentials:
   `aws iam delete-access-key` or disable the instance profile role session.
2. Rotate the EC2 instance profile — detach and re-attach a new role.
3. **Remediation:** Enable IMDSv2 (`HttpTokens=required`) on all EC2 instances
   to prevent unauthenticated metadata access.
4. Search CloudTrail for all API calls made with the stolen credentials
   (filter by `userIdentity.sessionContext.sessionIssuer.arn`).

---

## Phase 3 — Discovery

**Technique:** IAM and resource enumeration  
**MITRE:** T1069.003 — Cloud Groups / T1526 — Cloud Service Discovery

### What the attacker does
Uses the stolen IAM credentials to enumerate attached policies, list S3 buckets,
and discover Secrets Manager secrets.  This maps the blast radius and identifies
high-value targets for lateral movement.

### Detection signals
- CloudTrail: burst of `ListBuckets`, `ListPolicies`, `ListSecrets`,
  `SimulatePrincipalPolicy` calls from a new IP/session
- GuardDuty: `Discovery:IAMUser/AnomalousBehavior` finding

### IR steps
1. Review CloudTrail for the full enumeration event sequence.
2. Identify every resource the attacker has read access to.
3. Apply least-privilege to the compromised role immediately.
4. Enable GuardDuty if not already active — it flags enumeration patterns.

---

## Phase 4 — Defense Evasion

**Technique:** Disable CloudTrail logging  
**MITRE:** T1562.008 — Impair Defenses: Disable Cloud Logs

### What the attacker does
Calls `cloudtrail:StopLogging` to disable the active trail, blinding the
defender to subsequent API activity.  In the original campaign this was done
before the most destructive actions.

### Detection signals
- CloudTrail (if still active): `StopLogging` event
- CloudWatch alarm on `StopLogging` API call (if configured)
- Gap in CloudTrail log delivery to S3

### IR steps
1. Re-enable the trail immediately: `aws cloudtrail start-logging --name <arn>`.
2. Check the S3 log bucket for the gap window and reconstruct activity from
   VPC Flow Logs and any surviving CloudTrail events.
3. **Hardening:** Create a CloudWatch alarm on `StopLogging` / `DeleteTrail`
   events.  Lock the CloudTrail S3 bucket with Object Lock to prevent deletion.
4. Consider AWS Config rule `cloud-trail-enabled` for continuous compliance.

---

## Phase 5 — Lateral Movement

**Technique:** STS AssumeRole + Terraform state exfiltration  
**MITRE:** T1078.004 — Valid Accounts: Cloud Accounts  
**MITRE:** T1530 — Data from Cloud Storage Object

### What the attacker does
Uses the over-privileged EC2 role to assume a second IAM role and then reads
the Terraform state file from S3.  The state file contains plaintext resource
ARNs, IDs, and sometimes hardcoded secrets — a complete map of the
infrastructure.

### Detection signals
- CloudTrail: `AssumeRole` from the compromised role to a second role
- `GetObject` on a Terraform state bucket from an unusual principal
- S3 server access logs: large `GetObject` download

### IR steps
1. Rotate any secrets or credentials stored in Terraform state.
2. Revoke the assumed role session.
3. Audit all roles that the compromised role can assume — apply deny policies.
4. **Hardening:** Never store plaintext credentials in Terraform state.
   Use `terraform_remote_state` with strict bucket policies.
   Enable S3 bucket versioning + MFA delete on state buckets.

---

## Phase 6 — Impact / Persistence

**Technique:** Lambda backdoor deployment  
**MITRE:** T1546 — Event Triggered Execution / T1098 — Account Manipulation

### What the attacker does
Creates a Lambda function with an over-privileged execution role to establish
persistent access that survives EC2 instance termination or credential rotation.
The Lambda can be triggered on demand to exfiltrate data or re-issue credentials.

### Detection signals
- CloudTrail: `CreateFunction` from the compromised principal
- Lambda function name matching known attacker tooling patterns
- Unusual `InvokeFunction` calls from unrecognised principals
- GuardDuty: `Backdoor:Lambda/C2Activity`

### IR steps
1. Delete the Lambda function immediately:
   `aws lambda delete-function --function-name <name>`.
2. Detach and delete the Lambda execution role.
3. Search for any Lambda aliases, event source mappings, or scheduled rules
   that could re-invoke the backdoor.
4. Review all Lambda functions in the account for unexpected recent creation.
5. **Hardening:** Apply SCP to deny `lambda:CreateFunction` except from
   approved deployment pipelines.

---

## Full Remediation Checklist

After confirming the emulation is complete, verify the following:

- [ ] CloudTrail re-enabled and delivering logs
- [ ] Stolen IAM credentials rotated / invalidated
- [ ] IMDSv2 enforced on all EC2 instances (`HttpTokens=required`)
- [ ] Terraform state bucket policies tightened (deny `GetObject` to EC2 roles)
- [ ] Lambda backdoor removed; no event source mappings remain
- [ ] GuardDuty enabled and findings reviewed
- [ ] CloudWatch alarm created for `StopLogging` / `DeleteTrail`
- [ ] All IAM roles audited for over-permissive `sts:AssumeRole` trust policies

---

## References

- Sysdig: [SCARLETEEL 2.0](https://sysdig.com/blog/scarleteel-2-0/)
- MITRE ATT&CK Cloud Matrix: https://attack.mitre.org/matrices/enterprise/cloud/
- AWS Security Best Practices: https://docs.aws.amazon.com/security/
