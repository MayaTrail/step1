# Superseded aggregates

Directories here are **not** playbooks and are not part of the deliverable. Each one is an
aggregated playbook that covered several unrelated use cases in a single document, and that has
since been decomposed into atomic directories — one use case per playbook, per authoring rule B1.

They are kept only so the decomposition is auditable: a reviewer can check that every source rule
in the aggregate found a home, and that nothing was dropped in the split. The checker skips
underscore-prefixed directories, so nothing here is counted or scored.

## `aws.exfiltration.s3-bucket-public-exposure` — decomposed 2026-08-30

Seven source rules in one 1,206-line playbook, spanning three tactics. They did not belong
together: two of them cannot make a bucket public at all, and one of them detects a *hardening*
event. Where each went:

| Source rule | Now lives in | Why it is its own use case |
|---|---|---|
| Public Access Block Has Been Deleted | `s3.exfiltration.public-access-block-deleted` | The configuration removed wholesale — a different event from a flag change, and the source rule matched the SDK name so it could never fire |
| Public Access Block Has Been Removed | `s3.exfiltration.public-access-block-removed` | A flag lowered. Two of the four flags expose data immediately and two only permit a future write; the source rule ORed all four at one severity |
| Public Access Block Has Been Created/Modified | `s3.stealth.public-access-block-created-or-modified` | A *hardening* event. Defence evasion rather than exfiltration: its value is as the closing half of a lower-act-restore pair |
| Access Logging Has Been Disabled | `s3.stealth.access-logging-disabled` | Defence evasion, different tactic and different response. Carried along only because it shared a service |
| Bucket Policy Has Been Made Public | `s3.exfiltration.bucket-policy-made-public` | Exposure by policy. Its only predicate was a field AWS does not emit |
| Bucket ACL Has Been Configured | `s3.exfiltration.bucket-acl-configured` | Exposure by ACL — a separate mechanism with separate evidence, where a live read is not authoritative |
| Bucket Policy Has Been Deleted | `s3.impact.bucket-policy-deleted` | Cannot make a bucket public. Grouping it with exposure sent the responder to a procedure that finds nothing |

The cross-atom relationships the aggregate was implicitly carrying are now explicit as Sigma
`correlation` documents inside the relevant atoms — a lowered gate paired with the write it would
have refused, a lowered guardrail paired with its restoration, a policy deletion paired with a
public write. Each lives in the atom whose response procedure it triggers.

## `aws.defense-evasion.cloudtrail-logging-tampered` — decomposed 2026-08-30

Five source rules in one playbook, spanning two tactics. Where each went:

| Source rule | Now lives in | Why it is its own use case |
|---|---|---|
| Trail Logging Stopped | `cloudtrail.stealth.trail-logging-stopped` | Undone with one call. The refused attempt — AWS rejects `StopLogging` outside the home Region — is the earlier and higher-fidelity signal the source rule filtered out |
| Trail Deleted | `cloudtrail.impact.trail-deleted` | Irreversible for the configuration, harmless to the log files. AWS is explicit that the bucket and its contents survive, which inverts the responder's first assumption |
| Trail Modified | `cloudtrail.stealth.trail-modified` | The only one of the three that leaves every health check green. Also the only one whose real mechanism — `PutEventSelectors` — the source rule did not match |
| No Logs From AWS CloudTrail | `cloudtrail.stealth.no-logs-received` | A symptom rated above its own causes, and an absence rule inside an event-driven engine. Respecified as a scheduled check, with the delivery-path causes (bucket, lifecycle, KMS key) as the actual detections |
| Audit Logging Configuration Accessed | `cloudtrail.discovery.audit-configuration-accessed` | Discovery, not defence evasion. Nothing to contain; its value is the correlation with the other four |

The pack rated the symptom P1 and every cause P2 or P3 — the ordering is reversed in the atoms,
because the causes arrive first and are actionable.

## `aws.privilege-escalation.iam-managed-policy-escalation` — decomposed 2026-08-30

Seven source rules — three alerting, four building blocks — covering three techniques that share
only the word "policy". Where each went:

| Source rule | Now lives in | Why it is its own use case |
|---|---|---|
| SetDefaultPolicyVersion | `iam.privilege-escalation.default-policy-version-reverted` | Grants permissions while carrying none — no `policyDocument` on the request at all, so the other two rules in this pack are structurally blind to it |
| CreatePolicyVersion - Overly Permissive Policy | `iam.privilege-escalation.policy-version-overly-permissive` | Reads a document the other two do not have. Splits live from dormant on `setAsDefault`, which the source never reads |
| Policy Escalation (flow) + Admin Policy Attached + Attach{User,Role,Group}Policy | `iam.privilege-escalation.admin-policy-attached` | **Merged**: one operation against the three principal types IAM has, with one response. Blast radius is a severity dimension, not a use case |

The merge test was applied rather than assumed: the five attach rules share a response and merge;
the two version rules have different evidence and different remediations and do not.

## `aws.initial-access.sg-remote-management-open` — decomposed 2026-08-30

Six source rules covering inbound and outbound firewall changes as one playbook. Where each went:

| Source rule | Now lives in | Why |
|---|---|---|
| Ingress Rule Open to 0.0.0.0/0, Security Group Opened for Remote Management, Ingress Rule Was Added, Ingress Rule Was Revoked | `sg.initial-access.remote-management-open` | **Merged** — one operation at increasing specificity, plus the revoke that closes the pair |
| Egress Rule Was Added, Egress Rule Was Revoked | `sg.exfiltration.egress-rule-opened` | Different tactic, different response, and an inverted baseline: AWS creates every security group with an allow-all outbound rule, so "egress opened" is usually a restored default rather than a weakening |

The ingress rules read `requestParameters.cidrIp`, which exists only in the flat request form and
cannot express IPv6 at all — in most estates the console, CLI and SDKs emit the structured
`ipPermissions` form, so those rules have never fired. The shipped KQL counts flat-form usage so a
reviewer can confirm that against their own account in one query.
