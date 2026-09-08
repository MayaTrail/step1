# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One rule: Image Vulnerability Scan Disabled |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project. The rule
excluded a single named human principal by ARN; that value is redacted in the extract and the defect
it represents is described in `../../_ground-truth/ecr.md` §3.

**The rule cannot fire.** It matches `eventName:"putimagescanningconfiguration"`; CloudTrail emits
`PutImageScanningConfiguration`, and on a case-sensitive field the lowercase form matches nothing.
This is the second event name in the ECR set spelled in lowercase, alongside two identity-type
values.

**And it covers one setting of one tier.** ECR offers two scanning types:

| Type | Configured by | Coverage |
|---|---|---|
| **Basic** | `PutImageScanningConfiguration`, **per repository** | AWS native CVE database, **OS packages only**, manual or scan-on-push |
| **Enhanced** | `PutRegistryScanningConfiguration`, **registry-wide** | Amazon Inspector, OS **and language** packages, scan-on-push and **continuous** rescanning |

The rule watches the first. The registry-level API is not covered anywhere in the source pack.

**The registry-level switch is the one that destroys evidence.** AWS: *"Switching between Enhanced
scanning and Basic scanning will cause previously established scans to no longer be available. You
will have to set up your scans again."* So moving Enhanced → Basic discards every existing finding
across the whole registry in one call — while scanning remains nominally **enabled**. `scanOnPush`
may still read true afterwards, and a console check looks healthy. A rule testing `scanOnPush: false`
sees none of it.

**Archiving is a third path and changes no scanning configuration at all.** AWS: *"Archived images
cannot be scanned. Archived images must be restored before they can be scanned."* That is recorded
as a residual gap rather than closed, because no scanning-configuration event accompanies it.

**MITRE:** the source maps this to `T1578 — Modify Cloud Compute Infrastructure`, and ECR is a
registry rather than compute. `T1685 — Disable or Modify Tools` is the correct mapping: an image
scanner is a security tool, and AWS's own description of that technique covers *"endpoint detection
and response (EDR) tools, intrusion detection systems (IDS), antivirus, logging agents, sensors"*.
Note there is **no** cloud-security-tool sub-technique — `T1685.001` is Windows Event Log — so the
parent is the mapping. Verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case. Kept apart from
`../../ecr.stealth.malicious-image-pushed/` because disabling a control and using the gap are different
acts with different responses; the ordered pair between them ships here as a correlation.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `ecr.*` playbook is in `../../_ground-truth/ecr.md`, audited 2026-08-30.
§2 covers the two scanning tiers and the finding-loss on switching.
