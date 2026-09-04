# Detection Note — T1685 (Disable or Modify Tools)

**Signal:** image vulnerability scanning turned off — at a repository, or across the registry in a
way that leaves it looking enabled.

## The rule cannot fire

It matches `eventName:"putimagescanningconfiguration"`. CloudTrail emits
`PutImageScanningConfiguration`, so on a case-sensitive field it matches nothing. This is the second
lowercase event name in the ECR set, alongside two lowercase identity-type values.

## It also covers one setting of one tier

| Type | Configured by | Coverage |
|---|---|---|
| **Basic** | `PutImageScanningConfiguration`, per repository | OS packages only, manual or scan-on-push |
| **Enhanced** | `PutRegistryScanningConfiguration`, registry-wide | Inspector: OS **and language** packages, plus **continuous** rescanning |

The source rule watches the first. The registry-level API appears nowhere in the pack.

## The registry switch destroys evidence while looking healthy

> *"Switching between Enhanced scanning and Basic scanning will cause previously established scans
> to no longer be available. You will have to set up your scans again."*

Moving Enhanced → Basic discards every existing finding across the whole registry in one call. And
scanning stays **enabled** throughout: `scanOnPush` may still read true, the console looks fine, and
a rule testing `scanOnPush: false` sees nothing. Coverage silently drops from OS-plus-language with
continuous rescanning to OS-only.

## Three states all present as "scanning is on"

- Registry switched to Basic — findings gone, scanning enabled, coverage reduced.
- `scanOnPush` true under Basic with no manual scans — nothing scanned after the first push.
- Image **archived** — *"Archived images cannot be scanned"* — and no scanning configuration changed
  at all.

Confirm from findings, not configuration: `describe-image-scan-findings` on a specific digest is the
only check that distinguishes them.

## Response levers

**Read the registry configuration, not just the repository's.** The per-repository setting is the
one the source rule watches and the less consequential of the two.

**Disabled-then-pushed is the ordering that matters.** An image arriving after scanning was turned
off carries no finding, and nothing downstream has a reason to question it. The reverse order is an
ordinary configuration change.

**A clean scan is not an integrity check.** Scanning reports known CVEs in packages; it does not
detect an implanted backdoor. Disabling it matters because it removes a control and signals intent —
not because scanning would have caught the implant. That is
`../../ecr.stealth.malicious-image-pushed/`.

**Re-enabling does not rescan what arrived in the gap.** Under Basic, scanning happens on push.
Images that entered while it was off need a manual scan, and there is no automatic backfill.

**MITRE:** the source maps this to `T1578 — Modify Cloud Compute Infrastructure`, and ECR is a
registry rather than compute. `T1685 — Disable or Modify Tools` is correct — an image scanner is a
security tool, and AWS's own description of that technique names EDR, IDS, antivirus and sensors.
There is **no** cloud-security-tool sub-technique: `T1685.001` is Windows Event Log, so the parent is
the mapping. Verified live 2026-08-30.

**GuardDuty:** no finding type covers ECR scanning configuration. Enhanced scanning is Amazon
Inspector rather than GuardDuty, so disabling it removes Inspector coverage and produces no GuardDuty
signal at all.

**Files here:**
- `sigma_t1685.yml` — five documents: `ecr_repository_scanning_disabled` (high),
  `ecr_registry_scanning_changed` (high, the API the source pack watches nowhere),
  `ecr_scanning_config_changed` and `ecr_image_pushed_any` (informational base rules), and a
  `temporal_ordered` correlation for scanning-disabled-then-image-pushed (critical).
- `kql_t1685.kql` — separates the repository setting from the registry switch, flags a move to
  Basic as evidence loss, and lists the three states that all present as "scanning is on".

Full response procedure is in `../PLAYBOOK.md`.
