# Amazon ECR — verified service behaviour

Audited 2026-08-30 against AWS documentation. Every claim below is quoted or directly derived from
a cited page. Shared by every `ecr.*` playbook; do not restate it in each one.

---

## 1. `BatchGetImage` counts pulls, but does not mean image content moved

Source: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchGetImage.html

> Gets detailed information for an image. **When an image is pulled, the BatchGetImage API is called
> once to retrieve the image manifest.**

Two things follow, and they pull in opposite directions:

- **It is a fair proxy for pull count.** One call per pull, so a volume threshold on it is measuring
  roughly the right thing — better than it first appears.
- **It is not evidence that image content was transferred.** The response carries `imageManifest`
  and nothing else; the layers are referenced by digest. The bytes come from
  `GetDownloadUrlForLayer`, and a client that already has the layers cached pulls the manifest and
  downloads nothing. `BatchGetImage` is also callable simply to check whether a tag exists.

So a rule counting `BatchGetImage` answers "how many pulls" and not "how much left". Where the
question is exfiltration, `GetDownloadUrlForLayer` is the event that corresponds to data movement.

## 2. Switching scanning type destroys existing findings

Source: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html

> **Switching between Enhanced scanning and Basic scanning will cause previously established scans
> to no longer be available.** You will have to set up your scans again. However, if you switch back
> to your previous scanning type the established scans will be available.

ECR offers two scanning types:

| Type | Configured by | Frequencies |
|---|---|---|
| **Enhanced** — Amazon Inspector integration, OS *and* language packages | registry-level scanning configuration | scan on push, **continuous** |
| **Basic** — AWS native, CVE database, OS only | `PutImageScanningConfiguration` per repository | manual, scan on push |

A rule scoped to `PutImageScanningConfiguration` with `scanOnPush: false` therefore covers **one
repository-level setting of the basic tier only**. It does not see a switch from Enhanced to Basic,
which is registry-wide, silently discards every existing finding, and leaves scanning nominally
"enabled" throughout.

> **Archived images cannot be scanned.** Archived images must be restored before they can be
> scanned.

So archiving is a third way to remove an image from scanning coverage without changing any scanning
configuration.

## 3. Event-name and identity-type casing, and a single hardcoded human

Three defects run across the whole ECR source set and are recorded once here:

- **`putimagescanningconfiguration`** — CloudTrail emits `PutImageScanningConfiguration`. On a
  case-sensitive field the lowercase form matches nothing, and the rule cannot fire.
- **`userIdentity.type:"iamuser"`** — CloudTrail emits `IAMUser`. Two rules in the set use the
  lowercase form and four use the correct one, so the pack spells the same field two ways.
- **Every one of the seven rules excludes the same single named human principal by ARN.** That is a
  personal allowlist compiled into the detection logic for an entire service: if that identity is
  ever compromised or impersonated, every ECR rule is blind to it simultaneously. An allowlist
  belongs in configuration a responder can read and change, not in seven separate rule bodies.

`userIdentity.type` filtering is itself a problem beyond casing: it excludes **`AssumedRole`**,
which is what every CI/CD push and every SSO session is. In a normal estate the pushes and pulls a
detection most wants to see are exactly the ones this filter removes.

## 4. `NOT "TLSv1.3"` is an unfielded term negation

The `Repository Created` rule carries a bare `AND NOT "TLSv1.3"` clause. It is not bound to a field,
so it excludes any event whose serialised record contains that string anywhere — which is the TLS
version of the API call itself. Modern SDKs negotiate TLS 1.3 by default, so the clause excludes
much of the traffic it is meant to inspect, and it excludes attacker and administrator equally. There
is no reading of this clause under which it improves the rule.

## 5. Destruction has three shapes and only two are immediate

- `BatchDeleteImage` — removes specified images now.
- `DeleteRepository` with `force: true` — removes the repository **and the images in it** now.
- `PutLifecyclePolicy` — expires images on a schedule. Nothing is deleted at the time, so this is
  destruction on a timer and the quietest of the three; a policy with an aggressive `countNumber`
  or `sinceImagePushed` removes images days later with no further event naming them.

They share a response — establish what was destroyed, whether it is recoverable, and what depended
on it — which is why they are one use case rather than three.

---

## MITRE currency, verified 2026-08-30

| ID | Status | Name | Tactic |
|---|---|---|---|
| `T1525` | live | Implant Internal Image | Persistence |
| `T1485` | live | Data Destruction | Impact |
| `T1530` | live | Data from Cloud Storage | Collection |
| `T1578` | live | Modify Cloud Compute Infrastructure | Defense Evasion |
| `T1484` | live | Domain or Tenant Policy Modification | Privilege Escalation |
| `T1685` | live | Disable or Modify Tools | Defense Impairment |

The source pack's mappings are mostly wrong in a consistent direction — they name the *place* rather
than the *act*. `T1525 — Implant Internal Image` is correct for pushing a malicious image and wrong
for creating an empty repository, which implants nothing. `T1484 — Domain or Tenant Policy
Modification` is wrong for an ECR lifecycle policy, which is a retention rule and not a tenant
policy. `T1578 — Modify Cloud Compute Infrastructure` is applied to three ECR rules and ECR is a
registry, not compute. `T1685` is the right mapping for disabling image scanning, since the
scanner is a security tool.

**Correction, 2026-08-30.** An earlier version of this file named `T1685.001` as "Disable or Modify Cloud Security Tools". That sub-technique does not exist. `T1685`'s real sub-techniques are `.001` Windows Event Log, `.002` Cloud Log, `.003` Modify or Spoof Tool UI, `.004` Linux Audit System Log, `.005` Clear Windows Event Logs and `.006` Clear Linux or Mac System Logs. Disabling a cloud security service maps to the **parent** `T1685`, whose description covers "endpoint detection and response (EDR) tools, intrusion detection systems (IDS), antivirus, logging agents, sensors".
