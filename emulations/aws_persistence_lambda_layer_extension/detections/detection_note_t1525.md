# Detection Note — T1525 (Persist via Lambda Layer)

**Signal:** `lambda:PublishLayerVersion` followed by
`UpdateFunctionConfiguration` attaching that layer — an attacker's code
injected into a function's execution environment.

**The allowlist comparison is the whole detection.**
`UpdateFunctionConfiguration` fires on every memory, timeout and environment
change, so "a layer was attached" is only interesting once you know the layer
is not one of yours. The original rule inspected nothing, and additionally
bundled `DeleteLayerVersion` — teardown, not persistence.

**Layer ARN structure** (`:`-delimited):

```
arn:aws:lambda:REGION:OWNER_ACCOUNT:layer:NAME:VERSION
                     ^field 5             ^7    ^8
```

The **owner account** is the strongest allowlist key — it survives layers being
renamed or re-versioned.

## What the layer actually does — check before assessing impact

| Path in the layer | Behaviour |
|---|---|
| `/opt/extensions/…` | A true **extension** — auto-launched by Lambda at INIT, runs whether or not the function imports anything |
| `python/…` | A **code layer** — runs only if imported, or if it shadows a module the function already imports |

**This emulation ships `python/` despite "extension" in its name**, so its
payload is conditional rather than automatic. That materially changes the
impact assessment, and it is worth checking the path before escalating.

`sys.path` order is `/var/task` (function code) → `/opt/python/site-packages` →
`/opt/python` → runtime. A layer beats the runtime's own libraries but **never**
the function's own modules.

## Containment gotcha

> `UpdateFunctionConfiguration --layers` **replaces the entire layer list.**

It does not remove one entry. You must re-specify every legitimate layer you
intend to keep — otherwise you strip the function's real dependencies while
removing the malicious one, turning an intrusion into an outage.

## Investigation notes

**Layer content is not in CloudTrail.** Download and scan it:
`aws lambda get-layer-version-by-arn --arn <arn>`, then fetch the presigned
`Content.Location` URL.

**Response:** if the layer's code ran, treat the function's **execution role**
credentials as compromised — the attacker's code executed with them. Also
`delete-layer-version` and remove any `AddLayerVersionPermission` cross-account
share.

**Invoke is data-plane.** To establish whether the function ran during the
exposure window, see the synchronous-invoke `requestParameters`-null trap
documented in the `lambda_backdoor_function` detection note.

**Guardrail limitation:** there is no IAM condition key for a specific layer
ARN, so you cannot write a policy permitting layer attachment but restricting
*which* layer. Control the principals who may call
`UpdateFunctionConfiguration` instead.

**Portability nit (set-wide):** the CLI examples in the playbooks use GNU
`date -u -d`, which is not portable to BSD/macOS. This is consistent across the
whole catalogue and is noted rather than fixed per-file.

**Error strings:** denials surface as `AccessDenied` / `AccessDeniedException`.
Not `Client.`-prefixed like EC2.

**MITRE:** T1525 (*Implant Internal Image*) is defensible.

**Severity:** manifest MEDIUM; IR view **High** — code execution under the
function's execution role.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1525.yml` — four documents: unapproved-layer attach (`high`, needs
  the allowlist applied in the engine), the publish→attach sequence (`high`),
  the publish base rule (`low`), and public layer sharing (`high`).
- `kql_t1525.kql` — owner-account allowlist comparison, plus the containment
  and layer-path guidance inline.

Full response procedure is in `../PLAYBOOK.md`.
