# Detection Note — T1098.001 (Backdoor IAM User with Additional Access Key)

**Signal:** `iam:CreateAccessKey` where the target user is **not** the caller,
by a principal outside the provisioning allowlist.

**Why this is persistence:** the minted key belongs to the *victim*, not the
attacker. Revoking the attacker's own credentials — the standard first response
— leaves the backdoor key fully functional.

## The field path that breaks everything if you get it wrong

`CreateAccessKey` nests the new key id:

```
responseElements.accessKey.accessKeyId      ✅ correct
responseElements.accessKeyId                ❌ always null
```

A query using the flat path returns `null` for every event. That does not fail
loudly — it silently produces empty results, which breaks the whole
identify → contain → hunt chain. You cannot disable a key whose id you never
captured, and you cannot hunt for its use.

## The caller-vs-target comparison

The original rule's *description* asked for this comparison; the rule never
performed it, matching `CreateAccessKey` and `DeleteAccessKey` with a bare
`condition: selection`.

Two things make the comparison work in practice:

1. **Self-service creation omits `userName`** — the key is minted for the
   caller implicitly. So requiring `userName` to exist already excludes most
   benign traffic.
2. The residual case — a user passing their *own* name — needs a field-to-field
   comparison (`requestParameters.userName == userIdentity.userName`). Sigma
   cannot express that portably; the KQL does it explicitly.

**Caveat for role callers:** there is no `userIdentity.userName` on a role
session, so "created for another user" is a **coarse flag** in that case, not
proof. Triage those against whether the role legitimately provisions users.

**Drop `DeleteAccessKey`.** It is benign cleanup and the emulation's own
revert — signal-inverted as a trigger.

## Coverage beyond the event

**Was it used?** Feed the captured `accessKeyId` back through CloudTrail
(`userIdentity.accessKeyId`) to establish first use, source IPs and actions.
That is the difference between "a backdoor exists" and "a backdoor is active".

**Account-wide sweep** for keys planted before logging: use the **IAM
credential report**, not Access Analyzer — Access Analyzer covers resource
policies and external access, not user access keys. Look for users with two
active keys, or a key materially newer than its user.

**Guardrail caution:** an SCP restricting `CreateAccessKey` by `aws:username`
must use `StringNotEqualsIfExists`. The key is **absent** on role principals,
and a plain `StringNotEquals` therefore evaluates false and wrongly denies
every role-based call.

**Error strings:** IAM denials surface as `AccessDenied` /
`AccessDeniedException`; a user already holding the two-key maximum gives
`LimitExceeded`. Not `Client.`-prefixed like EC2.

**MITRE:** T1098.001 (*Account Manipulation: Additional Cloud Credentials*) is
precise — no caveat.

**Severity:** manifest MEDIUM; IR view **High** — durable credential
persistence surviving rotation.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1098_001.yml` — one rule (`high`) covering the "for another user by
  non-provisioning principal" shape.
- `kql_t1098_001.kql` — the full caller-vs-target comparison with the correct
  nested key path, plus the key-usage hunt query.

Full response procedure is in `../PLAYBOOK.md`.
