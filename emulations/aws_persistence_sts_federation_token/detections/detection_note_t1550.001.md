# Detection Note: T1550.001 (Backdoor IAM User with Federated Token)

**Signal:** `sts:GetFederationToken` minting a session that survives rotation of
the source user's access keys.

**`GetCallerIdentity` is deliberately absent from these rules.** The original
rule bundled it, one of the highest-volume calls in AWS, emitted by every
SDK/CLI init and credential check, which buried the rare `GetFederationToken`
signal completely. It was only the emulation's proof-of-access step.

## Two things responders get wrong

**1. `Action:"*"` is a ceiling, not a grant.**

The token's permissions are the **intersection** of the source user's
permissions and the inline policy. So a wide-open inline policy is **not
privilege escalation**, the blast radius is exactly the source user's own
privilege. A broad policy on a low-privilege user is far less serious than a
narrow one on an admin. Triage on the *user*, not the policy text.

**2. Rotating the source user's keys does not stop the token.**

There is **no API to revoke a federation token**. The token was already minted;
the key it came from is irrelevant to its continued validity.

The only reliable path is to attach an explicit **Deny to the source IAM
user**. Permissions are evaluated per-request against the user's live policies,
so the deny cascades to the derived federated session near-immediately (IAM is
eventually consistent, allow a few seconds for propagation). Deleting the user
also ends its federated sessions.

This is the single most important operational fact in this playbook: the
instinctive first response, rotate the key, is the one thing that does not
work.

## Scoring a minted token

| Field | Why it matters |
|---|---|
| `requestParameters.policy` | Logged **unredacted**, the attacker's requested policy is available for forensics |
| `requestParameters.durationSeconds` | Up to **36 hours** (129600s) |
| `responseElements.federatedUser.arn` | The session identity |
| `responseElements.credentials.accessKeyId` | The minted key, starts `ASIA`; the hunt pivot |

**Identity shape:** `userIdentity.type` is `FederatedUser`, and the ARN takes
the form `.../federated-user/<Name>`.

**Who can call it:** IAM users. Account **root** can also call it, capped at
3600s, so "IAM-user-only" is very nearly but not strictly true. A **role**
session cannot, and fails with `AccessDenied`; a burst of those failures is
itself a probing signal, covered by its own rule here.

**Error strings:** denials surface as `AccessDenied` / `AccessDeniedException`.
Not `Client.`-prefixed like EC2.

**MITRE note:** the manifest maps T1550.001 (*Application Access Token*), whose
canonical tactics are Defense Evasion / Lateral Movement rather than the tagged
Persistence. **T1078.004** (*Valid Accounts: Cloud Accounts*) is closer for the
durable-credential framing. Both tags are carried.

**Severity:** manifest MEDIUM; IR view **High**, a rotation-surviving session
lasting up to 36 hours.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1550.001.yml`, three documents: the mint (`high`), federated-session
  activity (`high`), and denied attempts as a probing signal (`medium`).
- `kql_t1550.001.kql`, scored on policy breadth and duration, with the
  revocation guidance and the minted-key hunt query inline.

Full response procedure is in `../PLAYBOOK.md`.
