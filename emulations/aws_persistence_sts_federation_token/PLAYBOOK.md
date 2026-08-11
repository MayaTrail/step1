# IR Playbook - Backdoor IAM User with Federated Token - Durable Access via `sts:GetFederationToken`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Alternate credential (long-lived federated session minted from a compromised IAM user) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, `sts:GetFederationToken` mints a federated session valid for **up to 36 hours** that **survives rotation of the source access key** and can be used from anywhere. Its effective permissions are the **intersection of the source IAM user's permissions and the passed inline policy**, so if the compromised user is privileged, this is a durable copy of that access that key rotation will not kill. **Not** a privilege escalation: the `Action:*` inline policy is a ceiling, not a grant, and cannot exceed what the user already has. `MANIFEST.py` rates MEDIUM; the IR view is High because the token is unrevocable-by-rotation and long-lived |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1550.001 (as mapped by the MANIFEST, see the mapping note in §6) |
| Services in Scope | STS, IAM, CloudTrail |
| Infrastructure Created | None, no infra; the technique runs entirely against STS with the caller's own IAM-user credentials |

**What the emulation does:** using compromised **IAM-user** credentials, it calls `sts:GetFederationToken` with `Name="backdoor"`, an inline policy granting `Action:*` on `Resource:*`, and `DurationSeconds=129600` (36 h, the maximum for an IAM user). It then proves the minted credentials work with `sts:GetCallerIdentity`. The result is a federated session (`arn:aws:sts::<acct>:federated-user/backdoor`) the attacker controls for up to 36 hours. There is nothing to clean up, the token simply expires.

**Why this is persistence, and what it is *not*.** The federated credentials are independent of the source access key: rotate or delete that key and the federated session keeps working until it expires. That is the persistence. But the session's permissions are **bounded by the source IAM user**, `GetFederationToken` returns the *intersection* of the user's identity-based permissions and the inline `Policy`. The broad `Action:*` policy therefore grants nothing extra; it just declines to narrow the user's existing access. So the blast radius equals the compromised user's privileges, held for up to 36 h beyond key rotation.

**Two hard truths for containment.** (1) `sts:GetFederationToken` is callable **only with long-term credentials of an IAM principal**, an IAM user, or (rarely, and discouraged) the account **root**; never from an assumed-role/temporary session, which gets `AccessDenied`. So the source is an IAM user in essentially every real case. (2) You **cannot revoke a federated session directly** (there is no delete-session API for it). Because the session's permissions are evaluated per request against the *current* state of the source user's policies, the way to kill it is to **attach an explicit `Deny` to that IAM user**, an explicit Deny in the user's identity policy applies to the federated principal too, taking effect near-immediately (subject to normal IAM policy propagation, usually seconds). Rotating the user's keys alone does *not* stop it.

**Detection is `GetFederationToken` and the federated session, not `GetCallerIdentity`.** `GetFederationToken` is rare in most environments (SSO/`AssumeRole` is the norm). The shipped rule pairs it with `GetCallerIdentity`, one of the highest-volume calls in all of AWS, which makes the rule unusably noisy and adds nothing (it was only the emulation's proof-of-access). Detect `GetFederationToken` itself, and the follow-on activity of `userIdentity.type == FederatedUser` sessions.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail (STS global endpoint events land in `us-east-1`; regional STS endpoints log in-region). `GetFederationToken` carries `requestParameters.name`, `requestParameters.durationSeconds`, `requestParameters.policy` (the **full attacker-supplied inline policy JSON, logged unredacted**, a useful forensic field showing exactly what was requested, even though the effective grant is capped by the source user), and `responseElements.federatedUser.arn`/`.federatedUserId`, `responseElements.credentials.accessKeyId`/`.expiration`, `responseElements.packedPolicySize`. Federated-session activity carries `userIdentity.type == "FederatedUser"` and `userIdentity.arn == arn:aws:sts::<acct>:federated-user/<Name>`
- A baseline of whether `GetFederationToken` is used at all in your environment (most orgs: never), so any call is anomalous

**Alerting (must be pre-configured)**
- **`sts:GetFederationToken` (any call) → P0** in an environment that does not use it; **P1 with a broad inline policy or a long `durationSeconds`** where it is used
- **Any activity by a `FederatedUser` principal whose `Name` is unrecognised (e.g. `backdoor`) → P0**
- `GetFederationToken` by an IAM user that is a service/automation account (should never federate) → P0

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from the user under investigation
- `jq`; the IAM user → owner mapping so the source user can be contained fast

**Known IOC Baselines**
- The emulation's federated `Name` = `backdoor`, `DurationSeconds` = 129600, inline policy `Action:*`
- Baseline which IAM users (if any) legitimately call `GetFederationToken`

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `sts:GetFederationToken` in an environment that does not use federation tokens | CloudTrail | T1550.001 |
| P0 | Activity by a `userIdentity.type == FederatedUser` session with an unrecognised `Name` (e.g. `federated-user/backdoor`) | CloudTrail | T1550.001 |
| P1 | `sts:GetFederationToken` with a broad inline policy (`packedPolicySize` large / `Action:*`) or a long `durationSeconds` | CloudTrail | T1550.001 |
| P1 | `sts:GetFederationToken` by a service/automation IAM user | CloudTrail | T1550.001 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Federated-session activity from a new source IP / geography vs the source user's norm | CloudTrail | T1550.001 |
| P2 | `sts:GetFederationToken` denied at volume (`errorCode = AccessDenied`), probing / role creds trying it | CloudTrail | T1550.001 |
| P3 | A known, baselined IAM user federating during expected use | CloudTrail | T1550.001 |

### Detection Rule Quality Notes

The shipped rule pairs the rare signal with the noisiest call in AWS. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (GetFederationToken, GetCallerIdentity)` with `condition: selection` | Unusable. `sts:GetCallerIdentity` is among the highest-volume calls in AWS (every SDK/CLI whoami, every credential check), bundling it buries the rare `GetFederationToken` signal in noise, and it was only the emulation's proof-of-access | Match `GetFederationToken` alone; drop `GetCallerIdentity` entirely |
| No follow-on federated-session detection | Misses the actual damage, what the minted token *did* | Add a rule on `userIdentity.type == FederatedUser` activity, especially an unrecognised `Name` |
| No policy/duration scoring | Cannot prioritise a broad, long-lived token over a narrow short one | Score on `Action:*`/`packedPolicySize` and `durationSeconds` |
| `level: medium`; header TODO | A rotation-surviving 36 h token is higher | Raise to `high`; resolve TODO |

**Recommended detection, the mint, plus the federated session's activity.**

```yaml
# Rule A: the federation-token mint itself (rare = high-fidelity)
title: STS GetFederationToken called
id: 2c7f1a94-3d58-4e61-9c2f-6a0b8d5e3f17
name: sts_getfederationtoken
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'sts.amazonaws.com'
    eventName: 'GetFederationToken'
  condition: selection
level: high
---
# Rule B: activity performed BY a federated session (the token being used)
title: Federated-user session activity
id: 3d8f2b05-4e69-4f72-a1d3-7b1c9e6f4a28
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    userIdentity.type: 'FederatedUser'
  # Optionally scope to unrecognised Names by excluding a baseline allowlist of
  # federated-user ARNs at the log platform (e.g. arn:aws:sts::*:federated-user/<approved>).
  condition: selection
level: high
```

Where federation *is* used legitimately, keep Rule A but downgrade to `medium` and add a
principal allowlist; keep Rule B scoped to unrecognised `Name`s. **On error strings:** a
role session calling `GetFederationToken` fails with `AccessDenied` (the API is IAM-user-only)
- a burst of these is itself a probing signal. Denials surface as `AccessDenied` /
`AccessDeniedException`, not `Client.`-prefixed.

---

### Key Investigation Queries

> STS events from the global endpoint land in **`us-east-1`**; regional STS endpoints log in-region, if in doubt, sweep regions. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

#### Query 1 - Reconstruct the mint: who federated, with what name, duration, and source

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '48 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-48H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetFederationToken \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, caller: .userIdentity.arn,
     source_user: .userIdentity.userName,             # the IAM USER that federated (the one to contain)
     access_key: .userIdentity.accessKeyId,           # the source user key (feeds Query 4)
     fed_name: .requestParameters.name,               # attacker-chosen federated Name (IOC)
     duration: .requestParameters.durationSeconds,
     fed_arn: .responseElements.federatedUser.arn,    # arn:...:federated-user/<Name>
     fed_user_id: .responseElements.federatedUser.federatedUserId,
     minted_key: .responseElements.credentials.accessKeyId,   # the FEDERATED session key (IOC)
     expires: .responseElements.credentials.expiration,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Record the `source_user` (the IAM user to contain), the `fed_name`, the `minted_key`
(the federated session's access key), and `expires`. The source user is the pivot for
containment; the `minted_key` and `fed_arn` are how you find what the token did (Query 2).

#### Query 2: What did the federated session DO?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '48 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-48H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
MINTED_KEY="<minted_key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$MINTED_KEY" \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     type: .userIdentity.type, principal: .userIdentity.arn,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Every event here (`type` = `FederatedUser`) is an action the backdoor token took, all in
scope. Note the `ip`s (IOCs) and any sensitive reads/writes. Because the STS global-endpoint
key may also surface events in other regions, re-run per region if the source used a regional
endpoint.

#### Query 3: Are there OTHER federated sessions (more than one mint)?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetFederationToken \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select((.errorCode // "") == "") |
    "\(.eventTime)  user=\(.userIdentity.userName)  name=\(.requestParameters.name)  expires=\(.responseElements.credentials.expiration)"' | sort
```

Each row is a live-until-expiry token. Any whose `expires` is still in the future is an
active backdoor, contain its `source_user` (Step 1). List every distinct `source_user`.

#### Query 4: Full session reconstruction of the SOURCE user

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '48 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-48H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"   # the SOURCE user's key

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Look for how the source key was obtained and any other persistence the attacker planted
(more federation calls, IAM backdoors, access keys), remediate each with its playbook.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

You cannot revoke the federated session directly, but its permissions derive from the
source IAM user, so an explicit `Deny` on that user neutralises the token near-immediately
(subject to normal IAM policy propagation, usually seconds). Do that
first, then rotate the source key.

> Run every command under the **break-glass responder credentials** from §1, not under the
> user being contained.

#### Step 1: Neutralise the federated token by denying the source user (the key move)

```bash
SOURCE_USER="<source_user-from-Query-1>"

# An explicit Deny in the source user's identity policy applies to the federated session too
# (the session can never exceed the user's permissions), so this kills the backdoor token
# immediately: without waiting up to 36h for expiry. The DateLessThan bounds it to sessions/
# activity as of now; drop the condition for an unconditional freeze while you investigate.
aws iam put-user-policy --user-name "$SOURCE_USER" --policy-name "EmergencyDenyFederatedSession" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
echo "[OK] Attached DenyAll to $SOURCE_USER, federated token(s) from this user are now inert"
```

> Note this also freezes the source user itself (intended). If the user must keep *some*
> function during IR, scope the Deny to the sensitive actions the federated session was seen
> using (Query 2) rather than `Action:*`.

#### Step 2: Rotate/disable the source user's access keys

```bash
SOURCE_USER="<source_user-from-Query-1>"

for K in $(aws iam list-access-keys --user-name "$SOURCE_USER" \
    --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
  aws iam update-access-key --user-name "$SOURCE_USER" --access-key-id "$K" --status Inactive
  echo "[OK] Disabled source key $K on $SOURCE_USER"
done
```

> Disabling the key stops *new* `GetFederationToken` calls, but by itself does **not** stop an
> already-minted federated session - Step 1 is what does that. Both are required.

#### Step 3: Confirm no assumed-role path and check for repeat mints

```bash
# GetFederationToken is IAM-user-only, so the source is always an IAM user (never a role).
# Re-run Query 3 to enumerate EVERY source_user that minted a still-live token, and apply
# Steps 1-2 to each.
echo "[i] Apply Steps 1-2 to every distinct source_user from Query 3 with a future expiry."
```

---

## 4. Eradication

### Remove Attacker Access

#### Decide the source user's fate

```bash
SOURCE_USER="<source_user-from-Query-1>"
# If the user is attacker-created or no longer needed, delete it (which also ends any
# federated session derived from it). Full teardown: keys, policies, login profile, then user.
for K in $(aws iam list-access-keys --user-name "$SOURCE_USER" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
  aws iam delete-access-key --user-name "$SOURCE_USER" --access-key-id "$K"
done
aws iam delete-login-profile --user-name "$SOURCE_USER" 2>/dev/null
# (detach/delete policies as needed, then:)  aws iam delete-user --user-name "$SOURCE_USER"
echo "[i] If $SOURCE_USER is legitimate, keep it: remove the emergency deny once its keys are"
echo "    rotated and any live federated token has expired (check 'expires' from Query 1)."
```

#### Remove other persistence

From Query 4, remediate anything else the attacker planted, other federation mints, IAM
backdoors, additional keys, with the relevant playbook.

#### Remove the emergency deny once safe

```bash
SOURCE_USER="<source_user-from-Query-1>"
# Only after keys are rotated AND every minted token's 'expires' has passed (or the user is deleted).
aws iam delete-user-policy --user-name "$SOURCE_USER" --policy-name "EmergencyDenyFederatedSession" 2>/dev/null
echo "[OK] Emergency deny removed from $SOURCE_USER"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the federated token can no longer act

```bash
REGION="us-east-1"
MINTED_KEY="<minted_key-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

# After the DenyAll (Step 1), any use of the minted key should now fail (AccessDenied) or stop.
POST=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$MINTED_KEY" \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | select((.errorCode // "") == "") | .eventTime' | grep -c .)
[ "$POST" -eq 0 ] && echo "[OK] No SUCCESSFUL federated-session actions since containment" \
                  || echo "[FAIL] $POST successful federated actions post-containment, the DenyAll did not cover them; widen it"
```

#### Verify no new federation mints since containment

```bash
REGION="us-east-1"
CONTAINED_AT="<iso8601-containment-timestamp>"

NEW=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetFederationToken \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | select((.errorCode // "") == "") | .eventTime' | grep -c .)
[ "$NEW" -eq 0 ] && echo "[OK] No new GetFederationToken since containment" \
                 || echo "[FAIL] $NEW new federation mints, a source key is still live"
```

#### Confirm the corrected detection fires

```bash
echo "Re-run the emulation and confirm Rule A fires HIGH on GetFederationToken and Rule B"
echo "fires on the FederatedUser session activity (federated-user/backdoor), and that the"
echo "rule no longer keys on the high-volume GetCallerIdentity."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A compromised IAM user could mint a 36 h federated token | `sts:GetFederationToken` not restricted; IAM users with long-lived keys exist at all |
| Token survives key rotation | Federated sessions are independent of the source key's status and cannot be revoked directly |
| Undetected | Shipped rule buried the rare `GetFederationToken` under high-volume `GetCallerIdentity` and never watched `FederatedUser` activity |
| Blast radius = the source user's privileges | Over-privileged IAM users; no least-privilege on human/service users |
| Slow/incorrect containment | Responders unaware that only a Deny on the *source user* (not key rotation) revokes a federated session |

### Recommended Guardrails

**Deny federation-token minting (primary control)**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// deny GetFederationToken outside any principal that legitimately needs it (usually: none).
{
  "Effect": "Deny",
  "Action": "sts:GetFederationToken",
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:user/legacy-federation-broker"] }
  }
}
```

(If nothing in your org uses `GetFederationToken`, deny it unconditionally, drop the
`Condition`.)

**Structural controls**
- **Eliminate long-lived IAM users** in favour of IAM Identity Center (SSO) / short-lived role sessions, no IAM-user keys means no `GetFederationToken` source
- **Least-privilege every IAM user**, the federated token can never exceed the user, so a scoped user caps the damage
- Where federation is genuinely needed, use a single dedicated broker user with a tightly scoped policy and short `durationSeconds`, and baseline it
- Rotate/audit IAM-user access keys; alert on keys not used by the pipeline

**Detection improvements**
- Deploy Rule A (`GetFederationToken`) and Rule B (`FederatedUser` activity); never the shipped `GetCallerIdentity`-inclusive match
- Alert on unrecognised federated `Name`s and on large `packedPolicySize` / long `durationSeconds`

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1550.001 - Use Alternate Authentication Material: Application Access Token (as mapped by MANIFEST) |
| MITRE tactic | MANIFEST tags Persistence |
| Primary API | `sts:GetFederationToken` (IAM-user creds only; mints a ≤36 h `FederatedUser` session) |
| Event source | `sts.amazonaws.com` (global endpoint → `us-east-1`; regional endpoints log in-region) |
| Key discriminator | The `GetFederationToken` call itself (rare) and `userIdentity.type == FederatedUser` activity with an unrecognised `Name`, not `GetCallerIdentity` |
| Permissions of the token | **Intersection** of the source user's permissions and the inline `Policy`, `Action:*` is a ceiling, not a grant; never a privilege escalation |
| Revocation | **No direct revoke.** Attach an explicit `Deny` to the **source IAM user** (applies to the federated session); rotating the source key alone does NOT stop an already-minted token |
| Source constraint | Long-term IAM-principal creds only, an IAM user, or (rarely) account root (root max duration 3600s); assumed-role/temporary sessions get `AccessDenied`. The source is an IAM user in essentially every real case |
| Nested response fields | `responseElements.federatedUser.arn`/`.federatedUserId`, `responseElements.credentials.accessKeyId`/`.expiration` (nested, a flat path yields null) |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException` |
| Resources created | None, no infra; the token expires on its own (≤36 h) |

**MITRE mapping note (flag):** the MANIFEST maps **T1550.001**, whose canonical name is
*Use Alternate Authentication Material: Application Access Token* and whose canonical tactics
are **Defense Evasion / Lateral Movement**, not Persistence, which the MANIFEST tags.
Minting a durable federated credential is arguably closer to **T1078.004 (Valid Accounts:
Cloud Accounts)** for the persistence/valid-credential framing, or T1550 broadly for
alternate-material use. The MANIFEST's technique *name* is the upstream Stratus label, not a
canonical MITRE name. Flagged as a mapping-precision finding; the operational content is
unaffected.

### Revert

There is nothing to destroy, the technique creates no infrastructure and the federated token
expires on its own within 36 hours. After a **real** incident, do not wait for expiry: attach
the `Deny` to the source user (§3 Step 1) to neutralise the token now, rotate the source key,
and remove any other persistence; the token is otherwise valid and usable from anywhere until
it expires, regardless of the source key's status.
