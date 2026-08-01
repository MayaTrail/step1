# IR Playbook: Backdoor IAM User with Additional Access Key — Persistence via `iam:CreateAccessKey`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Additional Cloud Credentials (backdoor access key) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A — single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High — a second access key gives the attacker independent, standing programmatic access that **survives rotation of the user's own key**; it is quiet, durable persistence (`MANIFEST.py` rates MEDIUM; the IR view is High because it is an enduring foothold behind a legitimate identity) |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1098.001 |
| Services in Scope | IAM, STS, CloudTrail |
| Infrastructure Created | 1 IAM user with no existing access keys (via `infra/`) |

**What the emulation does:** calls `iam:CreateAccessKey` for an existing IAM user (a user *other than the caller*), minting a second, attacker-controlled set of programmatic credentials for that identity. The attacker can now authenticate as the user indefinitely. The emulation's revert deletes the key it created.

**Why this is durable persistence.** The backdoor key is a fully independent credential for the user. If the legitimate owner rotates *their* key, or their password is reset, the attacker's key keeps working — the two keys are unrelated. Nothing new appears in the identity graph: no new user, no new role, just one extra key on an existing user, which few teams review. The only evidence is a single `iam:CreateAccessKey` event.

**The detection discriminator is "who created the key for whom."** Creating your *own* access key is routine self-service. The backdoor signature is `iam:CreateAccessKey` where **`requestParameters.userName` differs from the caller's own identity** — someone minting a key *for another user*. The shipped rule's own description states exactly this, but the shipped rule does not implement it — it matches `CreateAccessKey`/`DeleteAccessKey` with no comparison (§2). The refinement that matters: admins and provisioning pipelines *legitimately* create keys for other users, so the real signal is **key-for-another-user by a non-provisioning principal** (or on a user that should never get an ad-hoc key).

**Distinct from the trust-policy backdoor (the sibling technique).** That one is caught by IAM Access Analyzer (it analyses resource/trust policies). **Access Analyzer does NOT cover access-key creation** — there is no policy document here. The controls for *this* technique are CloudTrail detection on the create event, an SCP restricting `iam:CreateAccessKey`, and the IAM **Credential Report** for finding keys that shouldn't exist.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail (IAM is global → events land in `us-east-1`). `iam:CreateAccessKey` is a management event carrying `requestParameters.userName` (the target user, when specified), `userIdentity` (the caller), and `responseElements.accessKey.accessKeyId` (**the new key's ID — the IOC**)
- **IAM Credential Report** available on demand (`aws iam generate-credential-report` / `get-credential-report`) — the account-wide view of which users have which keys and when they were created/last used
- A maintained allowlist of principals that legitimately create keys for other users (provisioning/identity-admin), so a create-for-another by anyone else stands out

**Alerting (must be pre-configured)**
- **`iam:CreateAccessKey` where `requestParameters.userName` ≠ the caller's own user, by a principal not on the provisioning allowlist → P0** (the backdoor signature)
- `iam:CreateAccessKey` resulting in a user holding **two** access keys (AWS max) where the second was created by someone other than the user — a strong backdoor indicator
- Use of a newly-created access key from an off-baseline IP/geo within a short time of its creation (the key being exercised)
- `iam:CreateAccessKey` denied at volume (`errorCode = AccessDenied` / `LimitExceeded`) — probing / a user already at the 2-key limit

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- The provisioning-principal allowlist and a baseline of which users have keys (from the Credential Report)

**Known IOC Baselines**
- Baseline which principals create access keys for others — normally only provisioning/identity-admin
- Baseline which users have programmatic keys at all; a service/human user that *never* had a key suddenly getting one is anomalous
- The backdoor key ID from the create event is the primary IOC for hunting usage

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `iam:CreateAccessKey` where `requestParameters.userName` ≠ caller's own identity, by a non-provisioning principal | CloudTrail | T1098.001 |
| P0 | The new access key (`responseElements.accessKey.accessKeyId`) used shortly after creation from an off-baseline IP | CloudTrail | T1098.001 |
| P1 | A user ends up with two access keys, the second created by a different principal | CloudTrail / Credential Report | T1098.001 |
| P1 | `iam:CreateAccessKey` for a privileged/admin user by anyone outside identity-admin | CloudTrail | T1098.001 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `iam:CreateAccessKey` for another user by an interactive human principal (vs. the CI/provisioning role) | CloudTrail | T1098.001 |
| P2 | `iam:CreateAccessKey` for a user that has had no programmatic activity historically | CloudTrail / Credential Report | T1098.001 |
| P2 | `iam:CreateAccessKey` denied at volume (`errorCode = AccessDenied`/`LimitExceeded`) — probing | CloudTrail | T1098.001 |
| P3 | A user creating their **own** access key (no `userName`, or `userName` == caller) during normal rotation | CloudTrail | T1098.001 |

### Detection Rule Quality Notes

The shipped rule's *description* is correct but the rule does not implement it. These are correctness defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (CreateAccessKey, DeleteAccessKey)` with `condition: selection` — **no caller-vs-target comparison** despite the rule's own description calling for one | Noisy and imprecise. `CreateAccessKey` fires on every routine self-service key creation; `DeleteAccessKey` is the benign revert. The rule never checks whether the key was created *for another user* | Compare `requestParameters.userName` to the caller's own user; alert only on a mismatch |
| No provisioning allowlist | Admin/IaC creating keys for others is legitimate; without an allowlist the rule floods on provisioning | Exclude provisioning/identity-admin principals |
| `DeleteAccessKey` as a trigger | Benign cleanup / the emulation's revert — pure noise | Drop it as a primary trigger |
| No usage correlation | Catches the plant but not the key being used (the confirmation of active compromise) | Correlate the new `accessKeyId` with subsequent use from an off-baseline IP |
| Header TODO "verify acronym casing"; `level: medium` | Stale; durable credential persistence is higher | Resolve TODO; the mismatch rule → `level: high` |

**Recommended detection — key created for another user by a non-provisioning principal.** The caller-vs-target comparison is a field relationship, best expressed in the log platform (Query 1). A single-event Sigma rule can express the "for another user by non-provisioning" shape where the backend supports field-to-field comparison; otherwise deploy Query 1:

```yaml
title: IAM access key created for another user by a non-provisioning principal
id: 6d1a8f42-7c93-4e05-b2d1-8a0c9b7e3f61
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreateAccessKey'
    requestParameters.userName|exists: true      # a target user WAS specified (self-service omits it); verify your SIEM backend supports the `exists` modifier
  provisioning:
    userIdentity.arn|contains:
      - ':role/iac-deploy'
      - ':role/identity-admin'
      - ':role/BreakGlassAdmin'
  # Where the backend supports it, add: filter out events where
  # requestParameters.userName == userIdentity.userName (self creating own key
  # while also passing their own name). Otherwise do that comparison in Query 1.
  condition: selection and not provisioning
level: high
```

**On the comparison:** self-service key creation usually **omits** `userName` (the key is created for the caller), so `requestParameters.userName|exists: true` already excludes most self-service. The remaining false positive — a user passing their *own* name — is removed by the `userName == caller` check, which Query 1 does explicitly.

**On error strings:** IAM denials surface as `AccessDenied` / `AccessDeniedException`; a user already at the two-key maximum as `LimitExceeded`. Not `Client.`-prefixed. Match the denial forms and confirm against a sample.

---

### Key Investigation Queries

> IAM events are global → query **`us-east-1`**. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. (No policy documents here, so none of the URL-decoding of the trust-policy playbook applies.)

#### Query 1 — Find keys created for another user, and grab the backdoor key IDs

```bash
REGION="us-east-1"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "iam.amazonaws.com") |
    # caller identity: IAM user name if present, else the ARN
    (.userIdentity.userName // .userIdentity.arn) as $caller |
    {time: .eventTime,
     caller: .userIdentity.arn,
     caller_key: .userIdentity.accessKeyId,           # feeds ACCESS_KEY_ID in Query 4
     target_user: .requestParameters.userName,
     new_key: .responseElements.accessKey.accessKeyId,          # the BACKDOOR key IOC
     error: (.errorCode // "SUCCESS"),
     # backdoor pattern: a target user was named AND it is not the caller
     for_another: ((.requestParameters.userName // null) != null
                   and (.requestParameters.userName != ($caller))),
     ip: .sourceIPAddress}' | \
  jq -s 'map(select(.for_another)) | sort_by(.time)'
```

Note: `for_another` is a *coarse* flag — for an **assumed-role** caller it compares
the target username against the role ARN, so it is always `true`. Query 1 does no
allowlist filtering itself; it surfaces candidates for you to triage against the
provisioning allowlist. Each row with `for_another: true` from a non-provisioning `caller` is a backdoor.
Record every `new_key` — those are the IOC access-key IDs to disable (§3) and hunt
for usage (Query 3).

#### Query 2 — Sweep ALL users for foreign-created / extra keys (Credential Report)

The attacker may have backdoored more than one user. The Credential Report is the
account-wide view; cross-reference key creation against CloudTrail to see *who*
created each.

```bash
# Generate + fetch the credential report (base64 CSV)
aws iam generate-credential-report >/dev/null 2>&1
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  awk -F',' 'NR==1 || $9=="true" || $14=="true" {print $1, "key1_active="$9, "key2_active="$14}'
  # columns: 1=user, 9=access_key_1_active, 14=access_key_2_active

# For any user with keys, list them and their creation dates, then cross-check
# CreateAccessKey events (Query 1) for who created each and whether it was the user
for U in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam list-access-keys --user-name "$U" \
    --query 'AccessKeyMetadata[].{Key:AccessKeyId,Created:CreateDate,Status:Status}' \
    --output text 2>/dev/null | while read -r LINE; do echo "$U  $LINE"; done
done
```

Flag any user with a key it should not have, or a key whose `CreateAccessKey`
event (Query 1) shows a caller other than the user or provisioning.

#### Query 3 — Was the backdoor key USED? (active compromise?)

```bash
REGION="us-east-1"
BACKDOOR_KEY="<new_key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$BACKDOOR_KEY" \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Any activity here means the backdoor key was exercised — everything it did is part
of the incident, and the `ip` values are attacker IOCs. (CloudTrail is regional
for the *services called*; run this in the regions the key touched, or use your
log platform for an account-wide view by access key.)

#### Query 4 — Full session reconstruction of the principal that planted the backdoor

```bash
ACCESS_KEY_ID="<caller_key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Look for *other* persistence the same principal planted — more backdoored users,
backdoored role trust policies, new login profiles.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The backdoor key is a live credential. Disable it first, then determine whether it
was used and contain the planting principal.

> Run every command under the **break-glass responder credentials** from §1, not
> under any principal being contained.

#### Step 1 — Disable the backdoor key(s) (do NOT delete yet — preserve evidence)

```bash
TARGET_USER="<target_user-from-Query-1>"
BACKDOOR_KEY="<new_key-from-Query-1>"

aws iam update-access-key --user-name "$TARGET_USER" \
  --access-key-id "$BACKDOOR_KEY" --status Inactive
echo "[OK] Disabled backdoor key $BACKDOOR_KEY on $TARGET_USER"

# Confirm the user's keys and their status
aws iam list-access-keys --user-name "$TARGET_USER" \
  --query 'AccessKeyMetadata[].{Key:AccessKeyId,Status:Status,Created:CreateDate}' --output table
```

#### Step 2 — Contain the principal that created the backdoor

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')          # user ARN: name = last segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] Disabled key $K for $U"
  done
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')           # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}}]}'
  echo "[OK] Revoked sessions for role $R"
fi
```

#### Step 3 — Consider the backdoored user itself compromised

The user now had an attacker credential minted against it. Disable the user's
*other* keys too (rotate them in eradication) and, if it has console access, reset
the password / require MFA — treat the whole identity as suspect, not just the one
key.

```bash
TARGET_USER="<target_user-from-Query-1>"
for K in $(aws iam list-access-keys --user-name "$TARGET_USER" \
    --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
  aws iam update-access-key --user-name "$TARGET_USER" --access-key-id "$K" --status Inactive
  echo "[OK] Disabled key $K on the backdoored user $TARGET_USER (rotate in §4)"
done
```

#### Step 4 — Deny further key creation by the principal

```bash
SUSPECT_ROLE="<role-name>"    # role principals; for an IAM user use put-user-policy
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenyKeyCreation" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["iam:CreateAccessKey","iam:CreateLoginProfile","iam:UpdateLoginProfile"],"Resource":"*"}]
  }'
echo "[OK] Credential-creation actions denied for $SUSPECT_ROLE"
```

---

## 4. Eradication

### Remove Attacker Access

#### Delete the backdoor key(s) and rotate the backdoored user's real keys

```bash
TARGET_USER="<target_user-from-Query-1>"
BACKDOOR_KEY="<new_key-from-Query-1>"

# Delete the backdoor key (evidence preserved in CloudTrail; it's already Inactive)
aws iam delete-access-key --user-name "$TARGET_USER" --access-key-id "$BACKDOOR_KEY" && \
  echo "[OK] Deleted backdoor key $BACKDOOR_KEY"

# Delete the user's now-disabled real keys and re-issue (the identity was compromised)
for K in $(aws iam list-access-keys --user-name "$TARGET_USER" \
    --query 'AccessKeyMetadata[?Status==`Inactive`].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name "$TARGET_USER" --access-key-id "$K"
  echo "[OK] Deleted old key $K on $TARGET_USER"
done
aws iam create-access-key --user-name "$TARGET_USER" \
  --query 'AccessKey.{AccessKeyId:AccessKeyId,SecretAccessKey:SecretAccessKey}' 2>/dev/null
echo "[OK] Re-issued a clean key for $TARGET_USER (distribute securely)"
```

#### Remediate every other backdoored user (from Query 2)

Delete each foreign-created key Query 2 surfaced, and rotate those users' real
keys. Do not assume only the one user from Query 1 was affected.

#### Remove other persistence planted by the principal

From Query 4, remediate anything else the principal created — more backdoor keys,
backdoored role trust policies, login profiles, admin policy attachments — using
the relevant persistence playbook for each.

#### Right-size key-creation permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove iam:CreateAccessKey from principals that are not provisioning/identity-admin.
# Prefer short-lived role credentials (STS) over long-lived user access keys entirely.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyKeyCreation" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the backdoor key is gone and the user has only expected keys

```bash
TARGET_USER="<target_user-from-Query-1>"
BACKDOOR_KEY="<new_key-from-Query-1>"

GONE=$(aws iam list-access-keys --user-name "$TARGET_USER" \
  --query "AccessKeyMetadata[?AccessKeyId=='$BACKDOOR_KEY']" --output text)
[ -z "$GONE" ] && echo "[OK] Backdoor key $BACKDOOR_KEY removed from $TARGET_USER" \
               || echo "[FAIL] Backdoor key still present"

aws iam list-access-keys --user-name "$TARGET_USER" \
  --query 'AccessKeyMetadata[].{Key:AccessKeyId,Status:Status,Created:CreateDate}' --output table
```

#### Verify no user has an unexplained foreign-created key (re-sweep)

```bash
# Re-run the Credential Report sweep; every remaining key should trace to the user
# themselves or provisioning in CloudTrail
aws iam generate-credential-report >/dev/null 2>&1
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  awk -F',' 'NR==1 || $9=="true" || $14=="true" {print $1, "key1="$9, "key2="$14}'
echo "Cross-check any active key against its CreateAccessKey caller (Query 1)."
```

#### Verify no further key creation since containment

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .eventTime' | grep -c .)
[ "$COUNT" -eq 0 ] && echo "[OK] No further key creation from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further CreateAccessKey — containment did not hold"
```

#### Verify the backdoor key never worked again after disablement

```bash
REGION="us-east-1"
BACKDOOR_KEY="<new_key-from-Query-1>"
CONTAINED_AT="<iso8601-containment-timestamp>"

USED=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$BACKDOOR_KEY" \
  --start-time "$CONTAINED_AT" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) | .eventTime' | grep -c .)
[ "$USED" -eq 0 ] && echo "[OK] Backdoor key had no successful use after containment" \
                  || echo "[FAIL] Backdoor key succeeded $USED times post-containment — not fully disabled"
```

#### Confirm the corrected detection fires

```bash
echo "Re-run the emulation and confirm the corrected rule fires on the CreateAccessKey"
echo "where requestParameters.userName != the caller (a key minted for another user)"
echo "by a non-provisioning principal — classified P0 — and does NOT fire on a user"
echo "creating their own key or on DeleteAccessKey."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could mint a key for another user | `iam:CreateAccessKey` granted outside provisioning/identity-admin; no restriction on creating keys for others |
| Backdoor undetected | Shipped rule matched the event but never compared caller vs. target user (despite its own description); no usage correlation |
| Persistence survives rotation | The backdoor key is independent of the user's own key — rotating theirs does nothing |
| Possibly more than one user backdoored | No account-wide Credential Report sweep for foreign-created keys |
| Long-lived static keys existed at all | Reliance on IAM user access keys rather than short-lived STS role credentials |

### Recommended Guardrails

**Restrict who can create keys, and for whom**

```json
// SCP: only provisioning/identity-admin may create access keys for other users;
// everyone else may only create their OWN key (self-service).
{
  "Effect": "Deny",
  "Action": "iam:CreateAccessKey",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": { "aws:username": "${aws:PrincipalTag/self}" },
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/identity-admin", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

(The precise self-service condition varies by setup; the intent is: deny creating a
key for a user other than yourself unless you are provisioning/identity-admin.
**Use `StringNotEqualsIfExists`** for the `aws:username` clause — `aws:username`
is absent for assumed-role principals, and a plain `StringNotEquals` on a missing
key evaluates as a *match*, which would wrongly deny legitimate role sessions.)

**Reduce the value of the target**
- Prefer **short-lived STS/role credentials** over long-lived IAM user access keys; with no standing keys, this backdoor has far less to hide behind
- Where user keys are unavoidable, monitor the Credential Report for unexpected keys and enforce rotation/expiry

**Detection improvements**
- Deploy the caller-vs-target comparison rule (Query 1) — never the shipped bare `CreateAccessKey` match
- Correlate a newly-created key with its first use (off-baseline IP = active compromise)
- Alarm `CreateAccessKey` for privileged users by anyone outside identity-admin

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098.001 — Account Manipulation: Additional Cloud Credentials |
| MITRE tactic | Persistence (TA0003) |
| Primary API | `iam:CreateAccessKey` (for a user other than the caller) |
| Event source | `iam.amazonaws.com` (global → events in `us-east-1`) |
| Key discriminator | `requestParameters.userName` ≠ the caller's own identity, by a non-provisioning principal — self-service key creation usually omits `userName` |
| Primary IOC | `responseElements.accessKey.accessKeyId` from the create event — the backdoor key ID to disable and hunt for usage |
| Persistence property | The backdoor key is independent of the user's own credentials — survives the user rotating their key |
| Not covered by Access Analyzer | Unlike the trust-policy backdoor, there is no resource policy — detect via CloudTrail + Credential Report + SCP, not Access Analyzer |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException`, `LimitExceeded` (user already has 2 keys) |
| Resources created | 1 IAM user (no initial keys) |
| Related | The role trust-policy backdoor (sibling persistence technique) and the login-profile backdoor |

**MITRE mapping note:** T1098.001 (Additional Cloud Credentials) is the correct,
precise mapping — a second access key *is* additional cloud credentials for the
identity. No caveat needed.

### Revert

`pulumi destroy` in `infra/` removes the IAM user; the emulation's own revert
deletes the key it created, so a normal run self-cleans. After a **real** incident,
`pulumi destroy` is irrelevant — disable then delete every backdoor key (§3–§4),
rotate the affected users' real keys, remove any other persistence, and tighten
who can create keys; deleting a stack does not remove a key the attacker minted on
a user you still need.
