# IR Playbook - Create IAM Roles Anywhere Trust Anchor - Credential-Free Persistence via `rolesanywhere:CreateTrustAnchor`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence / Add an alternate authentication path (attacker CA registered as an IAM Roles Anywhere trust anchor) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | High, a trust anchor registers an **attacker-controlled CA** as a source of AWS identity. Once the full chain exists, any holder of a certificate signed by that CA can obtain IAM role credentials **with no long-term AWS credentials at all**, persistence that survives every access-key rotation and is invisible to key-centric hunts. **Caveat:** the trust anchor **alone is not sufficient**, assuming a role also requires a Roles Anywhere **profile** and an IAM **role whose trust policy trusts `rolesanywhere.amazonaws.com`**. As emulated only the trust anchor is created (no profile, no trusting role), so it is not yet usable, but it is the foundation of the chain and, in an account that already has permissive rolesanywhere-trusting roles, is immediately dangerous. `MANIFEST.py` rates MEDIUM |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1550.001 (as mapped by the MANIFEST, see the mapping note in §6; T1556/T1098 arguably fit better) |
| Services in Scope | IAM Roles Anywhere (regional), IAM, CloudTrail |
| Infrastructure Created | None persisted, the emulation creates the trust anchor and then disables + deletes it |

**What the emulation does:** it generates a **self-signed CA certificate** (CN=`stratus-red-team-ca`) and calls `rolesanywhere:CreateTrustAnchor` with `sourceType=CERTIFICATE_BUNDLE` and that cert as `x509CertificateData`, registering the attacker's CA as a trusted identity source. It then disables and deletes the trust anchor on cleanup. A normal run leaves only the CloudTrail trail; a real intrusion leaves the trust anchor (and, if the attacker completed the chain, a working credential-free access path).

**Why this is potent persistence.** IAM Roles Anywhere issues short-lived IAM role credentials to any workload presenting an X.509 certificate signed by a trusted CA. By registering *their own* CA, the attacker can mint certificates at will and exchange them for role credentials forever, no IAM user, no access key, nothing to rotate. It is the certificate-based cousin of a backdoored role trust policy, and it hides in a service most responders never inspect.

**Detection is the whole chain, not just the event name, but `CreateTrustAnchor` itself is high-fidelity.** `rolesanywhere:CreateTrustAnchor` is genuinely rare, almost never called outside initial onboarding, so *any* occurrence is a P0 worth immediate triage. The completed persistence, though, is `CreateTrustAnchor` **+** `CreateProfile` **+** a role trusting `rolesanywhere.amazonaws.com`. The shipped rule alerts on `CreateTrustAnchor` (good) but also bundles the `Disable`/`Delete` cleanup events and never looks at the profile or the role-trust side (§2).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing `rolesanywhere.amazonaws.com` events. **IAM Roles Anywhere is regional**, an attacker can create a trust anchor in *any* enabled region, so coverage and hunts must span all regions. `CreateTrustAnchor` carries `requestParameters.name`, `requestParameters.source.sourceType` (`CERTIFICATE_BUNDLE` vs `AWS_ACM_PCA`), `requestParameters.source.sourceData.x509CertificateData` (the CA cert PEM, public data, logged), and `responseElements.trustAnchor.trustAnchorArn`/`.trustAnchorId`
- A baseline inventory of **legitimate** trust anchors, profiles, and the IAM roles that trust `rolesanywhere.amazonaws.com`, so a new one is a concrete anomaly
- CloudTrail visibility of `sts`/role-session events so a Roles Anywhere credential exchange (`CreateSession`) and the resulting role activity can be traced

**Alerting (must be pre-configured)**
- **`rolesanywhere:CreateTrustAnchor` (any) → P0**, rare, high-fidelity
- **`rolesanywhere:CreateProfile` (any) → P0**, the other half of the chain; equally rare
- **`iam:UpdateAssumeRolePolicy`/`CreateRole` producing a trust policy that trusts `rolesanywhere.amazonaws.com` → P0**
- `rolesanywhere:ImportCrl`/`UpdateTrustAnchor` by a non-admin principal

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq`; `openssl` (to read the registered CA cert's subject/fingerprint from the event)
- The Roles Anywhere baseline and the list of roles trusting the service

**Known IOC Baselines**
- The emulation's trust-anchor name `stratus-red-team-trust-anchor`, CA subject CN `stratus-red-team-ca`, tag `StratusRedTeam=true`
- Baseline: legitimate trust anchors typically source from **AWS Private CA (`AWS_ACM_PCA`)**, not an externally-supplied self-signed `CERTIFICATE_BUNDLE`, the latter is a discriminator
- Baseline which principals administer Roles Anywhere (normally none, or a single onboarding role)

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `rolesanywhere:CreateTrustAnchor` (any occurrence) | CloudTrail | T1550.001 |
| P0 | `rolesanywhere:CreateProfile` (any occurrence), the role-linking half of the chain | CloudTrail | T1550.001 |
| P0 | An IAM role trust policy newly trusting `rolesanywhere.amazonaws.com` (`CreateRole`/`UpdateAssumeRolePolicy`) | CloudTrail | T1550.001 |
| P1 | `CreateTrustAnchor` with `sourceType=CERTIFICATE_BUNDLE` and a self-signed CA (subject == issuer) | CloudTrail | T1550.001 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P1 | `rolesanywhere:CreateSession` referencing an unrecognised trust anchor/profile (the CA being *used*) | CloudTrail | T1550.001 |
| P2 | `rolesanywhere:UpdateTrustAnchor`/`ImportCrl`/`EnableTrustAnchor` by a non-admin principal | CloudTrail | T1550.001 |
| P2 | `CreateTrustAnchor`/`CreateProfile` denied at volume (`errorCode = AccessDenied`), probing | CloudTrail | T1550.001 |
| P3 | The onboarding/admin role creating a trust anchor from an `AWS_ACM_PCA` source during a known rollout | CloudTrail | T1550.001 |

### Detection Rule Quality Notes

The shipped rule alerts on the (good) `CreateTrustAnchor` signal but bundles cleanup events and ignores the rest of the chain.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match `eventName IN (CreateTrustAnchor, DisableTrustAnchor, DeleteTrustAnchor)` with `condition: selection` | `CreateTrustAnchor` is correctly rare/high-fidelity, but bundling `Disable`/`Delete`, the *teardown* (and here the emulation's own cleanup), adds noise and inverts the signal (removing a trust anchor is remediation, not attack) | Alert on `CreateTrustAnchor` alone at `high`; keep `Disable`/`Delete` only for the forensic timeline |
| No `CreateProfile` coverage | Misses the role-linking half; a lone trust anchor is inert without a profile | Add `rolesanywhere:CreateProfile` as an equal P0 |
| No role-trust coverage | Misses a role newly trusting `rolesanywhere.amazonaws.com` (the gate the whole scheme depends on) | Add an IAM rule on trust policies trusting the service |
| Single-region assumption | Roles Anywhere is regional; a rule bound to one region misses an anchor created elsewhere | Deploy across all regions; sweep all regions in hunts |
| `level: medium`; header TODO | A credential-free persistence foundation is higher | Raise to `high`; resolve TODO |

**Recommended detection, the trust anchor, the profile, and the role-trust gate.**

```yaml
# Rule A: any trust anchor or profile creation (rare, high-fidelity)
title: IAM Roles Anywhere trust anchor or profile created
id: 9a3e1c74-2b58-4d69-8c1f-6a0d7b5e3f21
name: rolesanywhere_create_chain
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'rolesanywhere.amazonaws.com'
    eventName:
      - 'CreateTrustAnchor'
      - 'CreateProfile'
  condition: selection
level: high
---
# Rule B: an IAM role newly trusting the Roles Anywhere service
title: IAM role trust policy trusts rolesanywhere.amazonaws.com
id: 0b4f2d85-3c69-4e70-9d2a-7b1e8c6f4a32
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName:
      - 'CreateRole'
      - 'UpdateAssumeRolePolicy'
  # Split by event: UpdateAssumeRolePolicy carries policyDocument, CreateRole carries
  # assumeRolePolicyDocument: no single event has both, so these MUST be OR'd, not ANDed
  # (two keys in one selection block would AND and the rule would never fire).
  trust_update:
    requestParameters.policyDocument|contains: 'rolesanywhere.amazonaws.com'
  trust_create:
    requestParameters.assumeRolePolicyDocument|contains: 'rolesanywhere.amazonaws.com'
  # The trust policy is URL-encoded in the event, but the service principal survives as a
  # literal substring (only letters + dots: nothing percent-encodes).
  condition: selection and (trust_create or trust_update)
level: high
```

`CreateTrustAnchor` is rare enough that a single occurrence justifies triage, this is the
uncommon case where alerting on the bare event is correct, so Rule A does not over-fire.
Note the trust-policy match (Rule B) relies on the service principal `rolesanywhere.amazonaws.com`
surviving URL-encoding as a literal substring (it does, no `"`/`*` to encode). **On error
strings:** denials surface as `AccessDenied` / `AccessDeniedException`, not `Client.`-prefixed.

---

### Key Investigation Queries

> IAM Roles Anywhere is **regional**, run the CloudTrail hunts and the API sweeps in **every enabled region**, not just `us-east-1`. IAM (role) events remain global (`us-east-1`). Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

#### Query 1 - Reconstruct: who created the trust anchor / profile, and with what CA

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  for EV in CreateTrustAnchor CreateProfile; do
    aws cloudtrail lookup-events \
      --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
      --start-time "$START" \
      --region "$REGION" --output json 2>/dev/null
  done
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "rolesanywhere.amazonaws.com") |
    {time: .eventTime, region: .awsRegion, event: .eventName, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,          # feeds ACCESS_KEY_ID in Query 4
     name: .requestParameters.name,
     source_type: .requestParameters.source.sourceType,
     cert: .requestParameters.source.sourceData.x509CertificateData,   # the CA cert PEM
     anchor_arn: .responseElements.trustAnchor.trustAnchorArn,
     profile_arn: .responseElements.profile.profileArn,
     role_arns: .requestParameters.roleArns,          # CreateProfile: roles the profile grants
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

For a `CreateTrustAnchor`, extract the CA to see who signed it, a self-signed subject is a
strong tell:

```bash
echo "<cert-PEM-from-Query-1>" | openssl x509 -noout -subject -issuer -fingerprint -sha256 2>/dev/null
```

Record the `anchor_arn`, any `profile_arn` + `role_arns`, and `caller` (IOCs). A `CreateProfile`
whose `role_arns` point at privileged roles is the exploitable half of the chain.

#### Query 2: Sweep ALL regions for trust anchors, profiles, and rolesanywhere-trusting roles

```bash
# (a) Every trust anchor + profile, all regions:
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws rolesanywhere list-trust-anchors --region "$REGION" \
    --query 'trustAnchors[].{Region:`'"$REGION"'`,Name:name,Id:trustAnchorId,Enabled:enabled,Source:source.sourceType}' \
    --output text 2>/dev/null
  aws rolesanywhere list-profiles --region "$REGION" \
    --query 'profiles[].{Region:`'"$REGION"'`,Name:name,Id:profileId,Enabled:enabled}' \
    --output text 2>/dev/null
done
echo "[OK] Trust-anchor / profile sweep complete, reconcile each against your baseline"

# (b) Every IAM role whose trust policy trusts the Roles Anywhere service (IAM is global):
for R in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  aws iam get-role --role-name "$R" \
    --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null | \
    jq -e '(.Statement // [] | if type=="object" then [.] else . end)   # Statement may be object OR array
           | any(.[]; (.Principal.Service // empty
                       | if type=="array" then . else [.] end
                       | any(. == "rolesanywhere.amazonaws.com")))' >/dev/null \
    && echo "[!] role $R trusts rolesanywhere.amazonaws.com, confirm it is expected and bound to a known trust anchor"
done
echo "[OK] Role-trust sweep complete"
```

Any trust anchor/profile not in your baseline, or any unexpected rolesanywhere-trusting role,
is part of the persistence chain. `get-role` returns the trust policy **decoded**, so no
URL-decode is needed here (unlike the CloudTrail event).

#### Query 3: Was the trust anchor USED to obtain credentials?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)

# rolesanywhere:CreateSession is the credential-issuance call (verify the exact name against a
# real event in your account). Hunt it, all regions, referencing the attacker anchor/profile.
ANCHOR_ARN="<anchor_arn-from-Query-1>"
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateSession \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r --arg anchor "$ANCHOR_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "rolesanywhere.amazonaws.com") |
    {time: .eventTime, region: .awsRegion, profile: .requestParameters.profileArn,
     anchor: .requestParameters.trustAnchorArn, role: .requestParameters.roleArn,
     cert: .requestParameters.cert, ip: .sourceIPAddress} |
    select(.anchor == $anchor or $anchor == "")' | jq -s 'sort_by(.time)'
```

Any `CreateSession` against the attacker anchor means credentials were vended, pivot to the
`role` it targeted and reconstruct that role's session activity (it is fully in scope). The
presenting certificate is in `requestParameters.cert` (read its subject with `openssl x509`);
the certificate's CN also surfaces as `userIdentity.sessionContext ... sourceIdentity` on the
*downstream* calls the vended session makes, not as a field on `CreateSession` itself. If your
account does not emit `CreateSession`, hunt instead for role sessions on any rolesanywhere-trusting
role from Query 2 that you cannot attribute to a legitimate workload.

#### Query 4: Full session reconstruction of the principal that created the anchor

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

ACCESS_KEY_ID="<access-key-from-Query-1>"
REGION="<region-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$START" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

Look for the rest of the chain and other persistence, `CreateProfile`, role trust-policy
edits, IAM backdoors, and remediate each with the relevant playbook.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Break the chain fast: disable the trust anchor (instantly stops credential issuance), delete
any attacker profile, close any over-permissive rolesanywhere-trusting role, and contain the
principal.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained. Use the **region** the anchor was created in (Query 1).

#### Step 1: Disable the trust anchor (stops it being usable immediately)

```bash
REGION="<region-from-Query-1>"
ANCHOR_ID="<trustAnchorId, from the anchor_arn/Query-2 sweep>"

# Disable first (preserves the resource as evidence; a disabled anchor cannot vend credentials).
aws rolesanywhere disable-trust-anchor --trust-anchor-id "$ANCHOR_ID" --region "$REGION" && \
  echo "[OK] Disabled trust anchor $ANCHOR_ID (credential issuance halted)"
```

#### Step 2: Disable/delete any attacker profile

```bash
REGION="<region-from-Query-1>"
# profileId = the trailing segment of the profileArn (Query 1's profile_arn), or the Id
# column from Query 2(a)'s list-profiles output.
PROFILE_ID="<profileId, trailing segment of profile_arn, or from Query 2(a)>"

[ -n "$PROFILE_ID" ] && aws rolesanywhere disable-profile --profile-id "$PROFILE_ID" --region "$REGION" && \
  echo "[OK] Disabled profile $PROFILE_ID"
```

#### Step 3: Close over-permissive rolesanywhere-trusting roles

```bash
# For any role Query 2 flagged that should NOT trust Roles Anywhere (or trusts it without
# binding to a specific, known trust-anchor ARN), tighten or remove that trust:
ROLE="<role-name-from-Query-2>"
aws iam get-role --role-name "$ROLE" --query 'Role.AssumeRolePolicyDocument' --output json
# Replace with a trust policy that trusts rolesanywhere ONLY with a condition binding
# aws:SourceArn / the trust-anchor ARN to a KNOWN-good anchor, or detach the trust entirely:
#   aws iam update-assume-role-policy --role-name "$ROLE" --policy-document file://tightened-trust.json
echo "[i] Tighten or remove rolesanywhere trust on $ROLE (bind to a known anchor ARN)"
```

#### Step 4: Contain the principal that created the anchor

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
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role, root/federated: contain manually"
fi

# Deny further Roles Anywhere administration by the principal:
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["rolesanywhere:CreateTrustAnchor","rolesanywhere:CreateProfile","rolesanywhere:UpdateTrustAnchor","rolesanywhere:EnableTrustAnchor","iam:UpdateAssumeRolePolicy"],"Resource":"*"}]}'
if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  aws iam put-role-policy --role-name "$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')" \
    --policy-name "EmergencyDenyRolesAnywhere" --policy-document "$DENY_DOC"
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  aws iam put-user-policy --user-name "$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')" \
    --policy-name "EmergencyDenyRolesAnywhere" --policy-document "$DENY_DOC"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Delete the trust anchor and profile (all regions)

```bash
REGION="<region-from-Query-1>"
ANCHOR_ID="<trustAnchorId>"
PROFILE_ID="<profileId-if-any>"

[ -n "$PROFILE_ID" ] && aws rolesanywhere delete-profile --profile-id "$PROFILE_ID" --region "$REGION" && \
  echo "[OK] Deleted profile $PROFILE_ID"
aws rolesanywhere delete-trust-anchor --trust-anchor-id "$ANCHOR_ID" --region "$REGION" && \
  echo "[OK] Deleted trust anchor $ANCHOR_ID"
```

Repeat for every unexpected anchor/profile Query 2 surfaced, in each region.

#### Remediate the role-trust gate and other persistence

- For every role that trusted `rolesanywhere.amazonaws.com` inappropriately, remove/tighten
  the trust (Step 3) so no orphaned anchor can be reused.
- From Query 4, remediate anything else the principal did (IAM backdoors, more anchors) with
  the relevant playbook.

#### Right-size Roles Anywhere permissions

```bash
SUSPECT_ROLE="<role-name>"
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table
# Remove rolesanywhere:CreateTrustAnchor / CreateProfile from any principal that is not the
# designated Roles Anywhere administrator.
```

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenyRolesAnywhere" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the trust anchor and profile are gone (all regions)

```bash
FAIL=0
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  CNT=$(aws rolesanywhere list-trust-anchors --region "$REGION" \
         --query "length(trustAnchors[?name=='stratus-red-team-trust-anchor'])" --output text 2>/dev/null)
  [ "${CNT:-0}" != "0" ] && [ -n "$CNT" ] && { echo "[FAIL] trust anchor still present in $REGION"; FAIL=1; }
done
[ "$FAIL" -eq 0 ] && echo "[OK] Attacker trust anchor absent in all regions"
```

#### Verify no role still trusts an unrecognised trust anchor

```bash
# Re-run Query 2(b). Expect only baseline-approved roles trusting rolesanywhere.amazonaws.com,
# each bound (via condition) to a known-good trust-anchor ARN.
echo "[i] Re-run Query 2(b); every remaining rolesanywhere-trusting role must be baseline-approved."
```

#### Verify no credential issuance since containment

```bash
CONTAINED_AT="<iso8601-containment-timestamp>"
USED=0
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  N=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateSession \
    --start-time "$CONTAINED_AT" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson | select(.eventSource=="rolesanywhere.amazonaws.com") | .eventTime' | grep -c .)
  USED=$((USED + N))
done
[ "$USED" -eq 0 ] && echo "[OK] No Roles Anywhere credential issuance since containment" \
                  || echo "[i] $USED CreateSession event(s) since containment, confirm each is a legitimate, baseline anchor"
```

#### Confirm the corrected detection fires

```bash
echo "Re-run the emulation and confirm Rule A fires HIGH on the CreateTrustAnchor, and that"
echo "the corrected rule does NOT fire on the DisableTrustAnchor/DeleteTrustAnchor cleanup."
echo "Confirm Rule B would fire on a role newly trusting rolesanywhere.amazonaws.com."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could register an external CA as an AWS identity source | `rolesanywhere:CreateTrustAnchor` available outside a designated Roles Anywhere admin; no SCP restriction |
| Persistence is credential-free and survives key rotation | Roles Anywhere issues role credentials from a certificate, nothing to rotate on the AWS side |
| Chain went undetected | Shipped rule bundled cleanup events, ignored `CreateProfile` and the role-trust gate, and assumed a single region |
| Roles trusted the service too loosely | Role trust policies trusted `rolesanywhere.amazonaws.com` without binding to a specific, known trust-anchor ARN, so a *new* anchor could satisfy them |
| Blind spot in an unmonitored service | Roles Anywhere is rarely inventoried; no baseline of anchors/profiles/trusting roles |

### Recommended Guardrails

**Restrict Roles Anywhere administration (primary control)**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// deny creating trust anchors/profiles outside the designated Roles Anywhere admin.
{
  "Effect": "Deny",
  "Action": ["rolesanywhere:CreateTrustAnchor", "rolesanywhere:CreateProfile", "rolesanywhere:UpdateTrustAnchor", "rolesanywhere:EnableTrustAnchor"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/rolesanywhere-admin", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

```json
// SCP fragment: if you do not use IAM Roles Anywhere at all, deny it outright org-wide.
{
  "Effect": "Deny",
  "Action": "rolesanywhere:*",
  "Resource": "*"
}
```

**Structural controls**
- **Bind every rolesanywhere-trusting role to a specific trust-anchor ARN** via a `Condition` (`aws:SourceArn` on the known anchor), so a rogue anchor cannot satisfy the role's trust
- Prefer trust anchors sourced from **AWS Private CA (`AWS_ACM_PCA`)** over externally-supplied `CERTIFICATE_BUNDLE`s, and alert on any `CERTIFICATE_BUNDLE` anchor
- Maintain a **baseline inventory** of trust anchors, profiles, and rolesanywhere-trusting roles across all regions; reconcile on a schedule
- If Roles Anywhere is unused, disable it via SCP (above) so any use is impossible, not just alarmed

**Detection improvements**
- Deploy Rule A (`CreateTrustAnchor`/`CreateProfile`, any) and Rule B (role trusting the service) across all regions; never the shipped cleanup-inclusive match
- Alert on `CERTIFICATE_BUNDLE` self-signed sources and on `CreateSession` against unrecognised anchors

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1550.001 - Use Alternate Authentication Material: Application Access Token (as mapped by MANIFEST) |
| MITRE tactic | MANIFEST tags Persistence |
| Primary API | `rolesanywhere:CreateTrustAnchor` (register attacker CA), exploitable only with `CreateProfile` + a role trusting `rolesanywhere.amazonaws.com` |
| Event source | `rolesanywhere.amazonaws.com` (**regional**, hunt every region); role-trust edits under `iam.amazonaws.com` (global) |
| Key discriminator | A trust anchor whose CA is attacker-controlled (self-signed `CERTIFICATE_BUNDLE`), plus a profile pointing at privileged roles, plus a role trusting the service, the *chain*, though `CreateTrustAnchor` itself is rare enough to alert on alone |
| Cert visibility | The CA cert PEM is in `requestParameters.source.sourceData.x509CertificateData` (public data, logged), read it with `openssl x509` |
| Sweep tools | `rolesanywhere list-trust-anchors` / `list-profiles` (per region) + `iam get-role` trust-policy scan (global; returns the policy **decoded**) |
| "Was it used" pivot | `rolesanywhere:CreateSession` against the anchor/profile (verify the exact event name), then the downstream role session |
| Containment order | `disable-trust-anchor` (instant, preserves evidence) → disable/delete profile → tighten trusting roles → delete anchor |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException` |
| Resources created | None persisted, the emulation disables + deletes its own trust anchor (a real attack leaves it) |

**MITRE mapping note (flag):** the MANIFEST maps **T1550.001**, whose canonical name is
*Use Alternate Authentication Material: Application Access Token* and whose canonical tactics
are **Defense Evasion / Lateral Movement**, not Persistence, which the MANIFEST tags. It is a
loose fit: registering a CA as an identity source is closer to **T1556 (Modify Authentication
Process)** or **T1098 (Account Manipulation)** for the persistence framing. The MANIFEST's
technique *name* is the upstream Stratus label, not a canonical MITRE name. Flagged as a
mapping-precision finding; the operational content above is unaffected.

### Revert

The emulation disables and deletes its own trust anchor on cleanup, so a normal run leaves
nothing; there is no `pulumi` infra to destroy. After a **real** incident, disable then delete
every unexpected trust anchor and profile in **every region**, tighten each rolesanywhere-trusting
role to a known anchor, and restrict/disable Roles Anywhere via SCP; the credential-free path
persists until the anchor (and any completing profile/role trust) is removed, regardless of any
key rotation.
