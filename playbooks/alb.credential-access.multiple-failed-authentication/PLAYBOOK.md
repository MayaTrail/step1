# IR Playbook: Authentication Failures at the Load Balancer — `error_reason` on `authenticate` and `jwt-validation` actions

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential access (session tokens, OAuth flows and JWTs are being guessed, replayed or forged at the load balancer's authentication layer) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High for a JWT signature that does not verify or for repeated OAuth state-parameter failures — both are attempts to defeat the mechanism rather than to guess a credential. Medium for sustained request-side rejections. The source rule rates everything the same, which is why an identity-provider outage and a token-forgery attempt arrive as the same alert. |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1110 |
| Services in Scope | Elastic Load Balancing, Cognito or the external OIDC provider, CloudFront and AWS WAF where fronted, CloudTrail |

**What the technique does:** the load balancer is doing the authentication, so the attacker attacks
the load balancer's authentication. Three shapes. A session cookie is guessed or replayed —
`AuthInvalidCookie`. An OAuth authorization response is injected without the matching `state`
value, which is login CSRF or authorization-code interception — `AuthInvalidStateParam`. Or a JWT
is minted with the wrong key and presented in the `Authorization` header —
`JWTSignatureValidationError`. All three land in the same `error_reason` field of the access log,
and they are not the same event.

**Why the usual reflexes miss it.** The reflex is to count authentication failures, and the field
mixes two populations. AWS maps the codes to two different CloudWatch metrics: `ELBAuthFailure`
means the *request* was bad, and `ELBAuthError` means the *identity provider* was unreachable.
Counting both means an IdP outage produces a burst from every client on earth at once, which looks
exactly like a distributed brute-force attack and is not one.

**Detection thesis:** the error reason is the detection, not the count. Split the families, promote
the two reasons that have no benign explanation at volume — a state parameter that does not match
and a signature that does not verify — and route the availability family away from the security
queue explicitly.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **ALB access logs enabled**, with the caveat that AWS calls them best-effort and *"not a complete
  accounting of all requests"*. `../alb.stealth.no-logs-from-aws-alb/` is the playbook for their
  absence; this one assumes they exist.
- **Identity provider logs**, correlated by time and client address. Access logs carry **no
  username, no subject claim and no session identifier** — the identity is only in the IdP.
- **CloudFront or web ACL logs where the load balancer is fronted.** Behind a proxy the access log's
  client field holds the proxy address, and ALB access logs have no `X-Forwarded-For` field, so
  per-client detection has to happen upstream.
- **CloudWatch metrics `ELBAuthFailure`, `ELBAuthError` and `JWTValidationFailureCount`**, which
  are the same split the rules use and are cheaper to alert on for rate.

**Alerting (must be pre-configured)**
- **`JWTSignatureValidationError` — a token whose signature does not verify → P0**
- **More than three `AuthInvalidStateParam` or `AuthMissingStateParam` from one source in 15 minutes → P0**
- **A single `AuthInvalidStateParam` or `AuthMissingStateParam` → P1**
- **50 or more request-side authentication rejections from one source in 15 minutes → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- Access to the identity provider's session and token administration — the containment for this
  technique is mostly there, not in AWS.
- The current JWKS endpoint and key IDs, so a signature failure can be checked against a key
  rotation before it is treated as forgery.

**Known IOC Baselines**
- Whether a proxy sits in front of the load balancer. This single fact decides whether the client
  field means anything, and it should be recorded rather than rediscovered during triage.
- The key rotation schedule for JWT signing. A rotation produces a bounded burst of signature
  failures from legitimate clients, and knowing the schedule turns that from an incident into a line.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `error_reason: JWTSignatureValidationError` — the token's signature does not verify | ALB access logs | T1212 |
| P0 | More than three `AuthInvalidStateParam` / `AuthMissingStateParam` from one source within 15 minutes | ALB access logs (correlation) | T1212 |
| P1 | A single `AuthInvalidStateParam` or `AuthMissingStateParam` | ALB access logs | T1212 |
| P1 | ≥ 50 request-side authentication rejections (`ELBAuthFailure` family) from one source in 15 minutes | ALB access logs (correlation) | T1110 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `JWTClaimValueInvalid` or `JWTClaimNotPresent` — signature verified, claim did not | ALB access logs | T1212 |
| P2 | Request-side rejections spread across many sources with an identical reason and user agent | ALB access logs | T1110 |
| P3 | Any `ELBAuthError` family reason — identity provider unreachable. Availability, routed to the identity or platform team | ALB access logs / CloudWatch | — |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `NOT error_reason:"-"` matches both error families | AWS maps these codes to two metrics — `ELBAuthFailure` (bad request) and `ELBAuthError` (IdP unreachable). During an IdP outage every client produces the second family at once, so a threshold of 14 in 5 minutes fires for every source address simultaneously. The security on-call is paged for an identity team's outage, and the rule is muted | Two rule sets. The `ELBAuthError` family ships at **informational** so the routing is explicit rather than left to whoever triages first |
| `actions_executed:"authenticate"` excludes JWT validation | JWT failures are recorded in the same `error_reason` field but arise from a `jwt-validation` action. `JWTSignatureValidationError` — a token whose signature does not verify — is the highest-confidence event this log source produces, and the rule cannot see it | A dedicated JWT rule at high, matched on the error reason rather than on the action |
| No distinction inside the attack family | `AuthInvalidStateParam` is the OAuth CSRF binding failing, which is authorization-code interception rather than a stale tab. Buried among cookie failures at a threshold of 14, it never surfaces on its own | Its own rule at high, with no threshold — it is rare enough in normal traffic that a single occurrence is worth a look |
| `group_by client_ip` with a proxy in front | AWS: *"If there is a proxy in front of the load balancer, this field contains the IP address of the proxy."* ALB access logs carry no `X-Forwarded-For`, so behind CloudFront the whole internet groups onto a few edge addresses and the threshold is meaningless in both directions | The correlation states the caveat in its own description and names the correct detection point for that topology — the CloudFront log or the web ACL |
| Threshold of 14 in 5 minutes, precisely | AWS documents the logs as best-effort and *"not a complete accounting"*, with eventually-consistent delivery and possible duplicates under high traffic. A precise threshold on an imprecise count is false precision | Thresholds set where an order-of-magnitude error would not change the verdict, and the imprecision stated in the rule |
| `actions_executed` matched as a scalar | The field is a comma-separated list — `"authenticate,forward"` — so whether a scalar match hits depends on backend tokenisation | Match on `error_reason` values directly. They are single tokens and the semantics do not depend on the parser |

**Recommended detection — the error reason is the detection, with the outage family routed away.**

```yaml
# Authentication failures at the load balancer (T1110 / T1212)
#
# THE SOURCE RULE CONFLATES AN ATTACK WITH AN OUTAGE, AND THE OUTAGE IS LOUDER. It matches
# `actions_executed:"authenticate" AND NOT error_reason:"-"` — every non-empty error reason. AWS
# splits those codes into two families with two different CloudWatch metrics:
#
#   ELBAuthFailure — the REQUEST was bad: AuthInvalidCookie, AuthInvalidGrantError,
#     AuthInvalidIdToken, AuthInvalidStateParam, AuthInvalidTokenResponse,
#     AuthInvalidUserinfoResponse, AuthMissingCodeParam, AuthMissingStateParam.
#     These are attack signals.
#   ELBAuthError — the IDENTITY PROVIDER was unreachable or misbehaving:
#     AuthTokenEpRequestFailed, AuthTokenEpRequestTimeout, AuthUserinfoEpRequestFailed,
#     AuthUserinfoEpRequestTimeout, AuthUnhandledException, AuthMissingHostHeader,
#     AuthUserinfoResponseSizeExceeded. These are somebody else's availability problem.
#
# During an IdP outage EVERY client produces the second family, so a rule thresholding at 14 in
# five minutes fires for every source address at once, pages the security on-call for an identity
# team's incident, and is muted by the end of the week. The families are separate rules below and
# the outage family ships at informational, deliberately routed away from the security queue.
#
# IT ALSO MISSES THE STRONGEST SIGNAL AVAILABLE. JWT validation failures are recorded in the same
# error_reason field but arise from a `jwt-validation` action rather than `authenticate`, so the
# source rule's action filter excludes them entirely. JWTSignatureValidationError means a token was
# presented whose signature does not verify — forged, or signed with the wrong key. There is no
# benign explanation for that at volume, and it is the single highest-confidence authentication
# event this log source produces.
#
# THE GROUPING KEY MAY NOT BE THE CLIENT. AWS on the client:port field: "If there is a proxy in
# front of the load balancer, this field contains the IP address of the proxy." Behind CloudFront
# or any reverse proxy, every request collapses onto a handful of edge addresses — a per-client
# threshold then either never attributes anything or fires constantly on aggregate traffic. ALB
# access logs carry no X-Forwarded-For field, so in that topology the correct detection point is
# the CloudFront log or the web ACL, not here. Stated rather than silently mis-grouped.
#
# COUNTS IN THIS SERVICE ARE APPROXIMATE IN BOTH DIRECTIONS. AWS: "Elastic Load Balancing logs
# requests on a best-effort basis. We recommend that you use access logs to understand the nature
# of the requests, not as a complete accounting of all requests." Delivery is eventually consistent
# and "the load balancer can deliver multiple logs for the same period". Thresholds below are set
# where an order-of-magnitude error would not change the verdict.
title: Load balancer authentication request rejected
id: 6a04f2c7-9b18-4e53-80d6-13c7e5a94f28
name: alb_auth_request_failure
status: experimental
description: >-
  An authenticate action failed for a reason attributable to the request rather than to the
  identity provider — a bad or forged cookie, an invalid grant code, a tampered ID token, a missing
  authorization code. Base rule for the correlation below and a low-volume signal in its own right.
  Only the ELBAuthFailure family is matched; the ELBAuthError family is a separate rule at
  informational so an IdP outage cannot page this queue.
references:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
  - https://attack.mitre.org/techniques/T1110/
tags:
  - attack.credential-access
  - attack.t1110
logsource:
  product: aws
  service: elb
detection:
  auth_failure:
    error_reason:
      - 'AuthInvalidCookie'
      - 'AuthInvalidGrantError'
      - 'AuthInvalidIdToken'
      - 'AuthInvalidTokenResponse'
      - 'AuthInvalidUserinfoResponse'
      - 'AuthMissingCodeParam'
  condition: auth_failure
falsepositives:
  - >-
    A user with a stale session cookie after an application redeploy or a cookie-secret rotation.
    Genuinely common, which is why this ships as a base rule feeding a correlation rather than as
    an alert on a single occurrence.
level: low
---
title: OAuth state parameter invalid or missing at the load balancer
id: d51b8e40-2c97-4a16-bf03-7e6905c2ad81
name: alb_auth_state_param_failure
status: experimental
description: >-
  The authenticate action failed on the `state` parameter. This is separated from the other request
  failures because the state parameter is the OAuth CSRF defence — it binds an authorization
  response to the browser session that started it. A response arriving with a missing or
  non-matching state is the shape of an authorization-code interception or a login-CSRF attempt,
  not of a user with an expired tab. It is rare in normal traffic, so it does not need a threshold.
references:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
  - https://attack.mitre.org/techniques/T1212/
tags:
  - attack.credential-access
  - attack.t1212
logsource:
  product: aws
  service: elb
detection:
  state_failure:
    error_reason:
      - 'AuthInvalidStateParam'
      - 'AuthMissingStateParam'
  condition: state_failure
falsepositives:
  - >-
    A user who bookmarked a callback URL, or a browser that stripped the cookie carrying the state.
    Both happen; both are single events. A repeat from one source is not either of those.
level: high
---
title: JWT presented to the load balancer failed validation
id: 8f36c9a2-4071-4de8-95b4-c208a1e73b6d
name: alb_jwt_validation_failure
status: experimental
description: >-
  A jwt-validation action rejected the token in the Authorization header. The source rule cannot
  see any of these, because it filters on actions_executed containing `authenticate` and JWT
  validation is a different action. JWTSignatureValidationError is the one worth paging on: it
  means a token was presented whose signature does not verify — forged, signed with the wrong key,
  or using an algorithm the configuration does not permit. JWTClaimValueInvalid means the signature
  verified and a claim did not, which is a valid token being used where it should not be.
references:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-verify-jwt.html
  - https://attack.mitre.org/techniques/T1212/
tags:
  - attack.credential-access
  - attack.t1212
logsource:
  product: aws
  service: elb
detection:
  jwt_forged:
    error_reason:
      - 'JWTSignatureValidationError'
      - 'JWTClaimValueInvalid'
      - 'JWTClaimNotPresent'
      - 'JWTClaimFormatInvalid'
  condition: jwt_forged
falsepositives:
  - >-
    A client still presenting tokens signed by a retired key during a key rotation. Real, bounded
    in time, and it should be correlated with the rotation rather than allowlisted permanently.
level: high
---
title: Repeated authentication rejections from one source
id: 2e7a5013-b8c4-49f7-a06d-51938fe2c74b
status: experimental
description: >-
  One source address accumulated request-side authentication failures. The threshold is set where
  an order-of-magnitude counting error would not change the verdict, because AWS documents these
  logs as best-effort with possible duplicate delivery — a precise threshold on an imprecise count
  is false precision. READ THE GROUPING CAVEAT: behind CloudFront or any reverse proxy the client
  field carries the PROXY's address, so this correlation groups the whole internet into a few
  values. In that topology this rule is not the control and the web ACL or CloudFront log is.
references:
  - https://attack.mitre.org/techniques/T1110/
tags:
  - attack.credential-access
  - attack.t1110
correlation:
  type: event_count
  rules:
    - alb_auth_request_failure
  group-by:
    - client_ip
  timespan: 15m
  condition:
    gte: 50
falsepositives:
  - >-
    A misconfigured client retrying a rejected token in a loop. Distinguished by the error reason
    being identical every time and by the source being a known service address.
level: medium
---
title: Load balancer could not reach the identity provider
id: 9c8d13f5-6e20-4b74-83a1-0f47c6b528de
name: alb_idp_unreachable
status: experimental
description: >-
  Base rule and availability signal — NOT for the security queue, and shipped at informational so
  that routing is explicit rather than a matter of taste. These are the ELBAuthError family: the
  token endpoint or the user-info endpoint failed or timed out, or the load balancer hit an
  unhandled exception. During an identity provider outage every client produces these
  simultaneously, which is exactly the burst the source rule interprets as a brute-force attack
  from every address at once. Route to the identity or platform team.
references:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
tags:
  - attack.credential-access
  - attack.t1110
logsource:
  product: aws
  service: elb
detection:
  idp_error:
    error_reason:
      - 'AuthTokenEpRequestFailed'
      - 'AuthTokenEpRequestTimeout'
      - 'AuthUserinfoEpRequestFailed'
      - 'AuthUserinfoEpRequestTimeout'
      - 'AuthUnhandledException'
      - 'AuthMissingHostHeader'
      - 'AuthUserinfoResponseSizeExceeded'
  condition: idp_error
falsepositives:
  - >-
    Not false positives — these are genuine availability events. The rule exists so they are
    counted somewhere other than the brute-force detection, and so an IdP outage is legible as an
    outage rather than as an attack from every address on the internet.
level: informational
```

What this set structurally cannot do: it cannot name a user, because access logs carry no subject
claim or session identifier. It cannot count successes — a successful authentication leaves
`error_reason` as `-`, indistinguishable from a request that never attempted one — so the natural
failure-to-success ratio is not computable from this source. And behind a proxy it cannot identify
the client at all.

---

### Key Investigation Queries

> Queries 1 and 2 read the access logs, most often through Athena over the S3 prefix. Field names
> below use the access-log names from `../_ground-truth/alb.md` §3; adjust to your table's column
> naming. Queries 3 and 4 read the identity provider and CloudTrail.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: the failures, split by family

```sql
-- Athena over the ALB access log table. The families are separated in the SELECT, not merged.
SELECT
  client_ip,
  error_reason,
  CASE
    WHEN error_reason IN ('AuthInvalidStateParam','AuthMissingStateParam') THEN 'state'
    WHEN error_reason LIKE 'JWT%' THEN 'jwt'
    WHEN error_reason IN ('AuthTokenEpRequestFailed','AuthTokenEpRequestTimeout',
                          'AuthUserinfoEpRequestFailed','AuthUserinfoEpRequestTimeout',
                          'AuthUnhandledException','AuthMissingHostHeader',
                          'AuthUserinfoResponseSizeExceeded') THEN 'idp-outage'
    ELSE 'request'
  END AS family,
  COUNT(*)                AS failures,
  MIN(time)               AS first_seen,
  MAX(time)               AS last_seen,
  ARBITRARY(user_agent)   AS sample_agent,
  ARBITRARY(request_line) AS sample_request
FROM alb_access_logs
WHERE error_reason <> '-'
  AND time >= to_iso8601(current_timestamp - interval '24' hour)
GROUP BY client_ip, error_reason, 3
ORDER BY failures DESC;
```

Read the `family` column first. If `idp-outage` dominates, this is an availability incident and the
rest of the playbook does not apply — hand it to the identity or platform team. If `jwt` or `state`
appear at all, they outrank any volume in the `request` family: a signature that does not verify is
a stronger signal than ten thousand bad cookies.

#### Query 2 — Sweep: is the client field meaningful here at all

```bash
REGION="us-east-1"
LB_ARN="<load-balancer-arn>"

echo "== is anything in front of this load balancer =="
aws elbv2 describe-load-balancers --load-balancer-arns "$LB_ARN" --region "$REGION" --output json | \
  jq -r '.LoadBalancers[] | "scheme=\(.Scheme)  dns=\(.DNSName)  type=\(.Type)"'

echo
echo "[i] If a CloudFront distribution or another proxy fronts this DNS name, the access log's"
echo "    client field holds the PROXY's address and ALB access logs carry no X-Forwarded-For."
echo "    Per-client thresholds are then meaningless and the detection belongs upstream."
aws cloudfront list-distributions --output json 2>/dev/null | \
  jq -r --arg d "$(aws elbv2 describe-load-balancers --load-balancer-arns "$LB_ARN" --region "$REGION" --output text --query 'LoadBalancers[0].DNSName')" \
  '.DistributionList.Items[]? | select((.Origins.Items[]?.DomainName // "") == $d)
   | "[!] fronted by CloudFront distribution \(.Id) — investigate there, not here"' \
  || echo "[i] no CloudFront distribution found with this load balancer as an origin"

echo
echo "== the authentication configuration on the listener rules =="
for L in $(aws elbv2 describe-listeners --load-balancer-arn "$LB_ARN" --region "$REGION" \
           --output json | jq -r '.Listeners[].ListenerArn'); do
  aws elbv2 describe-rules --listener-arn "$L" --region "$REGION" --output json | \
    jq -r '.Rules[] | select([.Actions[].Type] | any(. == "authenticate-oidc" or . == "authenticate-cognito"))
           | "rule priority=\(.Priority) actions=\([.Actions[].Type] | join(","))"'
done
```

#### Query 3 — Inspect: what the identity provider saw

```bash
REGION="us-east-1"
USER_POOL_ID="<cognito-user-pool-id>"
SINCE=$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)

echo "== Cognito control-plane events, if Cognito is the provider =="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=cognito-idp.amazonaws.com \
  --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | jq -s 'sort_by(.time)' | head -60

echo
echo "[!] The access log has NO username. Whoever was being attacked is identifiable only in the"
echo "    identity provider's own sign-in logs, joined on time and — if no proxy is in front —"
echo "    client address. State that join in the incident rather than implying certainty."
```

#### Query 4 — For a JWT failure: rule out a key rotation before calling it forgery

```bash
JWKS_URL="<issuer>/.well-known/jwks.json"

echo "== key IDs the issuer currently publishes =="
curl -s "$JWKS_URL" | jq -r '.keys[] | "kid=\(.kid)  alg=\(.alg)  use=\(.use // "-")"' \
  || echo "[!] could not fetch JWKS — note this in the incident; the failures cannot be classified without it"

echo
echo "[i] Decode the header of a rejected token (header only — do NOT paste a live token into a"
echo "    third-party decoder) and compare its kid against the list above:"
echo "      kid present in JWKS      -> signature genuinely failed. Treat as forgery."
echo "      kid absent from JWKS     -> a retired key. Correlate with the rotation schedule;"
echo "                                  a bounded burst from legitimate clients looks like this."
echo "      no kid, or unexpected alg -> algorithm confusion attempt. Treat as forgery."
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The containment for this technique is mostly at the identity provider, not in AWS. What AWS can do
quickly is stop the traffic reaching the authentication layer at all.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Classify before acting

```bash
FAMILY="<dominant-family-from-Query-1>"

case "$FAMILY" in
  idp-outage)
    echo "[i] This is an availability incident. Hand to the identity or platform team."
    echo "    Do not rate-limit or block — the clients are legitimate and failing." ;;
  jwt)
    echo "[i] Token forgery or a key rotation. Run Query 4 BEFORE containing anything." ;;
  state)
    echo "[i] Authorization-code interception or login CSRF. Containment is at the IdP:"
    echo "    invalidate outstanding authorization codes and review redirect URI allowlists." ;;
  request)
    echo "[i] Credential or session guessing. Rate-limiting at the web ACL is the fast lever." ;;
  *)
    echo "[!] Family not determined — re-run Query 1 before proceeding." ;;
esac
```

This step exists because the wrong action here is worse than none. Rate-limiting during an IdP
outage removes the legitimate clients that were about to recover.

#### Step 2 — Rate-limit at the web ACL, not at the load balancer

```bash
REGION="us-east-1"
WEB_ACL_NAME="<web-acl-name>"
WEB_ACL_ID="<web-acl-id>"

aws wafv2 get-web-acl --name "$WEB_ACL_NAME" --scope REGIONAL --id "$WEB_ACL_ID" \
  --region "$REGION" --output json | \
  jq -r '.WebACL.Rules[] | select(.Statement.RateBasedStatement != null)
         | "existing rate rule: \(.Name) limit=\(.Statement.RateBasedStatement.Limit) key=\(.Statement.RateBasedStatement.AggregateKeyType)"' \
  || echo "[i] no web ACL, or no rate-based rule — a rate-based rule scoped to the callback path is the fast containment"

echo "[i] Scope the rate rule to the authentication callback path, not to the whole site."
echo "    A site-wide rate limit during a credential attack takes the application down for"
echo "    everyone, which is the outcome the attacker would have settled for."
echo "[!] If a proxy fronts the load balancer, rate-limit at THAT layer — a rule keyed on the"
echo "    ALB's view of the client address will key on the proxy and throttle everybody."
```

#### Step 3 — Invalidate sessions and tokens at the provider

For the `request` family, invalidate the sessions the attacker may have obtained: revoke refresh
tokens for any account that shows a successful sign-in from the attacking source in Query 3. For
the `jwt` family confirmed as forgery, the signing key is the issue — rotate it, and note that
every legitimate token signed by the old key becomes invalid at the same moment, which is a
planned outage rather than a side effect. For the `state` family, invalidate outstanding
authorization codes and audit the redirect URI allowlist.

#### Step 4 — Contain the source, if the client field means anything

If Query 2 showed no proxy in front, blocking the source address at the web ACL is worthwhile. If a
proxy is in front, the address in the log is the proxy and blocking it removes every legitimate
client behind it. This is the one containment step in this playbook that can cause a larger outage
than the incident, so the check in Query 2 is a prerequisite rather than a nicety.

---

## 4. Eradication

### Remove Attacker Access

#### Rotate what was reachable

For a confirmed forgery, the signing key is compromised or the algorithm configuration permits
something it should not — `JWTSignatureValidationError` accompanied by tokens with no `kid` or an
unexpected `alg` is algorithm confusion, and the fix is to pin the accepted algorithms rather than
to rotate.

#### Fix the state-parameter handling if it is the application's

An ALB-managed OIDC flow generates and validates `state` itself; a repeated failure there is
attacker-driven. If the application performs its own OAuth flow behind the load balancer, the
failures may be its own defect, and that is a code fix rather than an incident response.

#### Right-size the exposure of the authentication endpoint

The callback path is the only path that needs to accept authorization responses. A web ACL rule
restricting it — by rate, by geography where applicable, or by requiring the load balancer's own
session cookie — reduces the surface without touching the application.

#### Remove emergency rules once clean

Rate-based rules added during containment should be removed or lowered deliberately, and the
removal recorded. A forgotten emergency rate limit becomes an unexplained availability problem
months later.

---

## 5. Recovery

### Restore Clean State

#### Verify the failure rate has returned to baseline, by family

```bash
# Assert per family rather than describing the condition. JWT_FAILS and STATE_FAILS come from
# re-running §2 Query 1 over the last hour; export them before running this.
: "${JWT_FAILS:?count of error_reason=JWTSignatureValidationError in the last hour}"
: "${STATE_FAILS:?count of error_reason=AuthInvalidStateParam in the last hour}"
: "${STATE_BASELINE:?same-hour count from last week}"

FAIL=0
if [ "$JWT_FAILS" -eq 0 ]; then
  echo "[OK] jwt: zero signature failures"
else
  echo "[FAIL] jwt: $JWT_FAILS signature failure(s) — any residual is unexplained"; FAIL=1
fi
if [ "$STATE_FAILS" -le "$STATE_BASELINE" ]; then
  echo "[OK] state: $STATE_FAILS at or below baseline $STATE_BASELINE"
else
  echo "[FAIL] state: $STATE_FAILS above baseline $STATE_BASELINE"; FAIL=1
fi
# An idp-outage family at zero must be CONFIRMED by the identity team, not inferred from silence.
[ "$FAIL" -eq 0 ] && echo "[OK] recovery verified per family" \
                  || echo "[FAIL] recovery not verified — do not close"
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire at high on:"
echo "  error_reason=JWTSignatureValidationError"
echo "  (the source rule cannot see this at all — it comes from a jwt-validation action)"
echo "and MUST fire at high on:"
echo "  error_reason=AuthInvalidStateParam"
echo "The rule MUST NOT page on:"
echo "  error_reason=AuthTokenEpRequestTimeout   (identity provider unreachable — informational)"
echo "  error_reason=-                           (successful, or no authentication attempted)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| An identity-provider outage paged the security on-call | The rule counted both AWS error families as authentication failures |
| Token forgery attempts were invisible | The rule filtered on the `authenticate` action, and JWT validation is a different action in the same field |
| OAuth state failures were buried | They were counted alongside stale-cookie failures under one threshold |
| Per-source thresholds did not attribute | A proxy in front of the load balancer meant the client field held the proxy address, and ALB access logs carry no `X-Forwarded-For` |
| Nobody could say which user was targeted | Access logs carry no username, and identity provider logs were not correlated |

### Recommended Guardrails

**Keep the authentication configuration from being weakened**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["elasticloadbalancing:ModifyRule", "elasticloadbalancing:ModifyListener",
             "elasticloadbalancing:DeleteRule"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Pin the accepted JWT algorithms explicitly. Algorithm confusion is defeated by configuration, not
  by detection.
- Put a rate-based web ACL rule on the authentication callback path as a standing control, sized
  well above legitimate use. It costs nothing when quiet and is the containment already in place
  when it is not.
- Record whether each load balancer is fronted by a proxy, as an attribute of the service inventory.
  It determines whether every per-client detection on it means anything.
- Alert on the CloudWatch metrics `ELBAuthFailure`, `ELBAuthError` and `JWTValidationFailureCount`
  separately. They are the same split as these rules, computed by AWS, and cheaper for rate alerts.

**Detection improvements**
- Never merge an availability error family with an attack error family in one rule. This is the
  clearest example in the corpus of what that costs — the outage family is larger and arrives all
  at once, so it defines the alert's reputation.
- Alert on error reasons with no benign explanation without a threshold, and use thresholds only
  for reasons that occur normally. A signature that does not verify needs no count.
- Set thresholds at an order of magnitude, not a precise number, on telemetry the provider
  documents as best-effort with duplicate delivery.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1110 — Brute Force |
| MITRE tactic | Credential Access (TA0006) |
| Primary API | None — the technique is HTTP traffic. The observable is the `error_reason` field of the access log |
| Event source | ALB access logs; CloudWatch metrics `ELBAuthFailure`, `ELBAuthError`, `JWTValidationFailureCount` |
| Key discriminator | The specific `error_reason` value, and which of AWS's two error families it belongs to |
| Ground-truth signal | The identity provider's own sign-in record, joined on time and — absent a proxy — client address |
| "Was it used" pivot | Not available in the access log: a successful authentication leaves `error_reason` as `-`, indistinguishable from a request that never attempted one |
| Blast radius | Every account reachable through the authenticated application, plus anything the session grants downstream |
| Error strings | `ELBAuthFailure` family: `AuthInvalidCookie`, `AuthInvalidGrantError`, `AuthInvalidIdToken`, `AuthInvalidStateParam`, `AuthInvalidTokenResponse`, `AuthInvalidUserinfoResponse`, `AuthMissingCodeParam`, `AuthMissingStateParam`. `ELBAuthError` family: `AuthTokenEpRequestFailed`, `AuthTokenEpRequestTimeout`, `AuthUserinfoEpRequestFailed`, `AuthUserinfoEpRequestTimeout`, `AuthUnhandledException`, `AuthMissingHostHeader`, `AuthUserinfoResponseSizeExceeded`. JWT: `JWTSignatureValidationError`, `JWTClaimValueInvalid`, `JWTClaimNotPresent`, `JWTClaimFormatInvalid`, `JWTRequestFormatInvalid`, `JWTHeaderNotPresent`, plus the `JWKS*` endpoint errors |

**MITRE mapping note:** the source's `T1110 — Brute Force` is kept for the volume rules, where
credentials or session tokens are being guessed. `T1212 — Exploitation for Credential Access` is
added for the state-parameter and JWT rules, because a forged signature and a failed OAuth CSRF
binding are attempts to *defeat* the authentication mechanism rather than to exhaust it — a
distinction the source rule's single mapping cannot express. Both verified live 2026-08-30.

### Residual Risk

The access log cannot name a user, so which accounts were targeted is knowable only from the
identity provider, and only if its logs were retained. It cannot count successes either — a
successful authentication is indistinguishable from a request that never attempted one — so the
question "did any of these work" is not answerable from AWS at all, and a quiet log after
containment is not evidence that nothing succeeded before it. Behind a proxy, the source of the
attack was never recorded here in the first place. And because AWS documents these logs as
best-effort with possible duplicate delivery, every count in the investigation is approximate in
both directions.
