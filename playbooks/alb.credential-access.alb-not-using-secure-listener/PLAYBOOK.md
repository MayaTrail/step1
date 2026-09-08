# IR Playbook: Plaintext HTTP Served by a Load Balancer — an HTTP listener created by `CreateListener` that forwards instead of redirecting

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential access / collection (requests reach the application over unencrypted HTTP, so everything they carry is readable by anything on the path) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. Every session cookie, `Authorization` header and form body carried by a plaintext request is exposed to anything on the network path, and capture leaves no trace — so the exposure cannot be scoped downward by investigation. The source rule requires 99 occurrences in an hour before it says anything, which means the quietest and most sensitive endpoints never trigger it. |
| MITRE Tactics | Credential Access, Collection |
| MITRE Techniques | T1557 |
| Services in Scope | Elastic Load Balancing, AWS Certificate Manager, AWS Config, CloudTrail |

**What the technique does:** nothing, on the attacker's part, beyond being on the path. A listener
on port 80 forwards to a target group instead of redirecting to HTTPS — because a redirect rule was
never added, because a certificate expired and someone "temporarily" switched the listener, or
because a service was stood up quickly and TLS was going to be added later. From then on every
request to that endpoint carries its credentials in clear text across whatever networks lie between
the client and the load balancer.

**Why the usual reflexes miss it.** The reflex is to alert on plaintext traffic, and most estates
have plenty of it legitimately: a port 80 listener that redirects to HTTPS is the recommended
pattern, and it generates a plaintext access log entry for every client that arrives on the wrong
scheme. A rule that cannot tell a redirect from a forward fires constantly in a correctly
configured estate and says exactly the same thing in an exposed one. The second reflex is to look
for evidence of interception — and there is none to find, anywhere, ever.

**Detection thesis:** `actions_executed` is the discriminator. `redirect` is correct; `forward`
means the application received the plaintext request. One such request is the finding, because
reachability over plaintext is a configuration fact rather than a volume phenomenon.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **ALB access logs enabled** with `type`, `actions_executed`, `ssl_protocol` and the client field
  available. `../alb.stealth.no-logs-from-aws-alb/` covers their absence.
- **CloudTrail management events for `elasticloadbalancing.amazonaws.com`** — `CreateListener` and
  `ModifyListener` are how the exposure is created, and they fire before any traffic finds it.
- **AWS Config recording `AWS::ElasticLoadBalancingV2::Listener`**, so listener protocol has a
  history and "when did this become plaintext" is answerable after the trail retention window.

**Alerting (must be pre-configured)**
- **A plaintext (`http` or `ws`) request with `actions_executed` containing `forward` and not `redirect` → P0**
- **`CreateListener` or `ModifyListener` with `Protocol: HTTP` whose default action is not a redirect → P0**
- **A request completing over `TLSv1` or `TLSv1.1` → P1**
- **A listener's SSL policy changed to one permitting a deprecated protocol version → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials; `jq`.
- A valid ACM certificate for the domain, already issued and validated. The containment for this
  is "add an HTTPS listener", and waiting for DNS validation during an incident is the slow path —
  a pre-issued certificate turns a multi-hour response into a two-minute one.
- The credential rotation procedure for the application's session mechanism, because that is the
  actual remediation.

**Known IOC Baselines**
- Which load balancers are internet-facing versus internal (`Scheme`), since it changes severity
  but not the finding.
- The intended SSL policy for every HTTPS listener, so a downgrade is a diff rather than a
  judgement.
- Which endpoints legitimately have no TLS — ideally none, and if any, recorded as exceptions with
  an owner and an end date.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `type` in (`http`, `ws`) with `actions_executed` containing `forward` and not `redirect`, from a non-private client | ALB access logs | T1040 |
| P0 | `CreateListener` / `ModifyListener` with `Protocol: HTTP` whose `defaultActions` are not a redirect | CloudTrail (`elasticloadbalancing`) | T1557 |
| P1 | The same plaintext forward from a private client address | ALB access logs | T1040 |
| P1 | `ssl_protocol` of `TLSv1` or `TLSv1.1` on completed requests | ALB access logs | T1557 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A listener's SSL policy modified to one permitting a deprecated TLS version | CloudTrail (`elasticloadbalancing`) | T1557 |
| P2 | An HTTPS listener deleted while an HTTP listener on the same load balancer remains | CloudTrail (`elasticloadbalancing`) | T1557 |
| P3 | `chosen_cert_arn` naming a certificate approaching expiry — the common cause of a "temporary" switch to HTTP | ALB access logs / ACM | T1557 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Does not read `actions_executed` | A port 80 listener that redirects to HTTPS is the **recommended** pattern and produces a plaintext log entry for every client. The rule cannot distinguish it from a listener that forwards, so it fires continuously in a correctly configured estate and says the same thing in an exposed one | `actions_executed` contains `forward` and not `redirect`. That single field is the difference between correct configuration and credential exposure |
| Threshold of 99 in one hour | A volume test applied to a configuration fact. One forwarded plaintext request proves the listener serves; a low-traffic internal admin endpoint — the most likely thing left on port 80 and the most valuable to intercept — never reaches 99 | No threshold. Reachability does not need repeated observation to be true |
| Restricted to `elb_status_code` 200–299 | A plaintext request that received a 401 still carried its credential over the wire before being rejected. The exposure happened before the status code existed | Status code projected for context and used for nothing. It has no bearing on whether the secret was exposed |
| `type:"http"` only | The field takes `http \| https \| h2 \| grpcs \| ws \| wss`. `ws` is the unencrypted WebSocket form and is unmatched, so every plaintext WebSocket is invisible — the transport most likely to carry a session token in its first frame | Both `http` and `ws` matched |
| Geo-enrichment used to mean "external" | Depends on an enrichment pipeline that may not exist, and excludes internal sources entirely — but a credential on an internal network is still readable by anything on that path | Client address read directly; internal sources kept as a lower-severity finding rather than dropped |
| Watches traffic only | An endpoint too quiet to generate log volume stays misconfigured indefinitely and never appears. That is precisely the endpoint at issue | A CloudTrail rule at listener creation, plus the state sweep in Query 2 |

**Recommended detection — the `forward`-not-`redirect` test, plus the listener that created it.**

```yaml
# Plaintext HTTP served by a load balancer (T1557 / T1040)
#
# THE FIELD THAT SEPARATES A DEFECT FROM THE CORRECT PATTERN IS THE ONE THE SOURCE RULE IGNORES.
# An HTTP listener whose only job is to redirect to HTTPS is the RECOMMENDED configuration —
# clients that arrive on port 80 are told to come back over TLS, and nothing sensitive crosses the
# wire. An HTTP listener that FORWARDS to a target group is the defect: the request body, the
# cookies and the Authorization header all traversed the internet in clear text.
#
# Both produce `type: http` access log entries. They are distinguished by actions_executed:
#   "redirect" -> the load balancer answered with a 301/302 to the HTTPS URL. Correct.
#   "forward"  -> the application received the plaintext request. This is the finding.
# The source rule reads neither, so it cannot tell a correctly configured estate from an exposed
# one, and in a correctly configured estate it fires constantly on the redirects.
#
# ONE REQUEST IS THE FINDING, NOT NINETY-NINE. The source rule requires 99 matches in an hour.
# Reachability over plaintext is a configuration fact: a single forwarded HTTP request from the
# internet proves the listener exists and serves. A low-traffic internal admin endpoint — the most
# likely thing to be left on port 80 and the most valuable to intercept — never reaches 99 in an
# hour and never alerts. Thresholds are appropriate for volume-based attacks; this is not one.
#
# RESTRICTING TO 2xx MISSES THE CREDENTIAL. The source rule matches elb_status_code 200-299 only.
# A plaintext request that received a 401 still carried its credential over the wire before being
# rejected — the interception already happened. Response status is irrelevant to whether the
# secret was exposed, and it is not filtered on below.
#
# `ws` IS ALSO PLAINTEXT. The type field takes http | https | h2 | grpcs | ws | wss. The unencrypted
# values are `http` AND `ws`; `wss` is the TLS form. A rule listing only `http` misses every
# plaintext WebSocket, which is the transport most likely to carry a session token in its first
# frame.
#
# ssl_protocol IS CORROBORATION, NOT THE TEST. AWS documents it as "-" when the listener is not an
# HTTPS listener, so it agrees with `type` by construction. It is matched as an alternative rather
# than a conjunction so a pipeline that drops one field still leaves the rule working.
title: Plaintext HTTP request forwarded to a target
id: a37e5f10-84b6-4c29-9d05-6e28c1704b93
name: alb_plaintext_request_served
status: experimental
description: >-
  A request arrived over unencrypted HTTP or WebSocket and the load balancer FORWARDED it to a
  target rather than redirecting it to TLS. Everything in that request crossed the network in clear
  text — cookies, Authorization headers, form bodies, query parameters. This is a configuration
  defect that one matching request proves, so it carries no threshold. The redirect case, which is
  the recommended pattern for a port 80 listener, is excluded by the actions filter rather than by
  a status code.
references:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
  - https://attack.mitre.org/techniques/T1040/
tags:
  - attack.credential-access
  - attack.collection
  - attack.t1557
  - attack.t1040
logsource:
  product: aws
  service: elb
detection:
  plaintext_type:
    type:
      - 'http'
      - 'ws'
  served:
    actions_executed|contains: 'forward'
  redirected:
    actions_executed|contains: 'redirect'
  condition: plaintext_type and served and not redirected
falsepositives:
  - >-
    A health check or monitoring probe deliberately hitting port 80 to confirm the redirect works.
    Those are answered by the redirect action and are already excluded; one that is forwarded is
    the finding regardless of who sent it.
  - >-
    An internal-only load balancer where plaintext is an accepted risk. Legitimate as a recorded
    exception; note that the ground truth for this service treats the load balancer's scheme as
    the thing to check, and an internal scheme is verifiable directly rather than inferred here.
level: high
---
title: Plaintext listener created or modified on a load balancer
id: 5c0b9d42-1e78-4a35-b6f9-30d7248ce15a
name: elb_plaintext_listener_configured
status: experimental
description: >-
  CreateListener or ModifyListener with Protocol HTTP. This is the control-plane cause and it fires
  at the moment the exposure is created rather than when traffic finds it — which matters
  particularly here, because a low-traffic endpoint may serve plaintext for months without
  generating enough log volume to notice. The rule deliberately matches every HTTP listener,
  including redirect-only ones, because the default action is in the same request and triage reads
  it: a defaultActions entry of type `redirect` is the correct pattern and `forward` is not.
references:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html
  - https://attack.mitre.org/techniques/T1557/
tags:
  - attack.credential-access
  - attack.t1557
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'elasticloadbalancing.amazonaws.com'
    eventName:
      - 'CreateListener'
      - 'ModifyListener'
  success:
    errorCode: null
  plaintext_protocol:
    requestParameters.protocol:
      - 'HTTP'
      - 'TCP'
  condition: selection and success and plaintext_protocol
falsepositives:
  - >-
    The redirect-only listener that every well-configured public load balancer has on port 80.
    Common and correct — read defaultActions in the same event, and confirm it is a redirect to
    HTTPS rather than a forward.
level: medium
---
title: Load balancer negotiated a deprecated TLS version
id: e64c8a17-72d3-4be0-95c1-08b46f2e37d9
name: alb_weak_tls_negotiated
status: experimental
description: >-
  A request completed over TLS 1.0 or TLS 1.1. The connection was encrypted, so this is a weaker
  finding than plaintext — but both versions are deprecated, both permit cipher suites with known
  weaknesses, and a listener that still negotiates them is one an attacker can downgrade a client
  onto. It is included here rather than as a separate use case because it is the same question the
  source rule was reaching for — is this traffic actually protected — and the answer has three
  states rather than two: plaintext, weak TLS, and current TLS.
references:
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
  - https://attack.mitre.org/techniques/T1557/
tags:
  - attack.credential-access
  - attack.t1557
logsource:
  product: aws
  service: elb
detection:
  weak_tls:
    ssl_protocol:
      - 'TLSv1'
      - 'TLSv1.1'
  condition: weak_tls
falsepositives:
  - >-
    A legacy client that genuinely cannot negotiate anything newer. Real in some estates, and the
    correct handling is a recorded exception with an end date rather than removing the rule — the
    exception is the risk being accepted, and it should be visible.
level: medium
```

What this set structurally cannot do: it cannot tell you whether anything was intercepted. Passive
capture leaves no trace in AWS or anywhere else, so there is no query that scopes the exposure
down. It also cannot show what was in the request — the access log carries the request line and no
headers or body — so a password in a POST body is invisible while a token in a query string is
not. The log is a floor on the exposure, never a measurement of it.

---

### Key Investigation Queries

> Query 1 reads the access logs, most often through Athena over the S3 prefix; field names follow
> `../_ground-truth/alb.md` §3. Queries 2–4 read the ELB, ACM and CloudTrail APIs. Load balancers
> are regional — run the state queries in every Region in use.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: what was served in the clear, and to whom

```sql
-- Athena over the ALB access log table.
-- Status code is SELECTed and never filtered on: a 401 response does not un-send the credential.
SELECT
  elb,
  type,
  actions_executed,
  elb_status_code,
  client_ip,
  COUNT(*)                AS requests,
  MIN(time)               AS first_seen,
  MAX(time)               AS last_seen,
  ARBITRARY(request_line) AS sample_request,
  ARBITRARY(user_agent)   AS sample_agent
FROM alb_access_logs
WHERE type IN ('http', 'ws')
  AND actions_executed LIKE '%forward%'
  AND actions_executed NOT LIKE '%redirect%'
  AND time >= to_iso8601(current_timestamp - interval '30' day)
GROUP BY elb, type, actions_executed, elb_status_code, client_ip
ORDER BY requests DESC;
```

`first_seen` is the start of the exposure window, and it is the number that matters — every
credential used against this endpoint since then should be treated as exposed. Read
`sample_request` for tokens in query strings, which the log *does* capture because AWS *"preserves
the URL sent by the client, as is"*. Anything in a header or body is not here and is exposed
anyway.

#### Query 2 — Sweep: every listener in the account, by protocol and default action

```bash
REGION="us-east-1"

for LB in $(aws elbv2 describe-load-balancers --region "$REGION" --output json | \
            jq -r '.LoadBalancers[] | "\(.LoadBalancerArn)|\(.Scheme)"'); do
  ARN="${LB%%|*}"; SCHEME="${LB##*|}"; NAME="${ARN##*/}"
  aws elbv2 describe-listeners --load-balancer-arn "$ARN" --region "$REGION" --output json | \
    jq -r --arg n "$NAME" --arg s "$SCHEME" '
      .Listeners[] |
      ([.DefaultActions[].Type] | join(",")) as $acts |
      if (.Protocol == "HTTP" or .Protocol == "TCP") and ($acts | contains("redirect") | not)
        then "[FAIL] \($n) (\($s)) listener :\(.Port) \(.Protocol) -> \($acts)   PLAINTEXT AND SERVING"
      elif (.Protocol == "HTTP" or .Protocol == "TCP")
        then "[OK]   \($n) (\($s)) listener :\(.Port) \(.Protocol) -> \($acts)   redirect only, correct"
      else "[OK]   \($n) (\($s)) listener :\(.Port) \(.Protocol) policy=\(.SslPolicy // "-")"
      end'
done
```

This is the query that finds the exposure on an endpoint nobody is using yet, which is the case the
source rule's threshold guarantees it will miss. A `[FAIL]` line is actionable on its own — no
traffic needs to have arrived. `Scheme` distinguishes `internet-facing` from `internal`, which
changes the severity and not the finding.

#### Query 3 — Inspect: the TLS posture of the listeners that do have it

```bash
REGION="us-east-1"

echo "== SSL policies in use, and what they permit =="
for LB in $(aws elbv2 describe-load-balancers --region "$REGION" --output json | \
            jq -r '.LoadBalancers[].LoadBalancerArn'); do
  aws elbv2 describe-listeners --load-balancer-arn "$LB" --region "$REGION" --output json | \
    jq -r --arg n "${LB##*/}" '.Listeners[] | select(.SslPolicy != null)
           | "\($n) :\(.Port) policy=\(.SslPolicy)"'
done | sort -u

echo
echo "== which policies still allow TLS 1.0 or 1.1 =="
for P in $(aws elbv2 describe-load-balancers --region "$REGION" --output json | \
           jq -r '.LoadBalancers[].LoadBalancerArn' | while read -r L; do
             aws elbv2 describe-listeners --load-balancer-arn "$L" --region "$REGION" \
               --output json | jq -r '.Listeners[].SslPolicy // empty'; done | sort -u); do
  aws elbv2 describe-ssl-policies --names "$P" --region "$REGION" --output json 2>/dev/null | \
    jq -r --arg p "$P" '.SslPolicies[] |
      ([.SslProtocols[]] | join(",")) as $protos |
      if ($protos | test("TLSv1(,|$)|TLSv1\\.1"))
        then "[FAIL] \($p) permits \($protos)"
        else "[OK]   \($p) permits \($protos)" end'
done

echo
echo "== certificates approaching expiry — the usual cause of a 'temporary' switch to HTTP =="
aws acm list-certificates --region "$REGION" --output json | jq -r '.CertificateSummaryList[].CertificateArn' | \
  while read -r C; do
    aws acm describe-certificate --certificate-arn "$C" --region "$REGION" --output json | \
      jq -r '.Certificate | select(.NotAfter != null)
             | "\(.DomainName)\texpires=\(.NotAfter)\tstatus=\(.Status)\trenewal=\(.RenewalEligibility // "-")"'
  done
```

#### Query 4 — Full session reconstruction of who changed the listener

```bash
REGION="us-east-1"
SINCE=$(date -u -v-90d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in CreateListener ModifyListener DeleteListener; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       lb: (.requestParameters.loadBalancerArn // "-"),
       protocol: (.requestParameters.protocol // "-"),
       port: (.requestParameters.port // "-"),
       policy: (.requestParameters.sslPolicy // "-"),
       actions: [(.requestParameters.defaultActions // [])[].type],
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'sort_by(.time)'
```

Ninety days, because these changes are usually old. The pattern to look for is an HTTPS listener
deleted or modified shortly before an HTTP listener gained a `forward` action — that is a
certificate problem being worked around, and it is the most common origin of this exposure.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Stop serving plaintext, then rotate. The order matters only in that rotating first accomplishes
nothing while the endpoint is still exposing the new credentials.

> Run every command under the **break-glass responder credentials** from §1.

#### Step 1 — Convert the plaintext listener to a redirect

```bash
REGION="us-east-1"
LISTENER_ARN="<http-listener-arn-from-Query-2>"
CASE_DIR="./ir-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$CASE_DIR"

aws elbv2 describe-listeners --listener-arns "$LISTENER_ARN" --region "$REGION" --output json \
  > "$CASE_DIR/listener-before.json"

PROTO=$(jq -r '.Listeners[0].Protocol' "$CASE_DIR/listener-before.json")
if [ "$PROTO" != "HTTP" ]; then
  echo "[FAIL] $LISTENER_ARN is $PROTO, not HTTP — wrong listener, or already fixed"
else
  aws elbv2 modify-listener --listener-arn "$LISTENER_ARN" --region "$REGION" \
    --default-actions '[{"Type":"redirect","RedirectConfig":{"Protocol":"HTTPS","Port":"443","StatusCode":"HTTP_301"}}]' \
    --output json | jq -r '.Listeners[] | "[OK] :\(.Port) \(.Protocol) -> \([.DefaultActions[].Type] | join(","))"'
  echo "[i] before-state saved to $CASE_DIR/listener-before.json"
fi
```

A redirect rather than a deletion: deleting the port 80 listener breaks every client and bookmark
that arrives on the wrong scheme, which turns a security fix into an outage. The redirect keeps
them working and stops the exposure at the same time.

**This requires an HTTPS listener on 443 to exist.** If Query 2 showed none, create it first with
the pre-issued certificate from §1 — redirecting to a port with nothing behind it is a complete
outage.

#### Step 2 — Confirm plaintext is no longer served

```bash
ENDPOINT="<load-balancer-dns-name>"

echo "[i] From a host outside the VPC:"
if command -v curl >/dev/null 2>&1; then
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "http://${ENDPOINT}/" 2>/dev/null)
  case "$CODE" in
    301|302|307|308) echo "[OK] port 80 returns $CODE — redirecting, not serving" ;;
    000)             echo "[OK] port 80 unreachable — listener removed entirely" ;;
    "")              echo "[!] no response captured — verify by another means" ;;
    *)               echo "[FAIL] port 80 returned $CODE — still serving content in the clear" ;;
  esac
else
  echo "[!] curl unavailable — verify by another means before declaring this contained"
fi
```

A 2xx here means the fix did not take, or another listener or rule still forwards. A 4xx is also a
failure for this purpose: the application answered, which means the request reached it.

#### Step 3 — Rotate everything the exposure could have carried

This is the actual remediation and it does not depend on evidence. Every session cookie,
`Authorization` header, API key and form-submitted password sent to that endpoint since Query 1's
`first_seen` should be treated as exposed. Invalidate all sessions on the application, rotate any
static API keys it accepts, and require re-authentication. **Do not scope this down by looking for
evidence of interception** — there is none to find, in AWS or anywhere else, and its absence means
nothing.

#### Step 4 — Contain the principal, if the change was not accountable

```bash
SUSPECT_ARN="<caller-arn-from-Query-4>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name = last segment
  aws iam put-user-policy --user-name "$U" --policy-name IR-Deny-All \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name = 2nd segment
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$R" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

Most instances of this are a certificate expiry worked around under time pressure, not an attack.
Read Query 4's surrounding events before containing anyone — an HTTPS listener deleted minutes
earlier tells you which it was.

---

## 4. Eradication

### Remove Attacker Access

#### Fix every other listener the sweep found

Re-run Query 2 in every Region. A plaintext-serving listener is rarely unique — the module or the
habit that produced one produced others, and the ones on quiet endpoints are the ones the traffic
rule would never have surfaced.

#### Raise the SSL policy on every HTTPS listener

Query 3's `[FAIL]` policies permit TLS 1.0 or 1.1. Move them to a current policy, and note that
doing so may break genuinely old clients — which is a decision to make deliberately with a date,
rather than by leaving the weak policy in place indefinitely.

#### Remove the reason it happened

If the cause was a certificate expiry, the fix is automated renewal and an alert on approaching
expiry, not a reminder. ACM-issued certificates for domains validated by DNS renew automatically;
imported certificates do not, and those are the ones that cause this.

#### Right-size who can modify listeners

`elasticloadbalancing:ModifyListener` and `DeleteListener` on a production load balancer belong to
a platform role with review, not to application deploy credentials.

---

## 5. Recovery

### Restore Clean State

#### Verify no listener serves plaintext, in any Region

```bash
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  for ARN in $(aws elbv2 describe-load-balancers --region "$REGION" --output json 2>/dev/null | \
               jq -r '.LoadBalancers[].LoadBalancerArn'); do
    aws elbv2 describe-listeners --load-balancer-arn "$ARN" --region "$REGION" --output json | \
      jq -r --arg r "$REGION" --arg n "${ARN##*/}" '
        .Listeners[] | select(.Protocol == "HTTP" or .Protocol == "TCP")
        | select(([.DefaultActions[].Type] | join(",")) | contains("redirect") | not)
        | "[FAIL] \($r) \($n) :\(.Port) \(.Protocol) serves plaintext"'
  done
done
# Assert, rather than leaving the operator to read the output. A plaintext listener whose default
# action is not a redirect is the finding, and zero of them is the pass condition.
PLAINTEXT=0
for REGION in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  for ARN in $(aws elbv2 describe-load-balancers --region "$REGION" --output json 2>/dev/null | \
               jq -r '.LoadBalancers[].LoadBalancerArn'); do
    N="$(aws elbv2 describe-listeners --load-balancer-arn "$ARN" --region "$REGION" --output json 2>/dev/null \
         | jq -r '[.Listeners[] | select(.Protocol == "HTTP" or .Protocol == "TCP")
                   | select(([.DefaultActions[].Type] | join(",")) | contains("redirect") | not)] | length')"
    PLAINTEXT=$((PLAINTEXT + ${N:-0}))
  done
done
if [ "$PLAINTEXT" -eq 0 ]; then
  echo "[OK] no listener forwards plaintext in any Region"
else
  echo "[FAIL] $PLAINTEXT plaintext-forwarding listener(s) remain — recovery is not complete"
fi
```

#### Verify the access log agrees

Re-run Query 1 over the hour since the fix. It must return no rows. A row after the change means
another listener or another rule still forwards — the default action is not the only path, and a
rule with a `forward` action on an HTTP listener survives changing the default.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  type=http  actions_executed=\"forward\"  (any elb_status_code, including 401)"
echo "and MUST fire equally on:"
echo "  type=ws    actions_executed=\"forward\"  — the case the source rule cannot see"
echo "The rule MUST NOT fire on:"
echo "  type=http  actions_executed=\"redirect\"  — the recommended port 80 pattern"
echo "  type=https actions_executed=\"forward\"   — ordinary encrypted traffic"
echo "and note there is no volume threshold: ONE forwarded plaintext request is the finding."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| An HTTP listener forwarded to a target group | No provisioning rule required port 80 listeners to be redirect-only |
| The exposure ran for an extended period | The detection needed 99 requests an hour, and the affected endpoint was quiet |
| A correctly configured estate produced constant alerts | The rule could not distinguish a redirect from a forward, so it was tuned down or ignored |
| The change was made under time pressure | A certificate expired without an alert, and the workaround was to switch the listener to HTTP |
| The scope of exposed credentials was unknown | Nothing recorded when the listener changed, and interception leaves no evidence |

### Recommended Guardrails

**Keep listener protocol out of application deploy credentials**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["elasticloadbalancing:CreateListener", "elasticloadbalancing:ModifyListener",
             "elasticloadbalancing:DeleteListener"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Make redirect-only the provisioning template for every port 80 listener, so a forwarding HTTP
  listener cannot be created by following the normal path.
- Use ACM certificates with DNS validation, which renew automatically. Imported certificates do
  not, and an expiring imported certificate is the most common origin of this exposure.
- Alert on certificate expiry at 30 and 7 days. The incident is usually the workaround, not the
  expiry.
- Set the SSL policy centrally and record `AWS::ElasticLoadBalancingV2::Listener` in AWS Config, so
  a downgrade is a diff against a known value.

**Detection improvements**
- Detect on configuration as well as traffic. The state sweep finds the exposure on an endpoint too
  quiet to generate log volume, which is the endpoint most likely to be misconfigured.
- Do not put a volume threshold on a configuration fact. Reachability does not need repeated
  observation to be true, and a threshold guarantees the quietest exposures are the ones missed.
- Read `actions_executed` in every plaintext rule. Without it the recommended pattern and the
  defect are the same event.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1557 — Adversary-in-the-Middle |
| MITRE tactic | Credential Access (TA0006), Collection (TA0009) |
| Primary API | None on the data path. The control-plane cause is `elasticloadbalancing:CreateListener` or `ModifyListener` with `Protocol: HTTP` |
| Event source | ALB access logs; `elasticloadbalancing.amazonaws.com` in CloudTrail |
| Key discriminator | `type` in (`http`, `ws`) with `actions_executed` containing `forward` and not `redirect` |
| Ground-truth signal | `describe-listeners` showing an HTTP listener whose default actions are not a redirect — live state, not a log |
| "Was it used" pivot | **None exists.** Passive capture leaves no trace in AWS or anywhere else; the absence of evidence carries no information |
| Blast radius | Every credential carried by any request to that endpoint since the listener changed — session cookies, `Authorization` headers, API keys, form-submitted passwords |
| Error strings | Not applicable. The access log records a successful request; `elb_status_code` describes the application's answer and has no bearing on the exposure |

**MITRE mapping note:** the source's `T1557 — Adversary-in-the-Middle` is kept, and `T1040 —
Network Sniffing` added, because interception of an unencrypted request requires no interposition
at all. The passive technique is both the more likely one and the one the exposure actually
enables; citing only `T1557` implies more attacker effort than the situation requires. Both
verified live 2026-08-30.

### Residual Risk

Every credential carried over the plaintext endpoint since the listener changed must be treated as
exposed, and there is no way to narrow that — capture leaves no trace, so no investigation reduces
the scope and a clean-looking log is not evidence. The access log understates what was exposed: it
carries the request line and no headers or body, so a token in a query string is visible while a
password in a POST body is not, and the sample requests in any report are a floor. If the
exposure predates the log retention window, its start date is unknown and the rotation scope is
"everything". And deprecated TLS versions left in place after the plaintext fix are the same
problem with more steps — encrypted, downgradeable, and still readable to an attacker willing to
do slightly more work.
