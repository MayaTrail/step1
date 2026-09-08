# Detection Note — T1110 (Brute Force) / T1212 (Exploitation for Credential Access)

**Signal:** an `authenticate` or `jwt-validation` action at the load balancer failed, with the
reason distinguishing an attack from an identity-provider outage.

**The families are the whole detection.** AWS maps ALB authentication error reasons to two
CloudWatch metrics, and the split is exactly the triage decision:

- **`ELBAuthFailure`** — `AuthInvalidCookie`, `AuthInvalidGrantError`, `AuthInvalidIdToken`,
  `AuthInvalidStateParam`, `AuthInvalidTokenResponse`, `AuthInvalidUserinfoResponse`,
  `AuthMissingCodeParam`, `AuthMissingStateParam`. The **request** was bad. Attack signal.
- **`ELBAuthError`** — `AuthTokenEpRequestFailed`, `AuthTokenEpRequestTimeout`,
  `AuthUserinfoEpRequestFailed`, `AuthUserinfoEpRequestTimeout`, `AuthUnhandledException`,
  `AuthMissingHostHeader`, `AuthUserinfoResponseSizeExceeded`. The **identity provider** was
  unreachable. Availability signal.

**What the original rule got wrong** — it matches `NOT error_reason:"-"`, which is both families.
During an IdP outage every client produces the second family simultaneously, so a threshold of 14
in five minutes fires for every source address at once. The security on-call is paged for an
identity team's incident, at fleet scale, and the rule is muted within the week. The corrected set
ships the outage family at **informational**, so the routing is explicit rather than a matter of
whoever triages it first.

*It also excludes the strongest signal in the field it reads.* JWT validation failures appear in
the same `error_reason` field but arise from a `jwt-validation` action, and the rule's
`actions_executed:"authenticate"` filter drops them. `JWTSignatureValidationError` means a token
was presented whose signature does not verify — forged, signed with the wrong key, or using an
algorithm the configuration forbids. That has no benign explanation at volume and it is the
highest-confidence authentication event this log source produces.

*And it separates nothing within the attack family.* `AuthInvalidStateParam` and
`AuthMissingStateParam` are not a user with a stale tab: the `state` parameter is the OAuth CSRF
defence, binding an authorization response to the browser session that began it. Requests failing
on it are the shape of authorization-code interception. They are rare enough not to need a
threshold, and they ship as their own rule at high.

## The grouping key may not be the client

AWS on the `client:port` field: *"If there is a proxy in front of the load balancer, this field
contains the IP address of the proxy."* ALB access logs carry **no `X-Forwarded-For` field**. So
behind CloudFront, or any reverse proxy, every request in the world groups onto a handful of edge
addresses — a per-client threshold then fires constantly on aggregate traffic or attributes
nothing. In that topology the detection belongs in the CloudFront log or the web ACL, and this rule
is not the control. The shipped correlation says so in its own description rather than producing
confidently wrong attribution.

## Counts here are approximate in both directions

AWS: *"Elastic Load Balancing logs requests on a best-effort basis. We recommend that you use
access logs to understand the nature of the requests, not as a complete accounting of all
requests."* Delivery is eventually consistent, and *"the load balancer can deliver multiple logs
for the same period"* — most likely under high traffic, which is when a threshold is closest to
firing. Thresholds in these rules are set where an order-of-magnitude error would not change the
verdict, because a precise threshold on an imprecise count is false precision.

## Response levers

**No username is available.** Access logs carry no subject claim, no session identifier and no
user. The load balancer authenticated or did not; who it was is in the identity provider's own
logs, and the join is on time and client address. Say that in the incident rather than implying
attribution the log cannot support.

**Successes are not countable.** A successful `authenticate` leaves `error_reason` as `-`, which is
indistinguishable from a request that never attempted authentication. So a failure-to-success
ratio — the natural brute-force metric — cannot be computed from this source at all. Volume and
error-reason shape are what remain.

**MITRE:** `T1110` for the volume rules, the source's own mapping. `T1212 — Exploitation for
Credential Access` for the state-parameter and JWT rules, because a forged signature and a broken
CSRF binding are attempts to defeat the mechanism rather than to exhaust it. Both verified live
2026-08-30.

**Severity:** high for a JWT signature failure and for repeated state-parameter failures, medium
for sustained request-side rejections, informational for the IdP family. The distance between high
and informational is the single field the source rule ignores.

**GuardDuty:** no coverage of load balancer authentication. GuardDuty's brute-force findings cover
SSH and RDP, not application-layer OIDC or JWT. There is nothing to defer to here.

**Files here:**
- `sigma_t1110.yml` — five documents: `alb_auth_request_failure` (low base rule),
  `alb_auth_state_param_failure` (high), `alb_jwt_validation_failure` (high), an `event_count`
  correlation on request-side failures per source (medium), and `alb_idp_unreachable`
  (informational, routed away from the security queue by design).
- `kql_t1110.kql` — the families kept separate in the output, with the client field split and the
  proxy caveat carried in the query.

Full response procedure is in `../PLAYBOOK.md`.
