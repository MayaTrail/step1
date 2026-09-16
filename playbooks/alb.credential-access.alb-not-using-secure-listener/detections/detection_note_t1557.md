# Detection Note — T1557 (Adversary-in-the-Middle) / T1040 (Network Sniffing)

**Signal:** a request arrived over unencrypted HTTP or WebSocket and the load balancer **forwarded**
it to a target rather than redirecting it to TLS.

**The word `forward` is the entire detection.** An HTTP listener on port 80 whose only action is a
redirect to HTTPS is the configuration AWS recommends — clients that arrive in the clear are told
to come back over TLS and nothing sensitive crosses the wire. An HTTP listener that forwards is the
defect: the cookies, the `Authorization` header, the form body and the query string all traversed
the network in clear text. Both produce `type: http` access log entries, and only
`actions_executed` tells them apart.

**What the original rule got wrong** — three things, and each independently makes it unusable.

*It reads neither `actions_executed` nor anything equivalent.* So in a correctly configured estate
it fires continuously on redirects, and in an exposed one it produces the same alert. It cannot
distinguish the recommended pattern from the finding.

*Ninety-nine matches in an hour is a volume test applied to a configuration fact.* Reachability
over plaintext does not need to be observed repeatedly to be true. One forwarded request proves the
listener exists and serves — and a low-traffic internal admin endpoint, which is the most likely
thing to be left on port 80 and the most valuable to intercept, never reaches ninety-nine.

*Restricting to `elb_status_code` 200–299 misses the credential.* A plaintext request that received
a 401 still carried its credential over the wire before being rejected. The exposure happened
before the status code existed. Response status has no bearing on it and is not filtered on in the
corrected rules — it is projected so a responder can read it, and used for nothing.

Two smaller ones. **`ws` is a plaintext type**: the field takes `http | https | h2 | grpcs | ws |
wss`, and a rule listing only `http` misses every unencrypted WebSocket — the transport most likely
to carry a session token in its first frame. And the geo-enrichment standing in for "external" is
replaced by reading the client address directly, with internal sources kept as a **lower-severity
finding rather than excluded**: a credential on an internal network is still a credential anything
on that path can read.

## Three states, not two

The question the rule was reaching for is "is this traffic actually protected", and the answer has
three answers: plaintext, deprecated TLS, and current TLS. `alb_weak_tls_negotiated` covers the
middle one — TLS 1.0 and 1.1 are encrypted but deprecated, permit cipher suites with known
weaknesses, and represent a version an attacker can attempt to downgrade a client onto. It is a
weaker finding than plaintext and it is a finding.

## The control plane finds what traffic never will

`CreateListener` and `ModifyListener` with `Protocol: HTTP` fire at the moment the exposure is
created, which matters more here than in most services: an endpoint quiet enough to escape a
volume threshold is exactly the endpoint that stays misconfigured for months. Read `defaultActions`
in the same event — a `redirect` action is the correct pattern and a `forward` action is not. This
is the only view that finds a plaintext listener on an endpoint nobody is using yet.

## Response levers

**Rotate; do not investigate.** Passive capture leaves no trace anywhere in AWS, so there is no
query that establishes whether anything was intercepted. The correct posture is that every
credential carried over a plaintext request is exposed, and the remediation is rotation. An
investigation that concludes "we found no evidence of interception" has established nothing.

**The log understates the exposure and never overstates it.** Access logs carry the request *line*
— method, URL, version — and no headers and no body. A password in a POST body is invisible here.
A token in a query string is visible, because AWS *"preserves the URL sent by the client, as is"*.
So the sample requests in a report are a floor on what was exposed.

**Counts do not matter in this rule, which sidesteps a problem.** AWS documents these logs as
best-effort and *"not a complete accounting of all requests"*, with possible duplicate delivery.
Every other ALB rule has to work around that; this one does not, because the finding is that the
count is above zero.

**MITRE:** `T1557 — Adversary-in-the-Middle` from the source, kept, with `T1040 — Network Sniffing`
added: interception of an unencrypted request needs no interposition at all, so the passive
technique is the more likely of the two and the source's single mapping implies more attacker
effort than the situation requires. Both verified live 2026-08-30.

**Severity:** high for plaintext served from the internet, high-adjacent for plaintext served
internally (shipped at the same rule level, differentiated in the KQL verdict), medium for
deprecated TLS.

**GuardDuty:** no coverage. There is no finding type for a load balancer's listener protocol. AWS
Config has managed rules covering ALB listener security which are the closest equivalent, and they
evaluate configuration rather than traffic — complementary to the access-log rule here.

**Files here:**
- `sigma_t1557.yml` — three documents: `alb_plaintext_request_served` (high, the `forward`-not-
  `redirect` test), `elb_plaintext_listener_configured` (medium, CloudTrail, fires before any
  traffic), `alb_weak_tls_negotiated` (medium).
- `kql_t1557.kql` — per load balancer, separating internet from internal sources, with status codes
  projected and deliberately not filtered on.

Full response procedure is in `../PLAYBOOK.md`.
