# Detection Note — T1685.002 (Disable or Modify Tools: Disable or Modify Cloud Log)

**Signal:** `ModifyLoadBalancerAttributes` setting `access_logs.s3.enabled` to `false`, a load
balancer created and never given logging, or a log destination that stops accepting writes.

**An absence alert is a weaker control here than anywhere else in this corpus**, and it is worth
being precise about why. In VPC flow logs, an idle interface still emits a `NODATA` record, so
presence of records at least proves the pipeline is alive. An Application Load Balancer with no
requests **writes nothing at all**. Silence is the ordinary state of an unused load balancer, and
there is no record type that distinguishes it from a silenced one.

**What the original rule got wrong** — four things, and AWS documents all four.

*The `group_by` is empty.* The count is account-wide, so disabling access logs on one load balancer
among several changes the total by a fraction. The blind spot scales with everything else still
logging, which makes the rule weakest in the largest estates.

*AWS says the count is not a count.* *"Elastic Load Balancing logs requests on a best-effort basis.
We recommend that you use access logs to understand the nature of the requests, not as a complete
accounting of all requests."* Delivery is every five minutes per node, eventually consistent, and
*"the load balancer can deliver multiple logs for the same period"* — so records can be **both**
missing and duplicated, with duplication likeliest under high traffic. Every threshold in this
service is indicative only.

*Logging is off by default.* *"Access logs is an optional feature of Elastic Load Balancing that is
disabled by default."* A load balancer that has never logged is indistinguishable from one just
turned off, and only a state sweep separates them. That is why a `CreateLoadBalancer` rule ships
here at all — the default itself is the coverage gap.

*There is no separate logging resource to watch.* Access logging is a load balancer **attribute**,
so there is no `DeleteAccessLog` API. Turning it off is a key/value pair inside an attributes list,
and a rule reading a flat `requestParameters.enabled` matches nothing.

## The array-conjunction approximation, stated

Matching `attributes.key` and `attributes.value` as two fields in one Sigma block ANDs them across
the whole array rather than proving they belong to the same element — so a request disabling one
attribute while setting an unrelated one to `false` satisfies both. That is a deliberate superset;
the KQL uses `mv-apply` to expand the array and prove the pairing, and triage reads which pair it
actually was. Sigma has no per-element conjunction and inventing one would be worse than the
approximation.

## The quiet path: the attribute stays true and nothing lands

Deleting the destination bucket, or replacing its policy so the ELB log-delivery principal can no
longer `PutObject`, stops delivery while `access_logs.s3.enabled` still reads `true`. A
configuration check that reads only the attribute is satisfied. **There is no ELB-side error event
when delivery starts failing** — nothing is called — so only a scheduled read of the destination
finds it. A lifecycle rule expiring objects after a short period is the same outcome dressed as
cost control.

## Response levers

**State beats absence, and it answers a question the log cannot.**
`describe-load-balancer-attributes` returns `access_logs.s3.enabled` and the bucket per load
balancer, which is both "is it on right now" and "has this one ever had it on". Run it on a
schedule and diff it.

**AWS Config records `AWS::ElasticLoadBalancingV2::LoadBalancer`**, giving configuration history
for the attribute — the only source that can answer "when did this change" after the CloudTrail
retention window.

**MITRE:** `T1685.002` is the correct
current identifier. Verified live 2026-08-30.

**Severity:** high for a disable, medium for the creation-coverage and destination paths. The
blast radius is every `alb.*` detection plus any WAF investigation that relies on correlating web
ACL logs with access logs.

**GuardDuty:** no coverage. There is no finding type whose resource is a load balancer's logging
configuration.

**Files here:**
- `sigma_t1685_002.yml` — three CloudTrail documents: `elb_access_logging_disabled` (high),
  `elb_created_without_logging` (medium coverage check), `elb_log_destination_tampered` (medium).
- `kql_t1685_002.kql` — the control-plane view with `mv-apply` over the attributes array, and the
  per-load-balancer absence view in a commented section with the four-states argument beside it.

Full response procedure is in `../PLAYBOOK.md`.
