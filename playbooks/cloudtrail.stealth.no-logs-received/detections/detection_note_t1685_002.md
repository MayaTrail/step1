# Detection Note — T1685.002 (Disable or Modify Tools: Disable or Modify Cloud Log)

**Signal:** the delivery path breaking — the destination bucket or the KMS key — which produces
silence while the trail keeps reporting healthy.

## Absence cannot be detected by a rule engine

Sigma, and every engine of its kind, evaluates when an event arrives. When no event arrives, nothing
evaluates. An "absence" rule authored inside a rule engine therefore reports clean forever, and
clean-forever is indistinguishable from working.

So the heartbeat here is specified as a **scheduled check** in `../PLAYBOOK.md` §1, not shipped as a
rule. What the rules cover instead is the set of causes that *are* events.

## The source rule detects the symptom and rates it above every cause

P1 for the silence, against P2 for the trail being stopped, P2 for deleted, P3 for modified. The
causes arrive first and name what happened; the silence arrives up to two hours later and says only
that something is wrong somewhere. A responder paged by the symptom has strictly less to work with.

Its `group_by` is also the **ingestion pipeline's own stream identifier**, not a trail. That
conflates a stopped trail with a broken collector, an expired credential, a network fault and a
genuinely dormant account — which have entirely different responses, and the benign ones are more
common. That is how a P1 becomes an ignored P1.

## The silent causes no CloudTrail rule covers

Stopping, deleting and modifying a trail are CloudTrail API calls and are covered by the sibling
directories. Delivery also fails, with `IsLogging` still true, when something changes **outside**
CloudTrail:

| Change | Effect |
|---|---|
| Destination bucket policy drops the `cloudtrail.amazonaws.com` write statement | Delivery fails; only `LatestDeliveryError` shows it |
| Destination bucket deleted | Delivery fails **and the historical log files are gone** |
| Lifecycle rule with a short expiry | Logs arrive and are deleted afterwards — evidence destruction on a delay |
| KMS key disabled or scheduled for deletion | Delivery fails, or objects arrive permanently unreadable |

The bucket deletion is worth singling out: it is the **only** action in this whole set that destroys
the historical record. AWS is explicit that deleting a *trail* leaves the bucket and its files
intact, so the trail is not where the evidence is at risk — the bucket is.

## Response levers

**`LatestDeliveryError` is the field that matters and it is not an event.** Nothing emits it. Only a
scheduled `get-trail-status` reads it, which is why the heartbeat has to pair "did we stop
receiving?" with "is AWS still delivering?" — those have opposite responses and the alert alone
distinguishes neither.

**A scheduled key deletion does not warn again.** `ScheduleKeyDeletion` sets a waiting period of
seven to thirty days. When it expires, every object encrypted with that key becomes permanently
unreadable, and no event marks the moment. The alert on the scheduling call is the only warning
there will be.

**Check the lifecycle policy, not just the bucket policy.** A short expiry on the log bucket looks
like cost management and destroys evidence on a timer. It is the quietest item in the table above.

**Populate both lists before deploying.** The rules match on bucket and key identity; deployed with
placeholder values they become a general S3 and KMS monitor and will be tuned off.

**MITRE:** `T1685.002` is the live
mapping, verified live 2026-08-30.

**GuardDuty:** no finding type covers CloudTrail delivery failure. `Stealth:IAMUser/
CloudTrailLoggingDisabled` covers a stop only, so every cause in the table above produces no
GuardDuty signal.

**Files here:**
- `sigma_t1685_002.yml` — four documents: `cloudtrail_destination_key_disabled` (critical),
  `cloudtrail_destination_bucket_deleted` (critical), `cloudtrail_destination_bucket_altered`
  (high), and `cloudtrail_any_management_event` — an informational base rule that exists only to
  name the heartbeat stream for the scheduled check, and which must never be routed.
- `kql_t1685_002.kql` — surfaces every delivery-path change with a plain-language cause, and states
  inline why the heartbeat itself belongs in a scheduled check rather than a query.

Full response procedure is in `../PLAYBOOK.md`.
