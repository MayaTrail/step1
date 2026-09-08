# CloudTrail — verified service behaviour

Audited 2026-08-30 against AWS documentation. Every claim below is quoted or directly derived from
a cited page. Shared by every `cloudtrail.*` playbook; do not restate it in each one.

---

## 1. `StopLogging` is the only way to stop recording, and AWS says using it is rare

Source: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html

> Suspends the recording of AWS API calls and log file delivery for the specified trail. **Under
> most circumstances, there is no need to use this action. You can update a trail without stopping
> it first. This action is the only way to stop recording.**

Two things follow, and both matter for severity:

- There is no benign "we stopped it to reconfigure" story. AWS states outright that a trail can be
  updated while running. A `StopLogging` in an estate that manages CloudTrail through IaC is
  therefore close to unexplainable, and rating it below the trail-modification rules — as the
  source pack does — inverts the order.
- Nothing else suspends recording. A rule covering `StopLogging` and `DeleteTrail` covers the
  complete set of ways to end delivery from the trail side.

## 2. A failed `StopLogging` is a better signal than a successful one

> **For a trail enabled in all Regions, this operation must be called from the Region in which the
> trail was created, or an `InvalidHomeRegionException` will occur. This operation cannot be called
> on the shadow trails (replicated trails in other Regions) of a trail enabled in all Regions.**

An actor who does not already know the trail's home Region will get `InvalidHomeRegionException` on
the first attempt. That failure is:

- **high fidelity** — there is no ordinary reason for automation to call `StopLogging` in the wrong
  Region;
- **early** — it happens before logging actually stops;
- **discarded by every rule that filters on success**, which is what `NOT _exists_:errorCode` does.

The other error codes worth reading rather than dropping:

| Error | What it tells you |
|---|---|
| `InvalidHomeRegionException` | Called from a non-home Region — the caller was guessing |
| `NotOrganizationMasterAccountException` | A member account tried to touch an organization trail |
| `TrailNotFoundException` | The caller was enumerating trail names |
| `InsufficientDependencyServiceAccessPermissionException` | Missing service-linked role for an org resource |

## 3. Organization trails cannot be tampered with from a member account

Source: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html

> Users with CloudTrail permissions in member accounts will be able to see organization trails
> (including the trail ARN) ... **However, users in member accounts will not have sufficient
> permissions to delete organization trails, turn logging on or off, change what types of events are
> logged, or otherwise alter organization trails in any way.**

So the blast radius of every tampering technique here depends on a fact the event does not carry:
whether the trail is an organization trail. In an estate with a management-account organization
trail, a compromised member account cannot stop logging at all, and a `StopLogging` attempt there
fails. Any playbook that treats "a trail was stopped" as "logging has stopped" is wrong wherever an
organization trail is in force — and the reverse mistake, assuming an org trail exists, is worse.

Note also that member accounts **can see** the org trail and its ARN, so failed attempts against it
are the expected shape of a member-account compromise probing its own visibility.

## 4. Global service events land in `us-east-1`, which breaks single-Region coverage

> As of November 22, 2021, AWS CloudTrail changed how trails capture global service events. Now,
> events created by Amazon CloudFront, AWS Identity and Access Management, and AWS STS are recorded
> in the Region in which they were created, the **US East (N. Virginia) Region, us-east-1**.

> When `IncludeGlobalServiceEvents` is `true`, CloudTrail delivers global service events only to
> single-Region trails in US East (N. Virginia). For multi-Region trails,
> `IncludeGlobalServiceEvents` must be `true`.

Consequence: a single-Region trail outside `us-east-1` does not receive **IAM or STS** events at
all. Every IAM playbook in this set depends on those events, and a coverage review that confirms
"a trail exists and is logging" without checking `IsMultiRegionTrail` and `HomeRegion` can report
green while IAM activity is invisible.

`lookup-events` and the console **Event history** behave differently from trails here — they show
these events in the Region where they occurred — so a responder can find an event by hand that no
trail ever delivered to the SIEM.

## 5. Four event types, and only one is on by default

> CloudTrail logs four types of events: Management events, Data events, **Network activity events**,
> Insights events.

> **By default, trails and event data stores log management events, but not data or Insights
> events.**

Network activity events (VPC endpoint activity) are the newest type and are also off by default. A
`PutEventSelectors` or `PutInsightSelectors` call that narrows or removes selectors changes what is
captured **while the trail continues to report as logging** — which is why trail *modification*
needs its own use case rather than being folded in with stopping it.

## 6. Log files are not ordered, so correlations must key on `eventTime`

> **CloudTrail log files aren't an ordered stack trace of the public API calls, so events don't
> appear in any specific order.**

Any `temporal_ordered` correlation in this project — and there are several — orders on the
`eventTime` field, not on ingestion or file order. A backend that orders by arrival will produce
false negatives on the exact sequences these rules exist to catch, and it will do so silently.

## 7. Insights can detect the absence of calls, which is the deadman's-switch case

> Your account typically logs 20 calls per minute to the Amazon EC2 `AuthorizeSecurityGroupIngress`
> API, but your account **starts to log zero calls** ... An Insights event is logged at the start of
> the unusual activity.

Insights is off by default and billed separately, but it is the AWS-native form of the "no logs
received" detection, and it operates on call *rate* rather than on delivery. It does not replace a
delivery heartbeat: Insights events are themselves delivered through the trail, so a stopped trail
stops the Insights events too.

---

## MITRE currency, verified 2026-08-30

| ID | Status | Name | Tactic |
|---|---|---|---|
| `T1685` | live | Disable or Modify Tools | Defense Impairment |
| `T1685.002` | live | Disable or Modify Tools: Disable or Modify Cloud Log | Defense Impairment |
| `T1654` | live | Log Enumeration | Discovery |
| `T1070` | live | Indicator Removal | Defense Evasion |

`T1685.002`
is the correct mapping for stopping, deleting or narrowing a trail. `T1654` is correct for *reading*
the logging configuration and is the one mapping the source pack got right.
