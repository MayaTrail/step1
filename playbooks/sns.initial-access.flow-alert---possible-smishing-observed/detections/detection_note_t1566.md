# Detection Note — T1566 (outbound SMS abuse / smishing from a compromised AWS account)

**Signal:** one principal enumerating the account's SMS posture and then changing it —
raising the monthly spend limit, registering sandbox destinations, setting a sender id —
which is the management-plane setup for sending bulk SMS from your account to third parties.

**The harm points outward, and that changes what "response" means.** In every other use case
in this set the victim is the account. Here the account is the *weapon*: the people harmed
are strangers who receive a phishing text that carries your originating number or sender id,
your account pays for every message, and your sender reputation with the carriers is what
degrades. Nothing in the response undoes any of that. Reading this playbook expecting a data
breach will produce the wrong actions.

## The original flow cannot fire, and the reason is structural

Its second stage matches `eventName:("Publish")`.

1. **`Publish` is a CloudTrail data event.** AWS's published example carries
   `"eventCategory": "Data"` and `"managementEvent": false`, and data events are off by
   default. On a default trail the second stage never matches, so the flow never completes.
2. **Enabling SNS data events does not fix it.** AWS lists the loggable SNS data-event
   resource types as `AWS::SNS::Topic` and `AWS::SNS::PlatformEndpoint`, and states
   plainly: *"SNS resource type `AWS::SNS::PhoneNumber` is not logged by CloudTrail."* A
   `Publish` carrying a `PhoneNumber` and no `TopicArn` — which is exactly what sending an
   SMS to a stranger is — produces **no CloudTrail record under any trail configuration**.
   The sending step of this technique is invisible to CloudTrail by design.
3. **The message text is never available either.** Even for topic-based publishes with data
   events enabled, `requestParameters.message`, `.subject` and `.messageAttributes` are
   recorded as the literal `HIDDEN_DUE_TO_SECURITY_REASONS`.
4. **The flow's own group-by is empty**, so its two stages are not bound to the same
   principal. An enumeration by one identity and an unrelated publish by a legitimate
   application would satisfy it account-wide. Even in a hypothetical account where stage two
   could fire, the correlation would be meaningless.

So the correction is not a repair of the flow but a replacement of it: the detection moves
entirely onto the **management plane**, where the setup is fully logged by default and cannot
be turned off, and the correlation is grouped by `userIdentity.arn`.

## What the source rule left out, and what it is worth

The building blocks watch `GetSMSAttributes` and `GetSMSSandboxAccountStatus`. Both are real
and both are kept. But the events that actually distinguish preparation from curiosity are
absent from the original entirely:

- **`SetSMSAttributes`** — sets the account-wide `MonthlySpendLimit`, the default sender id,
  the default SMS type and the delivery-status logging role. The account spend quota
  **defaults to 1.00 USD per month**, and AWS stops publishing SMS within minutes of it
  being exceeded, so no volume campaign fits inside the default. Raising it is close to
  mandatory for abuse, and it is a management event.
- **`CreateSMSSandboxPhoneNumber` / `VerifySMSSandboxPhoneNumber`** — in the SMS sandbox an
  account may only send to numbers it has verified. These calls are the boundary between
  "cannot send to strangers" and "can", one event per destination number, and the number
  itself is in the request.
- **`OptInPhoneNumber`**, **`ListPhoneNumbersOptedOut`**, **`ListOriginationNumbers`** —
  opting a previously opted-out recipient back in, and enumerating which numbers are
  available to send from.

## Where the sending is actually recorded

None of it is in CloudTrail. Three sources, and each is incomplete alone:

1. **CloudWatch `AWS/SNS` `SMSMonthToDateSpentUSD`** — valid dimensions: **none**. An
   account-wide figure, so it tells you *that* money is being spent and never on what. It is
   also the metric AWS itself uses to stop sending at the quota.
2. **CloudWatch `AWS/SNS` `NumberOfMessagesPublished`, `NumberOfNotificationsDelivered`,
   `NumberOfNotificationsFailed` and `SMSSuccessRate` on dimension `PhoneNumber`** — AWS
   defines that dimension as *"the phone number when you publish SMS directly to a phone
   number (without a topic)"*. This is the only per-destination telemetry AWS produces for
   the technique.
3. **SMS delivery-status logs in CloudWatch Logs**, in
   `sns/<region>/<account-id>/DirectPublishToPhoneNumber` and
   `sns/<region>/<account-id>/DirectPublishToPhoneNumber/Failure`. Each entry carries
   `delivery.destination` (the recipient number), `delivery.priceInUSD`, `delivery.smsType`,
   `delivery.providerResponse`, `delivery.phoneCarrier`, `mcc`/`mnc`,
   `numberOfMessageParts`, `dwellTimeMs`, `notification.messageId` and `status`. This is the
   closest thing to a recipient list that exists.

   **It is off until someone turns it on.** It requires a delivery-status IAM role,
   configured through `SetSMSAttributes` — the same call these rules alert on. With no
   success sample rate set, AWS writes logs for all successful deliveries; a rate of `0`
   logs failures only. Entries can take up to 72 hours to appear.

Be honest about the consequence: **in an account that has never configured delivery-status
logging, there is no per-recipient record of the campaign at all.** You will be able to prove
money was spent and roughly how much, and nothing else. Say so in the incident report rather
than implying a recipient list exists.

## Response levers

**Error strings:** SNS does not use `AccessDenied`; a denied call is **`AuthorizationError`** (403). The SMS
management calls throw `AuthorizationError`, `InternalError`, `InvalidParameter`,
`InvalidSecurity` and — for the sandbox and opt-in calls — `Throttled` on their very low
hard TPS limits (`SetSMSAttributes`, `CreateSMSSandboxPhoneNumber`,
`DeleteSMSSandboxPhoneNumber`, `VerifySMSSandboxPhoneNumber` and `ListOriginationNumbers` are
each capped at 1 transaction per second, which is itself a weak rate control on enumeration).
`Publish` to a phone number adds `ParameterValueInvalid` and `Validation` for a malformed
E.164 number, and the KMS family (`KMSAccessDenied`, `KMSDisabled`, `KMSInvalidState`,
`KMSNotFound`, `KMSOptInRequired`, `KMSThrottling`) when a topic is involved. Confirm against
a real denied event before building on any of these.

**No oversized-document companion rule ships.** Nothing on this path is a policy document;
the largest request parameter here is a phone number or a spend limit, nowhere near
CloudTrail's 100 KB `requestParameters` omission threshold.

**GuardDuty:** No GuardDuty finding type covers outbound SMS abuse. The nearest neighbours —
`Impact:EC2/AbusedDomainRequest`, `Impact:EC2/BitcoinDomainRequest` — are EC2 network
findings and do not apply to SNS. Do not list GuardDuty as a detection source for this use
case.

**MITRE:** The source rule maps **T1566 (Phishing)** under Initial Access, and that is retained as
primary because the directory and the trigger table are organised around it. But it is worth
stating what it actually describes: ATT&CK defines phishing from the perspective of the
*targeted* organisation, and here the targets are third parties. From the perspective of
events happening in *your* account, the precise mapping is **T1584.006 — Compromise
Infrastructure: Web Services**, under Resource Development: an adversary has taken over a
service you own and is using it as sending infrastructure against someone else. Both are
carried as tags. **T1526 — Cloud Service Discovery** covers the reconnaissance stage, which
the source rule maps correctly. All four IDs verified live 2026-08-29.

**Severity:** **High**, against the source rule's P2. P2 is defensible for an ambiguous single signal, but
this is the one use case in the set where the damage accrues to people who cannot detect it
themselves and cannot be notified, at a rate bounded only by the account's SMS spend quota,
and where every hour of delay is more messages delivered. The financial exposure is real and
immediate — the spend is incurred as the messages send, and AWS's own stop only engages at
the quota. It is not P0 only because no data leaves the account and no credential is exposed
by this technique itself; the compromise that produced the access is a separate and probably
higher-priority incident.

**Files here:**

- `sigma_t1566.yml` — five documents: `sns_sms_attributes_changed` (high, the spend-limit and
  sender-id lever), `sns_sms_reconnaissance` (low, base rule with its own success filter),
  `sns_sms_sandbox_change` (medium, the send-to-strangers boundary), a `temporal_ordered`
  correlation grouped **by principal** that replaces the original flow (high), and
  `sns_publish_unexpected_principal` (low) — shipped with an explicit warning that it is
  inert without a data-event trail and blind to the direct-to-phone form regardless.
- `kql_t1566.kql` — summarises the SMS management activity per principal, grades on the
  recon-then-setup transition, and lists in its trailing section every place the sending is
  actually recorded, none of which is CloudTrail.

Full response procedure is in `../PLAYBOOK.md`. A topic policy opened for public publish is a
second route to the same outbound abuse when the topic carries `sms` subscriptions — see
`../../sns.collection.sns-topic-was-created-with-public-publish-permissions/`.

Full response procedure is in `../PLAYBOOK.md`.
