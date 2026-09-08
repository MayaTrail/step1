# Detection Note — T1526 (Cloud Service Discovery)

**Signal:** one principal failing to retrieve **ten or more distinct** SSM document
names inside five minutes — and, separately, one principal successfully reading
twenty-five or more distinct document names, which produces no errors at all.

**The original rule watches the wrong error, and that is the whole finding.** It
filters `getdocument` failures to `errorCode:"AccessDenied"`. AWS documents
`GetDocument`'s `InvalidDocument` error as *"The SSM document doesn't exist or the
document isn't available to the user"* — that single error covers both a name that
does not exist and a document that exists but is not shared with the caller, which
is exactly what a principal guessing document names receives. The rule filters that
path out entirely and keeps `AccessDenied`, the case where the principal lacks
`ssm:GetDocument` outright — which in practice is a misconfigured client far more
often than an actor, because an actor who cannot call the API at all does not sit
there calling it ten times.

Both codes belong in the rule, and they should be matched with `contains` rather
than equality, so that `AccessDeniedException` (the service-evaluated form) and
`InvalidDocumentVersion` are caught alongside their siblings. That is what
`sigma_t1526.yml`'s base rule does.

## Count distinct names, not attempts

Ten failed calls against one document name is a retry loop in a broken deployment
script. Ten failed calls against ten different names is a principal mapping what
exists. The source rule cannot tell those apart, because it counts events; the
shipped rule uses a `value_count` correlation on `requestParameters.name`, which
makes the count a count of *namespace probed*.

The same distinction gives you a triage signal with no extra telemetry: the ratio
of successes to distinct names attempted. A deployment tool reading documents it
owns sits near 1.0. A principal guessing sits near 0.0, and the names it tried read
like a wordlist rather than an internal naming scheme. Read the probed-name list
before deciding — the shape of the names is usually more conclusive than the count.

## The group-by is empty for IAM users

`userIdentity.sessionContext.sessionIssuer.userName` exists only for **role
sessions**. An IAM user's CloudTrail event has no `sessionContext` at all, so the
key is null and every IAM user in the account either collapses into a single bucket
or is dropped by the aggregation, depending on the platform. An IAM user can
therefore probe indefinitely without the count ever accumulating against them. The
corrected rules group by `userIdentity.arn`, which every event carries.

This defect is shared with the two "Excessive ..." creation alerts in the same
family — see
`../../ssm.discovery.excessive-document-creation-detected/detections/detection_note_t1651.md`
and
`../../ssm.discovery.excessive-parameter-creation-detected/detections/detection_note_t1565_001.md`.
It is a property of the group-by key, not of any one rule.

## The enumerator with permission is invisible to every error rule

A principal holding `ssm:GetDocument` on `*` enumerates by reading, not by failing.
No error is produced, so neither the original rule nor the corrected failure rule
sees anything. `ListDocuments` makes it cheaper still — one call returns the
inventory — and produces no per-document event to count.

`sigma_t1526.yml` covers this with a second `value_count` correlation on distinct
names read **successfully**. It is `medium` rather than `high` because the console
and inventory tooling do the same thing; both are allowlistable by principal and by
user agent, and that tuning is the price of seeing the case at all. Removing
`ssm:ListDocuments` from a principal does not stop enumeration — it forces the
enumeration through `GetDocument`, where it becomes noisy and visible, which is the
trade this rule set is built around.

## Why the enumeration matters — what is in a document

SSM documents are not treated as secrets, and people put things in them that are:
bootstrap scripts with embedded tokens, hard-coded internal endpoints and hostnames,
the parameter names an application reads through `{{ssm:/app/prod/db/password}}`,
and the `assumeRole` ARNs an Automation document runs under. A document read
successfully has disclosed all of it. That is why the `temporal_ordered`
correlation — a burst of failures followed by a success — is the `high` rule in the
file: the enumeration found something, and the something is now known.

The next step after enumeration is execution. Pivot the same principal onto
`SendCommand`, `StartAutomationExecution`, `StartSession` and `CreateAssociation`,
all of which are management events naming the document, and onto `CreateDocument`,
which is the same actor authoring their own rather than borrowing yours.

## Response levers

**There is nothing to contain in the document itself.** Reading a document changes
nothing; the response is to establish what was disclosed, remove any secret found
in a document that was read, and scope the principal's `ssm:GetDocument` down.
`ssm:GetDocument` and `ssm:DescribeDocument` both support resource-level
permissions on `arn:aws:ssm:<region>:<account>:document/<name>`.

**A secret found in a document is disclosed, not merely misplaced.** Rotate it at
its system of record; removing it from the document afterwards does not un-read it.

**Error strings:** `GetDocument` — `InvalidDocument`, `InvalidDocumentVersion`,
`InternalServerError`. IAM denials surface as `AccessDenied`, service-evaluated
denials as `AccessDeniedException`. Match both pairs with `contains`, and confirm
the exact strings against a real denied event in your own trail before narrowing.

**GuardDuty:** no finding type specific to SSM document enumeration.

**MITRE:** the source rule labels this T1110 (*Brute Force*) under TA0001
(*Initial Access*). Neither fits. Nothing is being guessed that authenticates —
`GetDocument` takes a document name, not a credential, and a correct name grants no
access the principal did not already hold. What is happening is enumeration of a
cloud service's contents, which is T1526 (*Cloud Service Discovery*) under
Discovery (TA0007). The mislabel matters operationally: a P2 "brute force" alert
routes to a credential-stuffing runbook, and the responder looks for a compromised
password that does not exist. The directory slug keeps the source's
`initial-access` label so the register stays navigable against the alert set; §6 of
`../PLAYBOOK.md` carries the correction.

**Severity:** the source rule rates this P2. The IR assessment is **Medium for the
enumeration on its own — reconnaissance, not access — and High once a successful
retrieval follows it**, which is the split the shipped rules encode.

## Cross-references

- `../../ssm.discovery.excessive-document-creation-detected/` — the write side of the
  same object, and where this principal goes next if enumeration succeeds.
- `../../ssm.credential-access.high-number-of-ssm-parameters-retrieval/` — a document
  read here often names the parameters worth reading there; it also carries the
  shared management-event verification.
- `../../ec2.credential-access.imds-credential-theft/` — the instance-profile
  session-name fact (`assumed-role/<Role>/<instance-id>`) applies to every query
  here that keys on `AttributeKey=Username`.

**Files here:**

- `sigma_t1526.yml` — five documents: a `value_count` correlation on distinct
  failed names (`medium`) with its failure base rule (`low`), a
  `temporal_ordered` correlation from that burst to a successful read (`high`), the
  success base rule (`low`), and a second `value_count` correlation covering the
  permitted enumerator who produces no errors (`medium`).
- `kql_t1526.kql` — one summary splitting the outcome into not-found, IAM-denied
  and success, with the hit-rate shape signal, the probed- and found-name sets, and
  the content-inspection, pivot and prevention notes inline.

Full response procedure is in `../PLAYBOOK.md`.
