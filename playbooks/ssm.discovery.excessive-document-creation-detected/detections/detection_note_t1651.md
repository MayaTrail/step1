# Detection Note — T1651 (Cloud Administration Command)

**Signal:** an SSM document created by a principal that is not the deployment
pipeline — and above everything else, a write to the Session-type document named
`SSM-SessionManagerRunShell`.

**Volume is the wrong axis for this API.** An SSM document is a payload waiting
for a dispatcher. One `Command` document wrapping a shell script, sent to a
target set, runs that script as root or SYSTEM on every managed node in the set.
The account cap is 500 active documents, so ten in five minutes is 2% of the
ceiling and tells you nothing; meanwhile the single document that matters never
trips a volume rule, because one is not more than ten.

**What the original rule got wrong.** It matched `createdocument`, counted more
than ten in five minutes, and grouped by
`userIdentity.sessionContext.sessionIssuer.userName`. Three consequences. A
CloudFormation or Terraform apply that ships a runbook set fires it on every
release, and it gets muted. A single deliberate document never fires it at all.
And `sessionContext` is present only for **role sessions** — an IAM user's event
has no `sessionContext` at all, so the group-by key is null and every IAM user
either collapses into one bucket or is dropped by the aggregation. The corrected
rules group by `userIdentity.arn`, which every event carries.

## `SSM-SessionManagerRunShell` is the document to watch

Session Manager stores its preferences in an SSM document of type `Session` named
`SSM-SessionManagerRunShell`, created with `aws ssm create-document --name
SSM-SessionManagerRunShell --document-type Session`. That document controls, for
**every session on every managed node in the Region**:

- `shellProfile` — commands run at the start of each session, per platform
- `s3BucketName`, `cloudWatchLogGroupName`, `kmsKeyId` — where session output is
  recorded, and whether it is recorded at all
- `runAsEnabled` / `runAsDefaultUser` — which OS user sessions run as

A principal with `ssm:CreateDocument` or `ssm:UpdateDocument` therefore has, in
one call, both code execution on every host anyone opens a session to and control
of the audit trail for those sessions. It needs no volume, no target list and no
`SendCommand`. That is why the shipped ruleset puts it at `high` on a single
event while leaving the volume rule at `low`.

The reserved-prefix rule helps here. AWS refuses `CreateDocument` for names
beginning `aws`, `amazon`, `amzn`, `AWSEC2`, `AWSConfigRemediation` or
`AWSSupport`, so an attacker **cannot** create a document that impersonates an
AWS-owned one. Anything in the account whose name looks AWS-owned is. The
`SSM-` prefix is not reserved, which is exactly why `SSM-SessionManagerRunShell`
is reachable.

## Content is deliberately not in the Sigma rules

`CreateDocument`'s `Content` parameter is capped at **64 KB**, well below
CloudTrail's 100 KB `requestParameters` omission threshold, so there is no
size-based evasion path here. But AWS does not document whether
`requestParameters.content` is recorded for `CreateDocument`, and a
content-matching rule that silently never fires is worse than no rule at all.
Content inspection therefore happens through `GetDocument` in `../PLAYBOOK.md`
Query 2, not in the rule.

What to look for once you have the content:

| Document type | The dangerous construct |
|---------------|-------------------------|
| `Command` | `aws:runShellScript` / `aws:runPowerShellScript` and their `runCommand` arrays |
| `Automation` | `aws:executeScript`, and the `assumeRole` the automation runs under — that role's permissions, not the author's, bound the blast radius |
| `Session` | `shellProfile` (runs at session start), and the logging fields above |

**Field shape:** `CreateDocument`'s `responseElements` **nests** under
`documentDescription`. The Sha256 of the content at creation is
`responseElements.documentDescription.hash`, with `hashType` alongside it; a flat
`responseElements.hash` yields null and every hash-based IOC disappears silently.
Store the hash — if the live content stops matching it, the document was updated
after creation and `UpdateDocument` is the event to hunt.

## Creation is staging; dispatch is the compromise

`CreateDocument` alone puts a payload in the account. The events that run it are
`SendCommand` (`requestParameters.documentName`), `StartAutomationExecution`
(`documentName`), `StartSession` (`documentName`) and `CreateAssociation` /
`UpdateAssociation` (`name`), the last of which is the persistent form — an
association re-runs the document on a schedule against a target set and survives
the deletion of nothing but itself.

All of these are **management events, recorded by default**: AWS states "Systems
Manager logs all control plane operations to CloudTrail as management events",
and the only SSM data events are `CreateControlChannel` / `OpenControlChannel`
and `RequestManagedInstanceRoleToken`. So the "was it used" question is directly
answerable, which is what the `temporal_ordered` correlation in
`sigma_t1651.yml` encodes.

## Response levers

**Deleting the document does not undo what it ran.** `DeleteDocument` removes the
payload; anything a `SendCommand` already executed on a node is a host-level
compromise handled outside AWS. Enumerate the command invocations before deleting
the document, because `ListCommandInvocations` is keyed on the command ID and the
document name, and the association between them is easier to walk while the
document still exists.

**Associations outlive the document's author.** Check
`ListAssociations` for anything referencing the document name before you close;
an association is the persistence, not the document.

**`ssm:SessionDocumentAccessCheck`** forces `StartSession` to verify the caller
has explicit permission on the session document it names — the control that stops
an attacker-authored `Session` document being usable by anyone else.

**Error strings:** `DocumentAlreadyExists`, `DocumentLimitExceeded` (the 500
active-document cap), `MaxDocumentSizeExceeded` (64 KB), `InvalidDocumentContent`,
`InvalidDocumentSchemaVersion`, `NoLongerSupportedException`, `TooManyUpdates`,
`InternalServerError`. Denials are `AccessDenied` (IAM) and
`AccessDeniedException` (service-evaluated) — match both, and confirm against a
real denied event. A run of `DocumentAlreadyExists` against names the principal
never created is name enumeration, not a retry loop.

**GuardDuty:** no finding type specific to SSM document creation.

**MITRE:** the source rule labels this T1082 (*System Information Discovery*) under
TA0007. Creating a document discovers nothing — it stages a payload. T1651
(*Cloud Administration Command*) is the technique the document exists to perform:
executing commands inside virtual machines through a cloud management service,
which is precisely Run Command and Session Manager. The tactic is Execution
(TA0002), not Discovery. The directory slug keeps the source's tactic label so the
register stays navigable; §6 of `../PLAYBOOK.md` carries the correction.

**Severity:** the source rule rates the volume condition P4. The IR assessment is
**High for a write to `SSM-SessionManagerRunShell` or a dispatched executable
document, Medium for an executable document created and not yet run, Low for bulk
creation on its own** — which is close to an inversion of the source rule's single
priority.

## Cross-references

- `../../ssm.credential-access.high-number-of-ssm-parameters-retrieval/` — SSM
  documents resolve `{{ssm:<name>}}` references, so a document plus a parameter
  the attacker controls is a two-part payload; that note also carries the shared
  management-event verification.
- `../../ssm.initial-access.excessive-failed-document-retrieval-attempts/` — the read
  side of the same object, and the `InvalidDocument` error-string trap.
- `../../ec2.credential-access.imds-credential-theft/` — the instance-profile
  session-name fact (`assumed-role/<Role>/<instance-id>`) applies to every query
  here that keys on `AttributeKey=Username`.

**Files here:**

- `sigma_t1651.yml` — six documents: the Session Manager preferences write
  (`high`), an executable document created outside the pipeline (`medium`), a
  `temporal_ordered` create-then-dispatch correlation (`high`) with its dispatch
  base rule (`low`), and the corrected volume correlation (`low`) with its
  creation base rule (`low`).
- `kql_t1651.kql` — all three signals in one summary with a verdict, plus the
  `get-document` content-inspection path, the error-code set and the
  `SessionDocumentAccessCheck` prevention note inline.

Full response procedure is in `../PLAYBOOK.md`.
