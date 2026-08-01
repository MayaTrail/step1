# Detection Note — T1098 (Backdoor Lambda Function via Resource Policy)

**Signal:** `lambda:AddPermission` granting `Invoke` to an external account or
a wildcard principal.

**Why it is persistence:** the grant lives in the **function's resource
policy**, not in IAM. Rotating every credential in the account does not touch
it. The blast radius is the function's **execution role** — whatever that role
can do, the external caller can now cause to happen.

**Parsing is easy here, unusually.** `principal` is **cleartext** in the event —
a request parameter, not a URL-encoded policy document. Account digits match
directly and no decode step is required, unlike the IAM trust-policy
techniques.

**Drop `RemovePermission`.** The original rule bundled it, which inverted the
signal: a permission *removal* is not persistence, and it is the emulation's own
cleanup.

## The parameter-name trap

`AddPermission` uses **`functionUrlAuthType`**.
`CreateFunctionUrlConfig` uses **`authType`**.

Different keys on different events. A rule matching only one silently misses
the other, and they must be OR'd as sibling blocks — ANDing them means no
single event satisfies both and the rule never fires at all.

## "Was it invoked?" — the trap that matters most

`lambda:Invoke` is a **data-plane** event. It does not appear in management
events at all, so none of the detection rules here show use. Lambda **data
events** must be enabled.

And when you query those data events, there is a second, sharper trap:

> A **synchronous** (`RequestResponse`) invoke — which is what the default
> `aws lambda invoke` produces — records `requestParameters` as **null** and
> carries the function identity **only** in `resources[].ARN`.

So a data-event filter written against `requestParameters.functionName`
**silently drops synchronous invokes** and returns zero results even when the
attacker did invoke the function. Match on the resource ARN and treat
`requestParameters` as optional.

A cross-account invoke lands in the **function owner's** trail, carrying the
external caller's account id.

**Coarse fallback** when data events are not enabled: the CloudWatch
`AWS/Lambda` `Invocations` metric shows that invocations happened, though not
by whom.

## Other coverage

**IAM Access Analyzer does analyse Lambda resource policies** — use it to sweep
for backdoors planted before logging was in place.

**`lambda:Principal` is a real IAM condition key**, so a guardrail SCP can
constrain who may be granted invoke permission. Verify its exact semantics for
account vs service principals in your environment, and combine with
`aws:PrincipalOrgID`.

**`get-policy` returns stringified JSON** — parse it before inspecting, and
guard for `Statement` being an object or an array and `Principal` being a
string, an object, or an object containing an array. A bare-account
`AddPermission` stores the principal as `arn:aws:iam::ACCOUNT:root`.

**Error strings:** denials surface as `AccessDenied` / `AccessDeniedException`.
Not `Client.`-prefixed like EC2.

**MITRE:** T1098 (*Account Manipulation*) is defensible.

**Severity:** manifest MEDIUM; IR view **High** — blast radius is the function
execution role. (As emulated the role is basic-execution and near-powerless,
which softens the specific test case but not the technique.)

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1098.yml` — two documents: external/public invoke grant (`high`) and
  the unauthenticated function-URL rule (`high`).
- `kql_t1098.kql` — org-list comparison with public/external/URL verdicts, plus
  the correct data-event query for establishing whether the backdoor was used.

Full response procedure is in `../PLAYBOOK.md`.
