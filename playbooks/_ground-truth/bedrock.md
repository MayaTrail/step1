# Ground truth — Amazon Bedrock model invocation logging

Audited 2026-08-30 against the AWS Bedrock User Guide (*Monitor model invocation using CloudWatch
Logs and Amazon S3*). Every playbook under `techniques/bedrock.*` is written from this file.

---

## 1. Logging is off by default, and it is the only source of prompt and response content

> **Model invocation logging is disabled by default.** After model invocation logging is enabled,
> logs are stored until the logging configuration is deleted.

Destinations are CloudWatch Logs and Amazon S3, *"Only destinations from the same account and
Region are supported."* Configured through `PutModelInvocationLoggingConfiguration`,
`GetModelInvocationLoggingConfiguration` and `DeleteModelInvocationLoggingConfiguration`.

**CloudTrail records that a model was invoked; only invocation logging records what was said.**
That distinction runs through every playbook in this service: the control-plane trail gives you
principal, time and model, and nothing about the content.

## 2. Which operations are logged, and the endpoint that is not

Logged: `Converse`, `ConverseStream`, `InvokeModel`, `InvokeModelWithResponseStream`.

> Model invocation logging is only supported for calls made through the `bedrock-runtime` endpoint.
> This includes the OpenAI-compatible Responses and Chat Completions APIs on that endpoint. **Calls
> made through other endpoints, such as the same APIs on `bedrock-mantle`, are not currently
> captured by invocation logging.**

That is a documented coverage gap in the log source itself, and it is not configurable — a caller
reaching the same models through a different endpoint produces no invocation log at all.

## 3. Record shape

```
{
  "schemaType": "ModelInvocationLog", "schemaVersion": "1.0",
  "timestamp": "...", "accountId": "...", "region": "...", "requestId": "...",
  "operation": "Converse" | "InvokeModel" | ...,
  "modelId": "...",
  "identity": { "arn": "arn:aws:sts::...:assumed-role/MyRole/session-name" },
  "requestMetadata": { ... },
  "input":  { "inputContentType": "...", "inputBodyJson": { }, "inputTokenCount": 25 },
  "output": { "outputContentType": "...", "outputBodyJson": { }, "outputTokenCount": 150 }
}
```

- **`identity.arn`** — *"The AWS STS or IAM ARN of the principal that made the request, including
  the role name and the session or user name. Captured automatically."* This is the only reliable
  actor field, and AWS's own guidance for attribution is to group on it.
- **`requestMetadata`** — *"the only field supplied by the caller"*. Everything else is populated by
  Bedrock. **Caller-supplied means attacker-supplied when the caller is the attacker**, so it must
  never be used as a trust signal or as a grouping key for a security rule.
- **`inputTokenCount` / `outputTokenCount`** — the volume measures, and the ones that map to cost.
- **`operation`** and **`modelId`** — what was called and which model.

## 4. The 100 KB rule — the content may not be in the log entry

> Each record will contain the invocation metadata, and input and output JSON bodies of **up to
> 100 KB in size. Binary data or JSON bodies larger than 100 KB will be uploaded as individual
> objects** in the specified Amazon S3 bucket under the data prefix.

> **Binary data (such as images) and JSON bodies larger than 100 KB are not included inline in the
> log entry.** Instead, they are stored as separate objects in the Amazon S3 bucket under the data
> prefix, and the log entry contains a reference to the Amazon S3 location.

So a search for text inside `inputBodyJson` misses every prompt over 100 KB — and a large prompt is
exactly what a data-exfiltration-through-a-model attempt looks like. **For large-data delivery to
work at all, an S3 location must be configured**; with a CloudWatch-only destination and no S3
location, oversized bodies have nowhere to go.

Modality selection matters too: logging is enabled per modality (Text, Image, Embedding, Video),
and *"Data will be logged for all models that support the modalities... that you choose"* — so a
modality left unselected is a class of invocation with no body recorded.

## 5. Where the control plane lives

`bedrock.amazonaws.com` in CloudTrail for configuration:
`PutModelInvocationLoggingConfiguration`, `DeleteModelInvocationLoggingConfiguration`,
`PutFoundationModelEntitlement` / model access changes, `CreateGuardrail`, `UpdateGuardrail`,
`DeleteGuardrail`.

`bedrock-runtime.amazonaws.com` for the invocations themselves — `InvokeModel`, `Converse` and
their streaming forms appear in CloudTrail as **data events** where enabled, carrying the principal
and the model and **not** the content.

**UNVERIFIED:** whether Bedrock runtime data events are on by default in a given trail
configuration was not confirmed on the pages audited. The playbooks state the requirement rather
than assuming the default.

## 6. What the source pack contains, and what it is for

The four Bedrock rules in the pack are observability rules — high invocation count, low invocation
count, high latency, high error count — carrying no MITRE mapping. They are written for cost and
availability. Read as security signals they cover real techniques, and the playbooks say so
explicitly rather than pretending the source intent was security:

- **High invocation count** → a stolen credential used for model compute, at the account owner's
  expense. Resource hijacking.
- **High error count** → enumeration of which models a credential can reach, or repeated guardrail
  refusals. Discovery.
- **Low invocation count** → for a production workload, availability; and the same signal a
  logging-configuration deletion produces.

## 7. MITRE ATT&CK — checked live 2026-08-30

| ID | Status | Name | Tactic |
|---|---|---|---|
| `T1496` | live | Resource Hijacking | Impact |
| `T1526` | live | Cloud Service Discovery | Discovery |
| `T1078.004` | live | Valid Accounts: Cloud Accounts | Multiple |
| `T1685.002` | live | Disable or Modify Tools: Disable or Modify Cloud Log | Defense Impairment |
| `T1530` | live | Data from Cloud Storage | Collection |

The source pack maps all four rules to nothing.

## 8. What could NOT be verified

1. **Whether Bedrock runtime data events are enabled by default** in a standard trail.
2. **The exact quota or throttling behaviour** that would distinguish a legitimate burst from
   abuse. Rules here use relative comparison against a baseline rather than absolute thresholds.
3. **Whether `requestMetadata` is recorded when the caller supplies malformed values.** It is
   caller-supplied, and the playbooks treat it as untrusted regardless.
