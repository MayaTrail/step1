# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | **Building block with no shipped logic** — no query, no threshold, no group-by |
| Scope captured | One entry: Low Invocation Count |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

## A new use case, not a corrected rule

The source entry is a **building block** with no query, no threshold and no grouping — a CloudWatch
metric alarm for availability. There is nothing to audit a correction against, and the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 records what the source provides against
what a security detection needs rather than inventing defects in an empty rule.

**The security reading of "invocation volume dropped" is that the log stopped, not the traffic — and
this service can tell the difference.** Bedrock invocations are recorded in two independent places:
the model invocation log, which carries the prompt, the response and the token counts; and
CloudTrail's `bedrock-runtime` data events, which carry the principal and the model and never the
content. `DeleteModelInvocationLoggingConfiguration` stops the first and leaves the second untouched.

So the divergence between them is unambiguous:

| Invocation log | CloudTrail | Meaning |
|---|---|---|
| quiet | quiet | The workload stopped. Availability |
| quiet | **busy** | **Logging was removed while invocations continue** |

Every other `*.stealth.no-logs-*` playbook in this corpus has to argue about what silence means,
because it has one source. This one has a second witness, which is why it is the only such playbook
here that ships a genuine absence-based detection rather than demoting absence to a corroborator.

**Three paths are covered.** Deleting the configuration is the loud one and produces the divergence.
Reconfiguring with a **modality disabled** — text, image, embedding or video — is the quiet one: the
configuration is present, the console shows logging enabled, both sources keep producing records,
and only the *content* for that modality stops. It produces no divergence at all and only the
control-plane event reveals it. And removing the destination leaves the configuration reporting
healthy with nothing landing, with no Bedrock-side error event at the moment delivery fails.

**One complication worth stating:** logging is **off by default**, so an account that never enabled
it is indistinguishable from one where it was removed, by the log streams alone. The control-plane
events and the state read in Query 2 separate them.

**MITRE:** the source maps this to nothing. `T1685.002 — Disable or Modify Tools: Disable or Modify
Cloud Log`, verified live 2026-08-30. Note this is `.002` and not `.001`: the model invocation log
is a log, not a security tool — the distinction the GuardDuty playbook at
`../../guardduty.stealth.no-logs-from-amazon-guardduty/` turns the other way.

**Merge test:** the three documents are one act — removing the record of what was said to the
models — by three routes. None has a source rule of its own.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `bedrock.*` playbook is in `../../_ground-truth/bedrock.md`, audited on
2026-08-30. Logging being off by default is §1; the record shape is §3; the 100 KB rule is §4; the
control plane is §5.
