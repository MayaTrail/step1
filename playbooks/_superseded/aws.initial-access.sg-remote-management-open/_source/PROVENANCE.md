# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window and group-by keys |
| Scope captured | The six security-group ingress/egress alerts |
| Retrieved | 2026-08-27 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Fires on |
|-------|----------|----------|
| Security Group Opened to the Internet for Remote Management | P1 | `AuthorizeSecurityGroupIngress` with a literal `fromPort` of 22/3389/5985/5986 and a literal `0.0.0.0/0` |
| Ingress Rule Open to 0.0.0.0/0 | P2 | `AuthorizeSecurityGroupIngress` with `requestParameters.cidrIp` equal to `0.0.0.0/0` |
| Ingress Rule Was Added | P3 | Every successful `AuthorizeSecurityGroupIngress` |
| Ingress Rule Was Revoked | P4 | Every successful `RevokeSecurityGroupIngress` |
| Egress Rule Was Added | building-block | Every successful `AuthorizeSecurityGroupEgress` |
| Egress Rule Was Revoked | building-block | Every successful `RevokeSecurityGroupEgress` |

The two P1/P2 alerts are the exposure signal this technique corrects. The four remaining
alerts are captured because they are the same rule family and because two of them —
`RevokeSecurityGroupIngress` and `RevokeSecurityGroupEgress` — are **remediation events
carried as alerting signal**, which is a defect in its own right and is analysed in
`../PLAYBOOK.md` §2.

The egress pair is out of scope for this technique: an egress rule permits outbound
traffic and does not expose a listening port to the internet. It is retained in the
extract only so the ingress/egress asymmetry in the source set is visible to a reviewer.

## Extraction

`original_rules.yml` is produced by the kit's shared extractor, not by hand:

```bash
python3 tools/deid_extract.py <PackDir> "Ingress" "Egress" "Remote Management" \
  > techniques/aws.initial-access.sg-remote-management-open/_source/original_rules.yml
```

Three of the six alerts are of the platform's *immediate* type — a query with no
threshold and no window, firing on every match. The extractor read only the
threshold-bearing shapes and dropped those queries silently, which left the extract
unauditable for exactly the rules that have no volume condition to inspect — including
the P2 CIDR rule, whose entire defect is in its field path. The extractor was corrected
to read the immediate shape as well; the change is additive and the previously shipped
extracts are byte-identical under it.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project
— including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately. The originals are packaged in a proprietary format whose
scaffolding — payload field lists, entity labels, product-specific field prefixes,
internal enums and packaging metadata — identifies the source on sight while bearing on
nothing about whether the rules are correct. What is retained is the complete detection
logic: name, priority, type, the Lucene query verbatim, threshold, window and group-by.
Every claim in the "Detection Rule Quality Notes" table in `../PLAYBOOK.md` §2 is
checkable against it.

The shipped `references:` blocks in `detections/` cite public MITRE and AWS documentation
only — a deployed rule travels outside the organisation that wrote it, and an internal
path is not resolvable to whoever receives it.
