# AWS incident-response playbooks

115 playbooks covering 25 AWS services. Each one is a complete, self-contained
response procedure for a single detection use case, with the detection rules that fire it.

**Start with [INDEX.md](INDEX.md)** — every playbook, grouped by service, with what it covers.

## What is in a playbook folder

```
<service>.<tactic>.<what-happened>/
├── PLAYBOOK.md                    the six-phase response procedure
├── detections/
│   ├── sigma_<technique>.yml      the detection rules, ready to deploy
│   ├── kql_<technique>.kql        the same logic as a hunting query
│   └── detection_note_*.md        why the rules are shaped that way
└── _source/
    ├── original_rules.yml         the rule this was built from
    └── PROVENANCE.md              where it came from, and why it is one playbook
```

The six phases in every `PLAYBOOK.md`: Preparation, Identification, Containment,
Eradication, Recovery, Lessons Learned. Every shell command is runnable as written.

## Two shared folders

- **`_ground-truth/`** — verified AWS behaviour per service, written once and
  referenced by every playbook for that service rather than repeated.
- **`_superseded/`** — earlier combined playbooks, kept with a mapping table so
  nothing is orphaned.

## Status in MayaTrail

These playbooks ship as **documentation** for SOC analysts and SOC engineers. A playbook is useful
on its own: it describes how to investigate and respond to a detection, whether or not MayaTrail can
currently simulate the attack behind it.

The Sigma rules under each `detections/` folder are a different matter. A rule is only shipped as a
platform detection once an emulation exists that fires it and a run has proven it fires. Rules living
here have not met that bar yet, so treat them as reference material, not as validated MayaTrail
detections.

As of 3rd September 2026, of the 115 playbooks here:

- 30 have at least one rule an emulation in `emulations/` can fire
- 70 read CloudTrail but have no emulation yet, so an emulation could be written for them
- 15 read a log source the detection archive does not ingest (VPC flow logs, WAF, GuardDuty,
  Network Firewall, Route 53 Resolver, Kubernetes audit, ELB, Bedrock), so no emulation can prove
  them until the log pipeline carries a second source

## Provenance

Imported 3rd September 2026 from the AWS-IR-PLAYBOOKS drop. Content is byte-identical to the source;
only the directory nesting was flattened (`AWS-IR-PLAYBOOKS/playbooks/<name>` became `playbooks/<name>`)
and this section was added.
