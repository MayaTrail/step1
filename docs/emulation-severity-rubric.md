# Emulation severity rubric

Every emulation carries one baseline severity, and it must read the same in the
MANIFEST (`severity`) and in the PLAYBOOK.md Classification table (`Severity`).
`backend/apps/emulations/tests/test_severity_alignment.py` fails the build when
they differ.

The level answers one question: **if the emulated technique were real and
succeeded under default conditions, how bad is the incident?**

| Level | Meaning | Typical techniques |
|-------|---------|--------------------|
| CRITICAL | Irreversible destruction or withholding of production data or infrastructure at scale, or unrestricted control of the account. | Ransomware, deleting data together with its backups, mass termination, locking users out of the account, a full multi-stage campaign that begins with an admin key. |
| HIGH | A confirmed compromise with real impact that is bounded or recoverable. | Data exfiltration or exposure, persistence and backdoors, privilege escalation, credential theft that yields reusable access, code execution on workloads, impairing logging or detection. |
| MEDIUM | Establishes access or posture, or reconnaissance aimed at secrets or at a follow-on action; needs another step to cause harm. | Targeted discovery (user-data, sending capability, instance-role enumeration), console sign-in posture, resource abuse that is cheap to reverse. |
| LOW | Plain inventory with no secret material and no follow-on action. | Unused today; reserve it for pure enumeration. |

## Rules

1. **The baseline is the headline.** A playbook may add conditions that raise
   it ("High. Raise to Critical when the stopped trail was the only multi-Region
   trail"), but it must open with the same level as the manifest.
2. **One reading per emulation.** Do not restate the level in other prose with a
   different value. Detection notes may describe the IR view but must agree with
   the manifest.
3. **Sigma rule `level` is a separate concept.** It rates a single detection
   rule's confidence and urgency, not the emulated technique, so it is not
   compared to the emulation severity.
4. **Changing a level changes both files in the same commit.**
