# K8s MITM via Pod status.podIP Mutation — IR & Detection Playbook

## Classification

| Field | Value |
|-------|-------|
| Incident Type | K8s MITM via Pod status.podIP Mutation |
| Threat Actor | N/A — single technique, not actor-attributed |
| Platform | k8s |
| Severity | High |
| MITRE Tactics | Credential Access |
| MITRE Techniques | T1557 (Adversary-in-the-Middle) |

## Summary
Emulates a traffic interception attack where an attacker patches the
`status.podIP` of a target pod to redirect service traffic to an
attacker-controlled endpoint. Technique: T1557 (Adversary-in-the-Middle).

## Detection
See detection rules in `detections/`:
- `sigma_t1557.yml` — Unexpected PATCH on pods/status subresource
- `kql_t1557.kql` — KQL equivalent

## Response
1. Identify the pod whose `status.podIP` was modified.
2. Restart the affected pod to restore the original IP assignment.
3. Review RBAC — remove `patch` on `pods/status` from non-system principals.
4. Audit audit logs for other `pods/status` PATCH events by the same identity.

## Revert
Handled by `pulumi destroy` (removes attacker pod and RBAC bindings).
