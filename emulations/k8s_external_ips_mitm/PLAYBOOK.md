# K8s External IPs Hijacking (CVE-2020-8554) — IR & Detection Playbook

## Summary
Emulates CVE-2020-8554 where an attacker creates a Kubernetes Service with
arbitrary `externalIPs`, forcing cluster traffic to route to an attacker-controlled
container. Technique: T1557 (Adversary-in-the-Middle).

## Detection
See detection rules in `detections/`:
- `sigma_t1557.yml` — Service creation with unexpected externalIPs
- `kql_t1557.kql` — KQL equivalent

## Response
1. Identify the Service resource with suspicious `externalIPs` set.
2. Delete or patch the Service to remove the externalIPs field.
3. Review RBAC policies — restrict `create`/`patch` on Services to trusted principals.
4. Enable the `DenyServiceExternalIPs` admission controller to prevent recurrence.
5. Audit other Services in the cluster for unexpected externalIPs entries.

## Revert
Handled by `pulumi destroy` (removes the attacker Service and supporting infra).
