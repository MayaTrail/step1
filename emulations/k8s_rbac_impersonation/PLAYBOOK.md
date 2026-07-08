# K8s RBAC Impersonation Privilege Escalation — IR & Detection Playbook

## Summary
Simulates a Kubernetes attacker exploiting service accounts with `impersonate`
access rights to gain admin privileges.
Techniques: T1069 (Permission Groups Discovery), T1548 (Abuse Elevation Control).

## Detection
See detection rules in `detections/`:
- `sigma_t1069.yml` — RBAC enumeration via auth can-i / SelfSubjectAccessReview
- `kql_t1069.kql` — KQL equivalent
- `sigma_t1548.yml` — API requests bearing Impersonate-User / Impersonate-Group headers
- `kql_t1548.kql` — KQL equivalent

## Response
1. Identify the service account or user that holds the `impersonate` ClusterRole binding.
2. Remove or scope down the `impersonate` RBAC verb — restrict to specific target users only.
3. Audit audit logs for requests containing `Impersonate-User` or `Impersonate-Group` headers.
4. Review all ClusterRoleBindings granting `impersonate` across the cluster.

## Revert
Handled by `pulumi destroy` (removes attacker service account and RBAC bindings).
