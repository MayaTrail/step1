# K8s PSA Bypass via PV Abuse — IR & Detection Playbook

## Summary
Demonstrates bypassing baseline Pod Security Admission (PSA) by mounting
host-paths using raw PersistentVolume and PersistentVolumeClaims, then reading
sensitive host files from inside an otherwise unprivileged pod.
Techniques: T1211 (Exploitation for Defense Evasion), T1611 (Escape to Host).

## Detection
See detection rules in `detections/`:
- `sigma_t1211.yml` — HostPath PV creation in baseline-restricted namespace
- `kql_t1211.kql` — KQL equivalent
- `sigma_t1611.yml` — Pod reading host filesystem paths
- `kql_t1611.kql` — KQL equivalent

## Response
1. Identify PersistentVolumes with `hostPath` type bound to pods in restricted namespaces.
2. Delete the malicious PV/PVC pair and evict the pod.
3. Add a validating admission webhook that blocks `hostPath` PV creation for non-admin principals.
4. Upgrade PSA from `baseline` to `restricted` where workloads allow it.
5. Audit all existing PVs of type hostPath for unexpected bindings.

## Revert
Handled by `pulumi destroy` (removes PV, PVC, pod, and namespace).
