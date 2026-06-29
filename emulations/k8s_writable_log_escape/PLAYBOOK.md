# K8s Writable /var/log Host Escape — IR & Detection Playbook

## Summary
Simulates host escape by utilizing a writable host log directory mount combined
with Kubelet log-retrieval permissions to read arbitrary host files via symlink.
Techniques: T1609 (Container Administration Command), T1611 (Escape to Host).

## Detection
See detection rules in `detections/`:
- `sigma_t1609.yml` — Symlink creation inside a container targeting /var/log paths
- `kql_t1609.kql` — KQL equivalent
- `sigma_t1611.yml` — Kubelet log API access returning unexpected host file content
- `kql_t1611.kql` — KQL equivalent

## Response
1. Identify the pod with a writable `/var/log` hostPath mount.
2. Immediately delete the pod and the associated DaemonSet or workload.
3. Remove the hostPath volume mount and redeploy with a non-host log path.
4. Restrict kubelet log API access — require cluster-admin or audit-only roles.
5. Audit other pods in the cluster for writable hostPath mounts to `/var/log`.

## Revert
Handled by `pulumi destroy` (removes the pod, hostPath DaemonSet, and RBAC).
