# Kubernetes Adversary Emulation Catalogue

This document details the five Kubernetes adversary emulation modules implemented under the `step1/emulations/` directory. These modules are integrated into the MayaTrail platform to allow security teams to safely simulate, monitor, and build detections for Kubernetes-specific attack techniques.

---

## 1. K8s RBAC Impersonation Privilege Escalation (`k8s_rbac_impersonation`)

### How It Works
1. **Enumeration Phase**: The attack script uses a compromised service account token (`stolen-dev-token`) to query the `SelfSubjectRulesReview` API. This allows the attacker to inspect their own RBAC permissions without triggering wildcard discovery alarms.
2. **Escalation Phase**: Upon discovering that the service account has the `impersonate` verb on `serviceaccounts` or specific groups, the attacker crafts API requests to the Kubernetes API server containing the HTTP headers:
   - `Impersonate-User: admin-sa`
   - `Impersonate-Group: system:masters`
3. **Action Execution**: The API server evaluates request-time impersonation, executing the query with the rights of the impersonated user/group. The attacker successfully reads protected Secrets.

### Attack Type & MITRE Mapping
* **Tactic**: Privilege Escalation
* **Technique**: [T1548: Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
* **Discovery Hook**: [T1069: Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/)

### Security Impact
* **Access Level**: Attacker gains cluster-admin level privileges (`system:masters`).
* **Stealth**: Impersonation does not modify RoleBindings, making it difficult to detect via static RBAC analysis. (Audit logs will show the impersonated identity performing actions, although the original caller is still recorded in the headers field).

---

## 2. K8s Writable `/var/log` Host Escape (`k8s_writable_log_escape`)

### How It Works
1. **Setup**: This emulation replicates a container running with host-path mount access to `/var/log` (e.g., standard for logging agents or metrics collectors).
2. **Symlink Insertion**: The attacker utilizes container command execution (simulated RCE) to create a symbolic link inside the mounted log path linking to a critical host file:
   - `ln -s /etc/shadow /var/log/pods/webapp.log`
3. **Exfiltration**: Using Kubernetes credentials with rights to read pod logs (via the Kubelet proxy endpoint `/api/v1/nodes/<node>/proxy/logs`), the attacker requests the logs for the target path. The host logging process traverses the symlink and returns the raw contents of `/etc/shadow` through the authenticated API channel.

### Attack Type & MITRE Mapping
* **Tactic**: Privilege Escalation / Host Escape
* **Technique**: [T1611: Escape to Host](https://attack.mitre.org/techniques/T1611/)
* **Execution Vector**: [T1609: Container Administration Command](https://attack.mitre.org/techniques/T1609/)

### Security Impact
* **Access Level**: Direct read access to the underlying worker node filesystem as root.
* **Impact**: Extraction of node-level credentials, private keys, configuration files, and authentication hashes.

---

## 3. K8s PSA Bypass via PV Abuse (`k8s_pvc_psa_bypass`)

### How It Works
1. **The Gap**: Pod Security Admission (PSA) restricts direct pod-level configurations like `hostPath` mounts to enforce baseline/restricted security standards. However, PSA does not inspect the underlying storage provisioning layer.
2. **Abuse**: The attacker bypasses PSA policy constraints by provisioning a raw Kubernetes `PersistentVolume` (PV) that specifies a target path on the host node filesystem:
   - `spec.hostPath.path: /etc`
3. **Mounting**: The attacker deploys a `PersistentVolumeClaim` (PVC) mapping to this PV. Because the volume properties are defined externally in the PV object, the pod mounts host storage without raising PSA alerts.

### Attack Type & MITRE Mapping
* **Tactic**: Defense Evasion
* **Technique**: [T1211: Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)

### Security Impact
* **Access Level**: Host filesystem read/write access from an otherwise unprivileged pod.
* **Impact**: Total compromise of the container boundary, allowing attackers to write persistence files or read sensitive configuration settings.

---

## 4. K8s External IPs Hijacking (`k8s_external_ips_mitm`)

### How It Works
1. **Mechanism**: Kubernetes Services can be configured with an `externalIPs` list. Traffic destined for those IPs within the cluster is routed to the Service's backend endpoints.
2. **Exploitation (CVE-2020-8554)**: An attacker creates a Service and binds it to a public IP (e.g., Google DNS `8.8.8.8`).
3. **Interception**: When other pods in the cluster attempt to contact `8.8.8.8`, `kube-proxy` redirects the traffic to the attacker's container instead.

### Attack Type & MITRE Mapping
* **Tactic**: Credential Access / Collection
* **Technique**: [T1557: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)

### Security Impact
* **Access Level**: Network interception inside the cluster network.
* **Impact**: Interception of API keys, DNS requests, and database connection secrets flowing to external integrations.

---

## 5. K8s MITM via Pod `status.podIP` Mutation (`k8s_pod_status_mitm`)

### How It Works
1. **The Vector**: Pod status subresources control the cluster's routing topology mappings. If an identity possesses the `patch` verb over the `pods/status` subresource, they can modify active routing records.
2. **Execution**: The attacker patches the `status.podIP` of a legitimate target pod to point to their own container's IP address.
3. **Routing Hijack**: The cluster control plane updates endpoints, sending service traffic aimed at the victim pod directly to the attacker.

### Attack Type & MITRE Mapping
* **Tactic**: Credential Access / Collection
* **Technique**: [T1557: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)

### Security Impact
* **Access Level**: Internal service traffic interception.
* **Impact**: Spoofing endpoints, capturing authentication credentials, and capturing application-level metadata.
