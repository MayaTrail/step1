/* ══════════════════════════════════════════
   MayaTrail — Kubernetes IR Playbooks Data
   ══════════════════════════════════════════ */

window.MayaTrail.platforms.k8s = window.MayaTrail.platforms.k8s || {};

window.MayaTrail.platforms.k8s.playbooks = [
  // [0] TeamTNT Kubernetes Playbook
  {
    steps: [
      {
        title: 'Detect Cryptomining Pods',
        body: 'Search for pods with abnormally high CPU or GPU usage. Check for known mining container images (xmrig, minergate). Review pod specs for privileged containers, hostNetwork, or hostPID settings that enable resource abuse.',
        code: 'kubectl top pods --all-namespaces --sort-by=cpu | head -20\nkubectl get pods --all-namespaces -o json | \\\n  jq \'.items[] | select(.spec.containers[].image | test("xmrig|miner|cryptonight")) | .metadata.name\''
      },
      {
        title: 'Isolate Compromised Nodes',
        body: 'Cordon affected nodes to prevent new pod scheduling. Drain workloads to healthy nodes. Apply NetworkPolicies to block pod egress to known mining pool IPs and C2 domains.',
        code: 'kubectl cordon compromised-node-01\nkubectl drain compromised-node-01 --ignore-daemonsets --delete-emptydir-data\nkubectl apply -f - <<EOF\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: deny-mining-egress\nspec:\n  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n  - to:\n    - ipBlock:\n        cidr: 0.0.0.0/0\n        except: [\"pool.minexmr.com/32\", \"xmrpool.eu/32\"]\nEOF'
      },
      {
        title: 'Audit K8s Secrets Exposure',
        body: 'TeamTNT steals K8s secrets for cloud credentials. Enumerate all secrets accessed by compromised pods. Check RBAC roles for overly permissive secret access. Rotate all cloud provider credentials stored as K8s secrets.',
        code: 'kubectl get secrets --all-namespaces -o json | \\\n  jq \'.items[] | {namespace: .metadata.namespace, name: .metadata.name, type: .type}\'\nkubectl auth can-i --list --as=system:serviceaccount:default:default'
      },
      {
        title: 'Check Cloud Metadata Access',
        body: 'Verify if pods can access the cloud metadata endpoint (169.254.169.254). Check for IMDS credentials theft. Review pod service account annotations for workload identity configuration.',
        code: 'kubectl run test-metadata --rm -it --image=curlimages/curl -- \\\n  curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/\nkubectl get pods --all-namespaces -o json | \\\n  jq \'.items[].spec.containers[].env[]? | select(.name | test("AWS|GOOGLE|AZURE"))\''
      },
      {
        title: 'Remove Malicious Workloads',
        body: 'Delete all malicious pods, deployments, DaemonSets, and CronJobs. Check for persistence via webhooks, mutating admission controllers, or custom controllers that recreate mining pods.',
        code: 'kubectl delete cronjob malicious-cron -n default\nkubectl delete daemonset miner-ds -n kube-system\nkubectl get mutatingwebhookconfigurations\nkubectl get validatingwebhookconfigurations'
      },
      {
        title: 'Harden Kubernetes Cluster',
        body: 'Disable anonymous kubelet access. Enable audit logging. Enforce Pod Security Standards (restricted). Implement NetworkPolicies for least-privilege networking. Enable Workload Identity to eliminate node-level cloud creds.',
        code: 'kubectl label namespace default pod-security.kubernetes.io/enforce=restricted\nkubectl label namespace default pod-security.kubernetes.io/warn=restricted'
      }
    ]
  },
  // [1] Hildegard Playbook
  {
    steps: [
      {
        title: 'Detect Kubelet API Exploitation',
        body: 'Review kubelet access logs for unauthorized exec or run commands. Check for connections to kubelet port 10250 from non-API-server IPs. Monitor for unusual container creation events via kubelet.',
        code: 'kubectl get events --all-namespaces --sort-by=.lastTimestamp | grep -i "exec\\|attach\\|create"\njournalctl -u kubelet | grep "exec\\|run\\|create" | tail -50'
      },
      {
        title: 'Detect tmate/IRC C2 Channels',
        body: 'Hildegard uses tmate for reverse shells and IRC for C2. Check for network connections to tmate.io domains and IRC ports (6667, 6697). Review DNS logs for suspicious domain resolutions.',
        code: 'kubectl exec -it suspicious-pod -- netstat -tlnp 2>/dev/null\nkubectl exec -it suspicious-pod -- cat /proc/net/tcp\n# Check for tmate processes:\nkubectl exec -it suspicious-pod -- ps aux | grep -i "tmate\\|irc\\|bot"'
      },
      {
        title: 'Check for Container Escape Indicators',
        body: 'Hildegard mounts host filesystem for escape. Check for pods with hostPath volume mounts, especially to /, /etc, or /var/run/docker.sock. Look for processes running on the host that were spawned from containers.',
        code: 'kubectl get pods --all-namespaces -o json | \\\n  jq \'.items[] | select(.spec.volumes[]?.hostPath) | {name: .metadata.name, namespace: .metadata.namespace, hostPaths: [.spec.volumes[] | select(.hostPath) | .hostPath.path]}\''
      },
      {
        title: 'Audit All CronJobs and DaemonSets',
        body: 'Hildegard creates CronJobs and DaemonSets for persistence. Review all CronJobs for suspicious commands. Check DaemonSets running in kube-system or default namespace for unauthorized entries.',
        code: 'kubectl get cronjobs --all-namespaces -o wide\nkubectl get daemonsets --all-namespaces -o wide\nkubectl get cronjobs --all-namespaces -o json | \\\n  jq \'.items[] | {name: .metadata.name, schedule: .spec.schedule, command: .spec.jobTemplate.spec.template.spec.containers[0].command}\''
      },
      {
        title: 'Forensic Evidence Collection',
        body: 'Capture container filesystem snapshots before termination. Export kubelet logs, API server audit logs, and etcd backups. Preserve network flow logs and DNS query logs for incident timeline reconstruction.'
      },
      {
        title: 'Deploy Runtime Security',
        body: 'Install Falco or Tetragon for runtime threat detection. Enable Kubernetes audit logging at the RequestResponse level. Deploy admission controllers (OPA Gatekeeper, Kyverno) to prevent privileged pods. Implement network segmentation with Calico or Cilium.'
      }
    ]
  },
  // [2] cr8escape Playbook
  {
    steps: [
      {
        title: 'Identify CRI-O Vulnerability Exposure',
        body: 'Determine if your cluster uses CRI-O as the container runtime. Check the CRI-O version for CVE-2022-0811 (affected versions < 1.23.2). Review node configurations for kernel parameter protections.',
        code: 'kubectl get nodes -o json | \\\n  jq \'.items[] | {name: .metadata.name, containerRuntime: .status.nodeInfo.containerRuntimeVersion}\'\n# Check CRI-O version:\nkubectl debug node/NODE_NAME -it --image=busybox -- crio --version'
      },
      {
        title: 'Detect Container Escape Activity',
        body: 'Check for processes on the host that were spawned from container contexts. Review kernel audit logs for sysctl parameter changes. Monitor for unexpected file modifications in host filesystem directories.',
        code: 'journalctl -k | grep "sysctl\\|kernel.core_pattern"\nls -la /proc/*/root 2>/dev/null | grep -v "Permission denied"'
      },
      {
        title: 'Isolate Compromised Nodes',
        body: 'If container escape is confirmed, immediately cordon and isolate the affected nodes. Do not drain workloads until forensic evidence is preserved. Block all network traffic to/from compromised nodes.',
        code: 'kubectl cordon compromised-node\nkubectl taint nodes compromised-node quarantine=true:NoSchedule'
      },
      {
        title: 'Check for Cluster-Wide Compromise',
        body: 'After node escape, attackers target kubelet credentials for cluster access. Review RBAC for new ClusterRoleBindings. Check for unauthorized ServiceAccounts or tokens. Audit API server logs for privilege escalation.',
        code: 'kubectl get clusterrolebindings -o json | \\\n  jq \'.items[] | select(.roleRef.name=="cluster-admin") | {name: .metadata.name, subjects: .subjects}\'\nkubectl get serviceaccounts --all-namespaces | grep -v default'
      },
      {
        title: 'Patch & Upgrade CRI-O',
        body: 'Upgrade CRI-O to patched version (>= 1.23.2). Apply OS-level patches. Verify kernel parameter protections are enabled. Consider migrating to containerd if CRI-O patching is not feasible.',
        code: 'apt-get update && apt-get install -y cri-o=1.23.2-*\nsystemctl restart crio'
      }
    ]
  },
  // [3] Siloscape Playbook
  {
    steps: [
      {
        title: 'Detect Windows Container Escape',
        body: 'Monitor Windows nodes for unexpected processes running as SYSTEM that originated from container contexts. Check for CExecSvc exploitation indicators. Review Windows Event Logs for container escape patterns.',
        code: 'kubectl get pods --all-namespaces --field-selector spec.os.name=windows -o wide\nkubectl logs <suspicious-windows-pod> --tail=100'
      },
      {
        title: 'Check for Tor C2 Connections',
        body: 'Siloscape uses Tor for C2. Check for Tor process execution on Windows nodes. Monitor outbound connections to Tor entry/exit nodes. Review DNS queries for .onion-related domains.',
        code: 'kubectl exec -it windows-pod -- powershell "Get-Process | Where-Object {$_.Name -like \'*tor*\'}"\nkubectl exec -it windows-pod -- powershell "netstat -an | Select-String \'9001|9030|9050\'"'
      },
      {
        title: 'Audit Backdoor Containers',
        body: 'Siloscape deploys backdoor containers across the cluster. Check for newly created containers with suspicious images, especially those with elevated privileges or host-mounted volumes.',
        code: 'kubectl get pods --all-namespaces --sort-by=.metadata.creationTimestamp | tail -20\nkubectl get pods --all-namespaces -o json | \\\n  jq \'.items[] | select(.metadata.creationTimestamp > "2024-01-01") | {name: .metadata.name, image: .spec.containers[0].image}\''
      },
      {
        title: 'Rotate K8s API Credentials',
        body: 'Rotate all ServiceAccount tokens that may have been stolen. Regenerate kubeconfig files. Rotate etcd encryption keys. Invalidate any bootstrap tokens that might be exposed.',
        code: 'kubectl delete secret --all --namespace=default --field-selector type=kubernetes.io/service-account-token\nkubectl create token default --namespace=default'
      },
      {
        title: 'Harden Windows Kubernetes Nodes',
        body: 'Apply Windows Server security patches. Enable Windows Defender on all nodes. Implement pod security policies specific to Windows containers. Restrict container capabilities and remove unnecessary privileges.'
      }
    ]
  },
  // [4] Scarleteel Playbook
  {
    steps: [
      {
        title: 'Detect K8s-to-Cloud Credential Theft',
        body: 'Scarleteel steals cloud IAM credentials from K8s pods via metadata endpoints and Terraform state files. Check for pods making requests to cloud metadata endpoints. Review S3/GCS access for Terraform state file downloads.',
        code: 'kubectl get pods --all-namespaces -o json | \\\n  jq \'.items[] | select(.spec.containers[].env[]? | .value | test("AKIA|GOOG|AZURE")) | .metadata.name\'\naws cloudtrail lookup-events \\\n  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \\\n  --start-time 2024-01-01T00:00:00Z | grep "terraform.tfstate"'
      },
      {
        title: 'Contain Cloud Account Compromise',
        body: 'If cloud IAM credentials were stolen via K8s, immediately rotate the affected credentials. Apply restrictive IAM policies. Check for persistence mechanisms (new IAM users, roles, or access keys) created with stolen credentials.',
        code: 'aws iam list-users --query "Users[?CreateDate>=\'2024-01-01\']"\naws iam list-access-keys --user-name <user>\naws iam list-attached-user-policies --user-name <user>'
      },
      {
        title: 'Audit Terraform State Exposure',
        body: 'Scarleteel targets Terraform state files for secrets. Check if Terraform state is stored in accessible S3/GCS buckets. Verify state file encryption. Rotate all secrets found in Terraform state.',
        code: 'aws s3 ls s3://terraform-state-bucket/ --recursive\naws s3api get-bucket-encryption --bucket terraform-state-bucket\n# Check for exposed state files:\naws s3api get-bucket-policy --bucket terraform-state-bucket'
      },
      {
        title: 'Block Metadata Endpoint Access',
        body: 'Implement NetworkPolicies to block pod access to cloud metadata endpoints. Enable Workload Identity / IRSA to eliminate the need for node-level cloud credentials. Restrict IMDS access to approved pods only.',
        code: 'kubectl apply -f - <<EOF\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: block-metadata\nspec:\n  podSelector: {}\n  policyTypes: [Egress]\n  egress:\n  - to:\n    - ipBlock:\n        cidr: 0.0.0.0/0\n        except: [\"169.254.169.254/32\"]\nEOF'
      },
      {
        title: 'Deploy Defense-in-Depth',
        body: 'Enable K8s audit logging. Deploy Falco for runtime detection. Implement OPA/Gatekeeper policies to prevent privileged pods. Enable AWS IRSA / GKE Workload Identity. Encrypt Terraform state with customer-managed keys.'
      },
      {
        title: 'Schedule Re-Emulation',
        body: 'After remediation, schedule a MayaTrail Scarleteel emulation re-run to validate that K8s-to-cloud attack paths are blocked. Verify metadata endpoint access is denied. Confirm Terraform state is properly secured.'
      }
    ]
  }
];
