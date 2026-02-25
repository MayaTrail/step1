/* ══════════════════════════════════════════
   MayaTrail — Kubernetes Detections & Guardrails
   ══════════════════════════════════════════ */

window.MayaTrail.platforms.k8s = window.MayaTrail.platforms.k8s || {};

window.MayaTrail.platforms.k8s.detections = {
  ruleCount: 124,
  formats: 'Falco Rules \u00b7 SIGMA \u00b7 OPA/Rego',
  rules: [
    {
      title: 'Falco Rule \u2014 Privileged Container Creation',
      code: '- rule: Launch Privileged Container\n  desc: Detect the creation of a privileged container which may be used for container escape\n  condition: >\n    container and evt.type in (execve, execveat)\n    and container.privileged=true\n    and not k8s.ns.name in (kube-system, monitoring)\n  output: >\n    Privileged container started\n    (user=%user.name command=%proc.cmdline container=%container.name\n     image=%container.image.repository k8s.ns=%k8s.ns.name\n     k8s.pod=%k8s.pod.name)\n  priority: CRITICAL\n  tags:\n    - container\n    - cis\n    - mitre_privilege_escalation\n    - T1611\n\n- rule: Contact K8s API Server From Container\n  desc: Detect a container making direct calls to the Kubernetes API server\n  condition: >\n    outbound and fd.sip.name=\"kubernetes.default.svc.cluster.local\"\n    and not k8s.ns.name in (kube-system, monitoring, ingress-nginx)\n    and not container.image.repository in (approved-images-list)\n  output: >\n    Unexpected connection to K8s API server from container\n    (command=%proc.cmdline connection=%fd.name\n     container=%container.name image=%container.image.repository\n     k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name)\n  priority: WARNING\n  tags:\n    - network\n    - k8s\n    - mitre_discovery\n    - T1552.007'
    },
    {
      title: 'SIGMA Rule \u2014 Suspicious kubectl exec Command',
      code: 'title: Suspicious kubectl exec into Production Pod\nstatus: experimental\ndescription: Detects kubectl exec commands targeting production namespace pods outside maintenance windows\nreferences:\n  - https://attack.mitre.org/techniques/T1609/\ntags:\n  - attack.execution\n  - attack.t1609\nlogsource:\n  product: kubernetes\n  service: audit\ndetection:\n  selection:\n    verb: create\n    objectRef.resource: pods\n    objectRef.subresource: exec\n  filter_namespaces:\n    objectRef.namespace|startswith:\n      - "kube-"\n      - "monitoring"\n  filter_users:\n    user.username|contains:\n      - "system:serviceaccount"\n      - "eks:"\n  condition: selection and not filter_namespaces and not filter_users\nfalsepositives:\n  - Legitimate debugging by authorized SREs\n  - Automated health check scripts\nlevel: high'
    },
    {
      title: 'OPA/Rego \u2014 Block hostPath Volume Mounts',
      code: 'package kubernetes.admission\n\nimport data.kubernetes.namespaces\n\n# Deny pods with hostPath volume mounts (container escape vector)\ndeny[msg] {\n    input.request.kind.kind == "Pod"\n    volume := input.request.object.spec.volumes[_]\n    volume.hostPath\n    not exempt_namespace(input.request.namespace)\n    msg := sprintf(\n        "Pod \'%s\' in namespace \'%s\' uses hostPath volume \'%s\' mounting \'%s\'. \" \\\n        \"hostPath mounts are blocked by security policy (MITRE T1611).\",\n        [input.request.object.metadata.name,\n         input.request.namespace,\n         volume.name,\n         volume.hostPath.path]\n    )\n}\n\n# Deny privileged containers\ndeny[msg] {\n    input.request.kind.kind == "Pod"\n    container := input.request.object.spec.containers[_]\n    container.securityContext.privileged == true\n    not exempt_namespace(input.request.namespace)\n    msg := sprintf(\n        "Container \'%s\' in pod \'%s\' requests privileged mode. \" \\\n        \"Privileged containers are blocked by security policy (MITRE T1611).\",\n        [container.name, input.request.object.metadata.name]\n    )\n}\n\n# Exempt system namespaces\nexempt_namespace(ns) {\n    ns == "kube-system"\n}\nexempt_namespace(ns) {\n    ns == "monitoring"\n}'
    }
  ]
};

window.MayaTrail.platforms.k8s.guardrails = {
  excluded: [
    'kube-system namespace (all system pods)',
    'monitoring namespace (Prometheus, Grafana)',
    'Production clusters (tag: env=production)',
    'etcd data stores',
    'Ingress controller pods'
  ],
  schedule: 'Monday \u2013 Friday  |  02:00 \u2013 06:00 UTC  |  Auto-pause on PagerDuty alerts',
  scopeLimits: [
    'Emulations run only in sandbox namespaces',
    'No privileged pod creation on production nodes',
    'Container images restricted to MayaTrail-approved registry',
    'No access to kube-system secrets or serviceaccounts',
    'Network policies enforced to prevent cross-namespace lateral movement',
    'Automatic cleanup of all emulation artifacts after completion'
  ]
};
