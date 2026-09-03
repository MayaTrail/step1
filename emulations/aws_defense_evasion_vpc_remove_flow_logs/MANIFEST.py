"""
MANIFEST for the Remove VPC Flow Logs atomic emulation.

Migrated from Stratus Red Team `aws.defense-evasion.vpc-remove-flow-logs`. The
id/name is the import-safe underscore form; the original id is in `aliases`.
schema_version 3.
"""

MANIFEST = {
    'schema_version': 3,
    'name': 'aws_defense_evasion_vpc_remove_flow_logs',
    'display_name': 'Remove VPC Flow Logs',
    'description': "Simulates an attacker with ec2:DeleteFlowLogs deleting a VPC's flow log "
                   "configuration to eliminate network traffic visibility, blinding detection of "
                   "lateral movement, data exfiltration, and C2 communication over the network.",
    'tier': 'atomic',
    'platform': 'aws',
    'added': '2026-08',
    'services': ['VPC', 'EC2'],
    'readiness': {'type': 'none'},
    'origin': 'stratus-red-team',
    'origin_label': 'ATOMIC TECHNIQUE',
    'tags': ['Defense Evasion', 'VPC'],
    'technique_count': 1,
    'severity': 'MEDIUM',
    'aliases': 'aws.defense-evasion.vpc-remove-flow-logs',
    'attribution': 'Stratus Red Team — atomic technique',
    'active_since': 'Atomic technique (Stratus Red Team)',
    'targets': 'AWS accounts with VPC flow logs and roles holding ec2:DeleteFlowLogs',
    'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
    'attack_path': [{'phase': 1,
                     'name': 'Defense Evasion',
                     'techniques': [{'id': 'T1562.008', 'name': 'Impair Defenses: Disable or Modify Cloud Logs'}]}],
    'mitre_mappings': [{'id': 'T1562.008',
                        'name': 'Impair Defenses: Disable or Modify Cloud Logs',
                        'tactic': 'Defense Evasion',
                        'platform': 'AWS VPC',
                        'description': 'ec2:DeleteFlowLogs removing the flow log configuration for a VPC'}],
    'references': [{'icon': '>',
                    'title': 'Stratus Red Team — Remove VPC Flow Logs',
                    'source': 'Stratus Red Team · stratus-red-team.cloud',
                    'type': 'REFERENCE',
                    'color': 'cyan',
                    'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.vpc-remove-flow-logs/'},
                   {'icon': '#',
                    'title': 'MITRE ATT&CK — T1562.008',
                    'source': 'MITRE ATT&CK · mitre.org',
                    'type': 'MITRE',
                    'color': 'purple',
                    'url': 'https://attack.mitre.org/techniques/T1562/008/'}],
    'phase_count': 1,
    'estimated_duration_minutes': 3,
    'estimated_cost_per_hour_usd': 0.0,
    'default_ttl_hours': 1,
    'total_resources': 8,
    'resources': {'ec2_count': 0, 'instance_types': []},
    'resource_costs': [],
}
