"""
MANIFEST for the Delete Route53 Resolver Query Log Config atomic emulation.

Migrated from Stratus Red Team `aws.defense-evasion.dns-delete-logs`. The id/name
is the import-safe underscore form; the original id is in `aliases`.
schema_version 3.
"""

MANIFEST = {
    'schema_version': 3,
    'name': 'aws_defense_evasion_dns_delete_logs',
    'display_name': 'Delete Route53 Resolver Query Log Config',
    'description': "Simulates an attacker with route53resolver:DeleteResolverQueryLogConfig deleting "
                   "a Route53 Resolver query logging configuration attached to a VPC, eliminating "
                   "DNS query visibility used to detect C2 communication and data exfiltration "
                   "over DNS.",
    'tier': 'atomic',
    'platform': 'aws',
    'added': '2026-08',
    'services': ['Route53', 'VPC'],
    'readiness': {'type': 'none'},
    'origin': 'stratus-red-team',
    'origin_label': 'ATOMIC TECHNIQUE',
    'tags': ['Defense Evasion', 'Route 53'],
    'technique_count': 1,
    'severity': 'MEDIUM',
    'aliases': 'aws.defense-evasion.dns-delete-logs',
    'attribution': 'Stratus Red Team — atomic technique',
    'active_since': 'Atomic technique (Stratus Red Team)',
    'targets': 'AWS accounts with Route53 Resolver query logging and roles holding route53resolver:DeleteResolverQueryLogConfig',
    'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
    'attack_path': [{'phase': 1,
                     'name': 'Defense Evasion',
                     'techniques': [{'id': 'T1562.008', 'name': 'Impair Defenses: Disable or Modify Cloud Logs'}]}],
    'mitre_mappings': [{'id': 'T1562.008',
                        'name': 'Impair Defenses: Disable or Modify Cloud Logs',
                        'tactic': 'Defense Evasion',
                        'platform': 'AWS Route 53 Resolver',
                        'description': 'route53resolver:DeleteResolverQueryLogConfig removing a DNS query logging configuration'}],
    'references': [{'icon': '>',
                    'title': 'Stratus Red Team — Delete DNS Server Logs',
                    'source': 'Stratus Red Team · stratus-red-team.cloud',
                    'type': 'REFERENCE',
                    'color': 'cyan',
                    'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.dns-delete-logs/'},
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
    'total_resources': 7,
    'resources': {'ec2_count': 0, 'instance_types': []},
    'resource_costs': [],
}
