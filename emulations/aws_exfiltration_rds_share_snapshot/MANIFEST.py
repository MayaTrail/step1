"""
MANIFEST for the Exfiltrate RDS Snapshot by Sharing atomic emulation.

Migrated from Stratus Red Team `aws.exfiltration.rds-share-snapshot`. The id/name
is the import-safe underscore form; the original id is in `aliases`.
schema_version 3.
"""

MANIFEST = {
    'schema_version': 3,
    'name': 'aws_exfiltration_rds_share_snapshot',
    'display_name': 'Exfiltrate RDS Snapshot by Sharing',
    'description': "Simulates an attacker with rds:ModifyDBSnapshotAttribute sharing a manual RDS "
                   "DB snapshot with an external AWS account via the 'restore' attribute, letting "
                   "that account restore the database and read all of its contents. The share is "
                   "revoked again as a cleanup step.",
    'tier': 'atomic',
    'platform': 'aws',
    'added': '2026-08',
    'services': ['RDS'],
    'readiness': {'type': 'none'},
    'origin': 'stratus-red-team',
    'origin_label': 'ATOMIC TECHNIQUE',
    'tags': ['Exfiltration', 'RDS'],
    'technique_count': 1,
    'severity': 'HIGH',
    'aliases': 'aws.exfiltration.rds-share-snapshot',
    'attribution': 'Stratus Red Team — atomic technique',
    'active_since': 'Atomic technique (Stratus Red Team)',
    'targets': 'AWS accounts with RDS instances and roles holding rds:ModifyDBSnapshotAttribute',
    'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
    'attack_path': [{'phase': 1,
                     'name': 'Exfiltration',
                     'techniques': [{'id': 'T1537', 'name': 'Transfer Data to Cloud Account'}]}],
    'mitre_mappings': [{'id': 'T1537',
                        'name': 'Transfer Data to Cloud Account',
                        'tactic': 'Exfiltration',
                        'platform': 'AWS RDS',
                        'description': "rds:ModifyDBSnapshotAttribute adding the 'restore' permission "
                                       "for an external AWS account ID to a DB snapshot"}],
    'references': [{'icon': '>',
                    'title': 'Stratus Red Team — Exfiltrate RDS Snapshot by Sharing',
                    'source': 'Stratus Red Team · stratus-red-team.cloud',
                    'type': 'REFERENCE',
                    'color': 'cyan',
                    'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.rds-share-snapshot/'},
                   {'icon': '#',
                    'title': 'MITRE ATT&CK — T1537',
                    'source': 'MITRE ATT&CK · mitre.org',
                    'type': 'MITRE',
                    'color': 'purple',
                    'url': 'https://attack.mitre.org/techniques/T1537/'}],
    'phase_count': 1,
    'estimated_duration_minutes': 15,
    'estimated_cost_per_hour_usd': 0.02,
    'default_ttl_hours': 2,
    'total_resources': 5,
    'resources': {'ec2_count': 0, 'instance_types': []},
    'resource_costs': [],
}
