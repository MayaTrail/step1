"""
MANIFEST for the Backdoor SQS Queue via Open Resource Policy atomic emulation.

Ported from the pipeline emulation ATOMIC_SQS_OPEN_QUEUE_POLICY
(campaign id aws.persistence.sqs-open-queue-policy). The id/name is the
import-safe underscore form; the original id is in `aliases`. schema_version 3.
"""

MANIFEST = {
    'schema_version': 3,
    'name': 'aws_persistence_sqs_open_queue_policy',
    'display_name': 'Backdoor SQS Queue via Open Resource Policy',
    'description': "Simulates an attacker with sqs:SetQueueAttributes injecting a resource-based "
                   "policy that grants a wildcard principal ('*') SendMessage / ReceiveMessage / "
                   "DeleteMessage on a production SQS queue, creating a durable public read/write "
                   "channel into the queue. The injected policy is removed again as a cleanup step.",
    'tier': 'atomic',
    'platform': 'aws',
    'added': '2026-08',
    'services': ['SQS', 'IAM'],
    'readiness': {'type': 'none'},
    'origin': 'mayatrail',
    'origin_label': 'ATOMIC TECHNIQUE',
    'tags': ['Persistence', 'SQS'],
    'technique_count': 1,
    'severity': 'HIGH',
    'aliases': 'aws.persistence.sqs-open-queue-policy',
    'attribution': 'Atomic adversary technique — no specific threat actor',
    'active_since': 'Atomic technique (MayaTrail pipeline)',
    'targets': 'AWS accounts with SQS queues and over-broad sqs:SetQueueAttributes grants',
    'incidents': ['HackTricks — AWS SQS post-exploitation'],
    'attack_path': [{'phase': 1,
                     'name': 'Persistence',
                     'techniques': [{'id': 'T1098', 'name': 'Account Manipulation'}]}],
    'mitre_mappings': [{'id': 'T1098',
                        'name': 'Account Manipulation',
                        'tactic': 'Persistence',
                        'platform': 'AWS SQS',
                        'description': "sqs:SetQueueAttributes replacing the queue Policy with one "
                                       "granting Principal '*' SendMessage/ReceiveMessage/DeleteMessage"}],
    'references': [{'icon': '>',
                    'title': 'HackTricks — AWS SQS Post-Exploitation',
                    'source': 'HackTricks Cloud · cloud.hacktricks.wiki',
                    'type': 'REFERENCE',
                    'color': 'cyan',
                    'url': 'https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-post-exploitation/aws-sqs-post-exploitation/index.html'},
                   {'icon': '#',
                    'title': 'MITRE ATT&CK — T1098',
                    'source': 'MITRE ATT&CK · mitre.org',
                    'type': 'MITRE',
                    'color': 'purple',
                    'url': 'https://attack.mitre.org/techniques/T1098/'}],
    'phase_count': 1,
    'estimated_duration_minutes': 2,
    'estimated_cost_per_hour_usd': 0.0,
    'default_ttl_hours': 1,
    'total_resources': 10,
    'resources': {'ec2_count': 0, 'instance_types': []},
    'resource_costs': [],
}
