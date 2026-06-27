# Detection Note — T1555 (Retrieve a High Number of Secrets Manager Secrets via Batch)

**Signal:** secretsmanager:BatchGetSecretValue from a single principal — distinct from individual GetSecretValue pattern

**GuardDuty:** none specific to this technique

See the sigma/kql rules in this directory (complete their TODO event names).
