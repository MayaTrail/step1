"""
Timing constants shared by the scan task and the model's staleness rule.

Separate from tasks.py so models.py can read them without a circular import,
and so the CI suite can assert SCAN_STALE_AFTER_SECONDS > SCAN_TIME_LIMIT
without importing the AWS runtime.
"""

# A GAAD collection plus chain ranking is minutes on a large account, not tens
# of minutes. The soft limit lets the task catch the timeout and write a real
# error message; without it a row sits at "running" forever and the page spins.
#
# Measured against a real 67-identity account: GAAD alone is ~30s; adding
# resource collection (EC2, Lambda, S3, ...) scoped to the tenant's declared
# regions (User.aws_audit_regions) was ~4 minutes total for 2 regions, versus
# ~17 minutes unscoped across all ~30 AWS regions. Region scoping is what
# keeps this budget realistic — a tenant who declares many regions can still
# exceed it, which is exactly what this limit is for.
SCAN_SOFT_TIME_LIMIT = 1500

# The hard limit. Celery enforces this by killing the worker process, so the
# task's own except-handlers do not run and the row does not reach a terminal
# status. That is what SCAN_STALE_AFTER_SECONDS exists to survive.
SCAN_TIME_LIMIT = 1560
