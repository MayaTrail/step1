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
# Both figures are a guess until measured against a production-scale account
# (spec, open items). Re-check them against the first real large scan.
SCAN_SOFT_TIME_LIMIT = 900

# The hard limit. Celery enforces this by killing the worker process, so the
# task's own except-handlers do not run and the row does not reach a terminal
# status. That is what SCAN_STALE_AFTER_SECONDS exists to survive.
SCAN_TIME_LIMIT = 960
