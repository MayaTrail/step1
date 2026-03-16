"""
Celery tasks for the simulations app.

run_simulation — loads and executes a simulation module from src/simulations/
                 by importing it dynamically, capturing its stdout/stderr.
"""

import importlib
import io
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from celery import shared_task
from django.apps import apps
from django.utils import timezone as dj_timezone
# Absolute path to the project root so the top-level `simulations` package
# is importable.  parents[2] == backend/ locally or /app in the container.
# SIMULATIONS_PATH can be overridden via environment variable.
# In docker-compose, simulations/ is mounted at /opt/simulations and
# SIMULATIONS_PATH=/opt is set.
_BACKEND_DIR = Path(__file__).resolve().parents[2]
SIMULATIONS_PATH = str(
    Path(os.environ.get("SIMULATIONS_PATH", str(_BACKEND_DIR.parent)))
)


def _get_run(run_id: str):
    """
    Retrieve a SimulationRun instance by its UUID primary key.

    Args:
        run_id: String UUID of the SimulationRun record.

    Returns:
        SimulationRun model instance.
    """
    SimulationRun = apps.get_model("simulations", "SimulationRun")
    return SimulationRun.objects.get(id=run_id)


@shared_task(bind=True, name="simulations.run_simulation")
def run_simulation(self, run_id: str) -> dict:
    """
    Celery task: execute a simulation module against a provisioned stack.

    Adds the project root to sys.path, then imports the requested module
    via importlib.  Stdout and stderr from the module are captured
    in-process.  The run record is updated with timing, status, and output.

    Args:
        self: Celery task instance (provided by bind=True).
        run_id: UUID string of the SimulationRun record to execute.

    Returns:
        Dict with keys: run_id, status, stdout, stderr.
    """
    SimulationRun = apps.get_model("simulations", "SimulationRun")

    try:
        run = _get_run(run_id)

        run.status = SimulationRun.Status.RUNNING
        run.started_at = dj_timezone.now()
        run.save(update_fields=["status", "started_at"])

        # Insert the project root (or SIMULATIONS_PATH) into sys.path
        # so `import simulations.<module>` resolves correctly.
        if SIMULATIONS_PATH not in sys.path:
            sys.path.insert(0, SIMULATIONS_PATH)

        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        try:
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                mod = importlib.import_module(f"simulations.{run.module}")
                # If the module exposes a run() entry point, call it.
                if hasattr(mod, "run"):
                    mod.run()
            final_status = SimulationRun.Status.COMPLETED
        except Exception as module_exc:
            stderr_buf.write(f"\n[task error] {type(module_exc).__name__}: {module_exc}")
            final_status = SimulationRun.Status.FAILED

        run.stdout = stdout_buf.getvalue()
        run.stderr = stderr_buf.getvalue()
        run.status = final_status
        run.completed_at = dj_timezone.now()
        run.save(update_fields=["stdout", "stderr", "status", "completed_at"])

        return {
            "run_id": run_id,
            "status": final_status,
            "stdout": run.stdout,
            "stderr": run.stderr,
        }

    except Exception as exc:
        try:
            run = _get_run(run_id)
            run.status = SimulationRun.Status.FAILED
            run.stderr = f"[task error] {type(exc).__name__}: {exc}"
            run.completed_at = dj_timezone.now()
            run.save(update_fields=["status", "stderr", "completed_at"])
        except Exception:
            pass
        raise self.retry(exc=exc, max_retries=0) from exc
