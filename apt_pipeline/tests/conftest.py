import sys
from pathlib import Path

# Add the pipeline root to sys.path so tests can `import utils`, `import
# validators`, `import pipeline`. Keeps tests/ a plain directory (no package
# marker needed) and avoids mutating the production import graph.
_PIPELINE_ROOT = Path(__file__).resolve().parent.parent
if str(_PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PIPELINE_ROOT))
