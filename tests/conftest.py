"""Make the repository package importable under every supported pytest launcher.

Some environments invoke pytest with an import mode that does not add the
checkout root to ``sys.path``.  The tests intentionally import the operator
scripts as ``scripts.*``; keep that contract independent of the caller's
``PYTHONPATH``.
"""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
