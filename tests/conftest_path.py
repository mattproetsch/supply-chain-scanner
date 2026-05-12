"""Helper: add src/ to sys.path so `import scs.*` works during tests."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
VENDOR = SRC / "scs" / "_vendor"
if str(VENDOR) not in sys.path:
    sys.path.insert(0, str(VENDOR))

FIXTURES = ROOT / "tests" / "fixtures"
DIST = ROOT / "dist"
