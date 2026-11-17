"""Phase 2 detection agents A-H (build step 4).

Rules follow spec/rules/rulebook.v0.yaml. The engine is pure (no Kafka) so
the same code runs offline over an envelope list and online in run.py.
"""
import os
import sys

from mtcore import REPO

# spec/tools/mtcodec.py is the reference encoder for keys and logical IDs;
# the agents import it rather than keeping a second copy.
_TOOLS = os.path.join(REPO, "spec", "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

DETECTOR_VERSION = "microtrace-agents/0.4.0+rulebook.v0"
