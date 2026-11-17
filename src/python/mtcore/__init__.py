"""MicroTRACE analysis-side code (agents, orchestrator, graph store, tools)."""
import os
import sys

# Generated protobuf modules (src/python/gen) import each other as
# "microtrace.v0.*", so that folder must be on the import path.
_GEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gen")
if _GEN not in sys.path:
    sys.path.insert(0, _GEN)

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
