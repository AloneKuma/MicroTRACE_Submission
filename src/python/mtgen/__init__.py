"""MicroTRACE dataset generator."""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PYTHON = os.path.dirname(_HERE)
_REPO = os.path.dirname(os.path.dirname(_PYTHON))

# Generated protobuf modules (src/python/gen) import each other as
# "microtrace.v0.*", so that folder must be on the import path.
_GEN = os.path.join(_PYTHON, "gen")
if _GEN not in sys.path:
    sys.path.insert(0, _GEN)

# spec/tools: mtcodec and check scripts
_SPEC_TOOLS = os.path.join(_REPO, "spec", "tools")
if _SPEC_TOOLS not in sys.path:
    sys.path.insert(0, _SPEC_TOOLS)
