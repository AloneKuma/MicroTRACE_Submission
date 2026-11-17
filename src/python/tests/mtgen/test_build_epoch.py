"""The manifests' generated_at is a fixed, recent date (freeze proposal OQ-7).

run_pilot.py sets SOURCE_DATE_EPOCH explicitly; it must equal mtgen's
BUILD_EPOCH, or pilot builds and plain mtgen builds would differ.
"""
import datetime
import importlib.util
from pathlib import Path

import mtgen  # noqa: F401 — registers gen/ on sys.path
from mtgen.__main__ import BUILD_EPOCH

REPO = Path(__file__).resolve().parents[4]


def test_build_epoch_is_2026_10_25():
    d = datetime.datetime.fromtimestamp(BUILD_EPOCH, datetime.timezone.utc)
    assert d.strftime("%Y-%m-%dT%H:%M:%SZ") == "2026-10-25T00:00:00Z"


def test_run_pilot_uses_the_build_epoch():
    spec = importlib.util.spec_from_file_location(
        "run_pilot", REPO / "src" / "scripts" / "pilot" / "run_pilot.py")
    rp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rp)
    assert rp._env()["SOURCE_DATE_EPOCH"] == str(BUILD_EPOCH)
