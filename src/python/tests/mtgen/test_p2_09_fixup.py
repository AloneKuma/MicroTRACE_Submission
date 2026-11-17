"""p2-09 fix-up tests: shipper-input rules, watermarks, CLI determinism,
manifest schema, evidence archive and context history in the run directory.
"""
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
from google.protobuf import json_format

import mtgen  # noqa: F401
from mtgen.emit import write_context_history
from mtgen.evidence import EvidenceArchive
from mtgen.history import ContextHistoryRow
from microtrace.v0 import common_pb2, envelope_pb2, keys_pb2, ship_pb2

from test_p2_09 import (
    _build_and_emit, _make_ebpf_ne, _make_gateway_ne, _make_heartbeat,
)

REPO = Path(__file__).resolve().parents[4]
PY_SRC = REPO / "src" / "python"


# ---------------------------------------------------------------------------
# Port of the Go shipper input rules
# (src/go/cmd/shipper/main.go: type line, handleLine).
# ---------------------------------------------------------------------------

def _go_handle_line(raw: str):
    """Mirror handleLine: returns ("watermark", lane, time) or ("item", lane, line)."""
    l = json.loads(raw)                                   # json.Unmarshal
    lane = l.get("lane", "") or "NORMAL"                  # lane defaults to NORMAL
    if lane not in ship_pb2.Lane.keys():                  # pb.Lane_value
        raise ValueError(f"unknown lane {lane!r}")
    if l.get("watermark"):
        # time.Parse(time.RFC3339Nano, ...): UTC, <= 9 fractional digits
        wm = l["watermark"]
        assert wm.endswith("Z"), wm
        datetime.datetime.strptime(wm[:-1].split(".")[0], "%Y-%m-%dT%H:%M:%S")
        return ("watermark", lane, wm)
    if l.get("key_type", "") not in keys_pb2.KeyType.keys():   # pb.KeyType_value
        raise ValueError(f"unknown key type {l.get('key_type')!r}")
    env = envelope_pb2.Envelope()
    json_format.ParseDict(l["envelope"], env)             # protojson.Unmarshal
    assert isinstance(l.get("key_components", []), list)
    return ("item", lane, l)


def _all_lines(shipper_dir: Path):
    for p in sorted(shipper_dir.glob("*.jsonl")):
        for n, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            yield p, n, raw


def test_shipper_lines_obey_go_input_rules(tmp_path):
    nes = [_make_ebpf_ne("node-a", "proc.exec"), _make_ebpf_ne("node-a", "ns.change"),
           _make_gateway_ne()]
    _build_and_emit(tmp_path, node_uids=["node-a"], ne_list=nes,
                    heartbeats=[_make_heartbeat()])
    n_items = n_wm = 0
    for p, n, raw in _all_lines(tmp_path / "shipper"):
        kind, _lane, _ = _go_handle_line(raw)
        n_items += kind == "item"
        n_wm += kind == "watermark"
    assert n_items >= 3 and n_wm >= 2


def test_watermarks_declared_and_monotone_per_lane(tmp_path):
    nes = [_make_ebpf_ne("node-a", "proc.exec"), _make_ebpf_ne("node-a", "ns.change")]
    _build_and_emit(tmp_path, node_uids=["node-a"], ne_list=nes)
    for p in (tmp_path / "shipper").glob("*.jsonl"):
        per_lane = {}
        for raw in p.read_text(encoding="utf-8").splitlines():
            kind, lane, v = _go_handle_line(raw)
            per_lane.setdefault(lane, []).append((kind, v))
        for lane, seq in per_lane.items():
            assert seq[0][0] == "watermark", f"{p.name}/{lane}: no watermark first"
            assert seq[-1][0] == "watermark", f"{p.name}/{lane}: no final watermark"
            wms = [v for k, v in seq if k == "watermark"]
            assert wms == sorted(wms), f"{p.name}/{lane}: watermark went backwards"


# ---------------------------------------------------------------------------
# Archive and context history writers
# ---------------------------------------------------------------------------

def test_evidence_archive_write_to(tmp_path):
    a = EvidenceArchive("run-x")
    r1 = a.put(b"hello", common_pb2.PROTECTED_HTTP_BODY)
    a.put(b"world", common_pb2.PROTECTED_HTTP_BODY)
    h = a.write_to(tmp_path / "ev")
    assert len(h) == 64
    assert (tmp_path / "ev" / "objects" / r1.object_key[:2] / r1.object_key).read_bytes() == b"hello"
    idx = json.loads((tmp_path / "ev" / "index.json").read_text())
    assert [o["sha256"] for o in idx["objects"]] == sorted(o["sha256"] for o in idx["objects"])
    assert a.write_to(tmp_path / "ev2") == h


def test_write_context_history_sorted_and_stable(tmp_path):
    rows = [
        ContextHistoryRow("r", "Pod", uid, 1, 2, 3, "p", {"b": 1, "a": 2}, "context.v0", "")
        for uid in ("z", "a")
    ]
    h1 = write_context_history(rows, tmp_path / "a.jsonl")
    h2 = write_context_history(list(reversed(rows)), tmp_path / "b.jsonl")
    assert h1 == h2
    uids = [json.loads(l)["entity_uid"] for l in (tmp_path / "a.jsonl").read_text().splitlines()]
    assert uids == ["a", "z"]


# ---------------------------------------------------------------------------
# End-to-end CLI: determinism, manifest, run-directory contents
# ---------------------------------------------------------------------------

def _cli_build(out: Path, hashseed: str):
    env = dict(os.environ, PYTHONHASHSEED=hashseed)
    subprocess.run(
        [sys.executable, "-m", "mtgen", "build", "--world", "Small",
         "--scenarios", "all", "--seed", "7", "--duration-s", "30",
         "--out", str(out)],
        cwd=PY_SRC, env=env, check=True, capture_output=True,
    )


def _tree(root: Path):
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.fixture(scope="module")
def cli_runs(tmp_path_factory):
    base = tmp_path_factory.mktemp("cli")
    _cli_build(base / "a", "1")
    _cli_build(base / "b", "2")
    return base / "a", base / "b"


def test_cli_builds_are_byte_identical(cli_runs):
    a, b = cli_runs
    ta, tb = _tree(a), _tree(b)
    assert ta.keys() == tb.keys()
    differing = [k for k in ta if ta[k] != tb[k]]
    assert not differing, f"files differ across builds: {differing}"


def test_cli_text_files_use_lf_on_every_platform(cli_runs):
    # A run built on Windows must equal one built on Linux byte for byte.
    a, _ = cli_runs
    crlf = [k for k, v in _tree(a).items()
            if k.endswith((".json", ".jsonl")) and b"\r" in v]
    assert not crlf, f"CRLF line endings in: {crlf}"


def test_cli_manifest_matches_schema_and_hashes(cli_runs):
    a, _ = cli_runs
    schema = json.loads((REPO / "spec/generator/build-manifest.schema.json").read_text())
    manifest = json.loads((a / "manifest.json").read_text())
    jsonschema.validate(manifest, schema)
    assert "seeds" not in manifest            # seeds live under restricted/
    assert (a / "restricted" / "seeds" / "manifest.json").exists()
    for key in ("base_stream_sha256", "truth_sha256", "evidence_archive_sha256",
                "context_history_sha256"):
        assert len(manifest["hashes"][key]) == 64
    assert manifest["spec_file_sha256"] and manifest["code_sha256"]
    for rel in manifest["archive_paths"].values():
        assert (a / rel).exists(), rel


def test_cli_run_dir_has_archive_and_context_history(cli_runs):
    a, _ = cli_runs
    assert (a / "evidence" / "index.json").exists()
    assert (a / "context_history.jsonl").stat().st_size > 0
    assert list((a / "shipper").glob("*.jsonl"))
