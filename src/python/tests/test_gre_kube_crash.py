"""GRE build step 7.3 on the kind cluster: the GRE process is killed
(os._exit(137)) at each interruption point, then reconciliation reads the
real API-server audit log and the Pod, and the outcome is checked against
the cluster itself; reconciliation also verifies the postcondition (7.4)
of a write the killed GRE never verified. A pause at the check-to-submit
point lets a change land between revalidation and write. Needs Postgres and
the GRE cluster (gre.env)."""
import json
import os
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives import serialization

import test_gre_kube as K
from test_gre_kube import name  # noqa: F401  (a unique object name, cleaned up after)
import test_tgs_ingest as T
import test_tgs_snapshot as TS
from mtcore import failpoint
from mtcore.gre.approver import ScriptedApprover
from mtcore.gre.execute import ISOLATION_LABEL
from mtcore.gre.kube import Kube
from mtcore.gre.reconcile import KindAuditLog, Reconciler
from mtcore.gre.store import PgGreStore
from mtcore.gre.verify import Verifier
from mtcore.tgs import apply as A

pytestmark = K.pytestmark
PY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUB_HEX = K.PUB.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


@pytest.fixture
def world(name, tmp_path):
    with T.pg_store() as tgs:
        A.apply_batch(tgs, T.batch(T.witness("w12", "f1", "f2"), topic=T.WIT))
        A.apply_batch(tgs, T.batch(TS.inc("in-1", members=("f1", "f2"), witnesses=("w12",)), topic=T.INC))
        gstore = PgGreStore(tgs.conn)
        gstore.apply_schema()
        schema = tgs.conn.execute("SELECT current_schema()").fetchone()[0]
        tgs.conn.commit()
        K.make_pod(name)
        approver = ScriptedApprover("ap", K.KEY, tgs, os.environ.get("MT_GRE_CLUSTER", "microtrace-gre"))
        kube = Kube.from_kubeconfig(os.environ["MT_GRE_KUBECONFIG"])
        rec = Reconciler(gstore, kube, KindAuditLog(), grace_s=2, verifier=Verifier(kube, deadline_s=90))
        yield {"schema": schema, "store": gstore, "rec": rec, "tmp": tmp_path, "name": name,
               "issue": lambda: approver.issue("in-1", "isolate_pod", "shop", K.obj("pod", name)["metadata"]["uid"],
                                               K.obj("pod", name)["metadata"]["resourceVersion"], {"pod": name})}


def run_gre(w, req, point=None, mode="exit", wait=True):
    path = w["tmp"] / f"{req['rid']}.json"
    path.write_text(json.dumps(req), encoding="utf-8")
    env = dict(os.environ, MT_FAILPOINT_LOG=str(w["tmp"] / "fp.log"))
    env.pop("MT_FAILPOINT", None)
    if point:
        env.update(MT_FAILPOINT=point, MT_FAILPOINT_MODE=mode)
        if mode == "pause":
            env["MT_FAILPOINT_RELEASE"] = str(w["tmp"] / "release")
    cmd = [sys.executable, "-m", "mtcore.gre.cli", "execute", "--request", str(path), "--trust", f"ap={PUB_HEX}",
           "--namespace", "shop", "--schema", w["schema"]]
    p = subprocess.Popen(cmd, cwd=PY, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not wait:
        return p
    out, err = p.communicate(timeout=120)
    return p.returncode, out, err


def reconcile_until(w, want, timeout=120):
    """Run reconciliation until it appends rows (the audit log is written
    asynchronously); returns the rows."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = w["rec"].run()
        if rows:
            assert [r["status"] for r in rows] == want, rows
            return rows
        time.sleep(1)
    raise AssertionError(f"no reconciliation within {timeout} s")


def labelled(w):
    return K.obj("pod", w["name"])["metadata"].get("labels", {}).get(ISOLATION_LABEL) == "true"


@pytest.mark.parametrize("point, want, effect", [
    ("gre.before_intent", ["Failed"], False),
    ("gre.after_intent_before_submit", ["Failed"], False),
    ("gre.after_submit_before_record", ["Submitted", "Verified"], True),
])
def test_a_killed_gre_is_reconciled_from_the_audit_log(world, point, want, effect):
    req = world["issue"]()
    code, _out, _err = run_gre(world, req, point)
    assert code == failpoint.EXIT_CODE
    [fired] = failpoint.read_log(str(world["tmp"] / "fp.log"))
    assert fired["failpoint"] == point
    assert world["store"].attempts(rid=req["rid"]) == []           # the GRE died before any outcome row
    time.sleep(2.5)                                                # past the grace period
    row, *verified = reconcile_until(world, want)
    assert labelled(world) is effect
    if effect:
        assert row["ref_audit"] and row["reason"] == "reconciled: the audit log records the accepted write"
        assert verified[0]["ref_audit"] == row["ref_audit"] and verified[0]["ref_verify"]
    code, out, _ = run_gre(world, req)                             # the same request again
    assert code == 0 and json.loads(out)["reason"] == "nonce already used"
    assert world["rec"].run() == []


def test_killed_before_verification_reconciliation_verifies(world):
    req = world["issue"]()
    code, _, _ = run_gre(world, req, "gre.before_verify")
    assert code == failpoint.EXIT_CODE and labelled(world)
    assert [a["status"] for a in world["store"].attempts(rid=req["rid"])] == ["Submitted"]
    [row] = reconcile_until(world, ["Verified"])
    assert row["reason"].startswith("reconciled: new connections to ") and row["ref_verify"]
    assert world["rec"].run() == []


def test_an_uninterrupted_run_ends_verified(world):
    req = world["issue"]()
    code, out, err = run_gre(world, req)
    assert code == 0, err
    assert json.loads(out)["status"] == "Verified", out
    assert [a["status"] for a in world["store"].attempts(rid=req["rid"])] == ["Submitted", "Verified"]


def test_a_change_between_check_and_write_is_caught(world):
    """Paused after the intent, before the write: the Pod's labels change.
    The write's resourceVersion precondition fails (409), the next round's
    revalidation sees the changed labels, and nothing is written."""
    req = world["issue"]()
    p = run_gre(world, req, "gre.after_intent_before_submit", mode="pause", wait=False)
    log = world["tmp"] / "fp.log"
    deadline = time.time() + 60
    while not failpoint.read_log(str(log)) and time.time() < deadline:
        time.sleep(0.2)
    K.kubectl("-n", "shop", "label", "pod", world["name"], "app=other", "--overwrite")
    (world["tmp"] / "release").write_text("go", encoding="utf-8")
    out, _err = p.communicate(timeout=120)
    res = json.loads(out)
    assert (res["status"], res["reason"]) == ("Rejected", "fields the action depends on changed since review: labels")
    assert not labelled(world)
    assert world["store"].open_intents() == []
