"""Run the GRE from the command line: execute one request, or reconcile.

    python -m mtcore.gre.cli execute --request req.json --trust ap=<hex public key> \\
        --namespace shop [--cluster microtrace-gre] [--dsn DSN] [--schema S] [--kubeconfig K]
    python -m mtcore.gre.cli reconcile [--grace 30] [--dsn DSN] [--schema S] [--kubeconfig K]

Both verify postconditions (verify.py) unless --no-verify is given.
--ablate GUARD (repeatable; nonce, snapshot, revalidation, postcondition,
permissions) switches a guard off for an Exp. 5 ablation run (7.5).

Prints the outcome as JSON. The TGS and the GRE tables are read through
--dsn (default $MT_TGS_TEST_DSN, for tests; a deployment uses open_gre's
roles) with search_path --schema. The Kubernetes credential is the
executor's own (--kubeconfig, default $MT_GRE_KUBECONFIG). Failpoints are
armed through the MT_FAILPOINT* environment (mtcore.failpoint); the Exp. 5
crash runs kill this process at the GRE's interruption points.
"""
import argparse
import json
import os
import sys

import psycopg
from psycopg import sql

from mtcore.gre import request as R
from mtcore.gre.execute import Executor
from mtcore.gre.kube import Kube
from mtcore.gre.reconcile import KindAuditLog, Reconciler
from mtcore.gre.store import PgGreStore
from mtcore.gre.validate import GUARDS, Gre, GreConfig, TgsGraph
from mtcore.gre.verify import AcceptanceVerifier, Verifier
from mtcore.tgs.store import PgStore


def _connect(dsn, schema):
    conn = psycopg.connect(dsn)
    if schema:
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.commit()
    return conn


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the MicroTRACE GRE once.")
    ap.add_argument("command", choices=["execute", "reconcile"])
    ap.add_argument("--request")
    ap.add_argument("--trust", action="append", default=[], help="key_id=<32-byte public key, hex>")
    ap.add_argument("--namespace", action="append", default=[])
    ap.add_argument("--cluster", default=os.environ.get("MT_GRE_CLUSTER", "microtrace-gre"))
    ap.add_argument("--dsn", default=os.environ.get("MT_TGS_TEST_DSN"))
    ap.add_argument("--schema")
    ap.add_argument("--kubeconfig", default=os.environ.get("MT_GRE_KUBECONFIG"))
    ap.add_argument("--grace", type=float, default=30)
    ap.add_argument("--no-verify", action="store_true", help="stop at Submitted (no postcondition check)")
    ap.add_argument("--ablate", action="append", default=[], choices=GUARDS, help="switch a guard off (7.5)")
    a = ap.parse_args(argv)
    kube = Kube.from_kubeconfig(a.kubeconfig)
    if "postcondition" in a.ablate:
        verifier = AcceptanceVerifier()
    else:
        verifier = None if a.no_verify else Verifier(kube)
    gstore = PgGreStore(_connect(a.dsn, a.schema))
    if a.command == "reconcile":
        rows = Reconciler(gstore, kube, KindAuditLog(), grace_s=a.grace, verifier=verifier).run()
        print(json.dumps([{k: r[k] for k in ("rid", "status", "reason", "ref_audit", "ref_verify")} for r in rows]))
        return 0
    keys = {}
    for t in a.trust:
        kid, hexkey = t.split("=", 1)
        keys[kid] = R.load_public_key(bytes.fromhex(hexkey))
    config = GreConfig(a.cluster, frozenset(a.namespace), keys, ablate=frozenset(a.ablate))
    gre = Gre(config, TgsGraph(PgStore(_connect(a.dsn, a.schema))), gstore)
    with open(a.request, encoding="utf-8") as fh:
        req = json.load(fh)
    out = Executor(gre, kube, verifier=verifier).execute(req)
    print(json.dumps({"status": out.status, "reason": out.reason, "timings_ms": out.timings_ms,
                      "ablated": sorted(a.ablate)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
