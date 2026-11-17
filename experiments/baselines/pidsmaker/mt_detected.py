"""Choose the epoch and export the flagged nodes of one KAIROS or ORTHRUS run on our data.

Runs in the PIDSMaker container after main.py, with the same model, dataset and
config arguments, so it finds the same task directories:

    MT_OUT=/home/artifacts/mt-results/kairos_pilot \\
      python mt_detected.py kairos MT_PILOT --artifact_dir /home/artifacts/

Epoch rule (decided 2026-11-01, docs/plans/kairos-orthrus-our-data-plan.md
section 2): the epoch with the lowest mean edge loss on the validation runs,
ties to the earlier epoch. The loss is read from the per-edge CSVs the
inference loop writes under edge_losses/val/model_epoch_N/; their mean is the
"Val Loss" PIDSMaker logs. Only epochs with validation losses can be chosen.
PIDSMaker's own pick (best_model_selection) reads test labels and is ignored.

Nothing labelled is read for the choice. The flagged nodes are then the y_hat
of the chosen epoch only, from evaluation's result_model_epoch_N.pth; the
stats_*.pth files (test metrics) are never opened.

Writes to MT_OUT:
  val_loss.tsv   epoch, validation edges, mean edge loss (every epoch found)
  choice.json    the rule, the chosen epoch and the files read
  flagged.csv    node_uuid, index_id, node_type, score: the nodes flagged at that epoch
"""
import csv
import glob
import json
import os
import re

import pandas as pd
import torch

from pidsmaker.config import get_runtime_required_args, get_yml_cfg
from pidsmaker.utils.utils import init_database_connection

NODE_TABLES = ("subject_node_table", "file_node_table", "netflow_node_table")


def val_losses(val_dir):
    """{epoch: (edges, mean loss)} over every CSV of each model_epoch_N directory."""
    out = {}
    for d in glob.glob(os.path.join(val_dir, "model_epoch_*")):
        epoch = int(re.search(r"model_epoch_(\d+)$", d).group(1))
        n, total = 0, 0.0
        for f in sorted(glob.glob(os.path.join(d, "*.csv"))):
            loss = pd.read_csv(f, usecols=["loss"])["loss"]
            n += len(loss)
            total += float(loss.sum())
        if n:
            out[epoch] = (n, total / n)
    return out


def choose(losses):
    """Lowest mean validation loss; ties go to the earlier epoch."""
    return min(losses, key=lambda e: (losses[e][1], e))


def node_uuids(cfg, ids):
    """{index_id: (node_uuid, table)} for the given graph node IDs."""
    cur, conn = init_database_connection(cfg)
    out = {}
    try:
        for t in NODE_TABLES:
            cur.execute(f"SELECT index_id, node_uuid FROM {t} WHERE index_id = ANY(%s)", (list(ids),))
            for i, u in cur.fetchall():
                out[int(i)] = (u, t.split("_")[0])
    finally:
        conn.close()
    return out


def main():
    out_dir = os.environ["MT_OUT"]
    os.makedirs(out_dir, exist_ok=True)
    cfg = get_yml_cfg(get_runtime_required_args())

    losses = val_losses(os.path.join(cfg.training._edge_losses_dir, "val"))
    if not losses:
        raise SystemExit("no validation losses found")
    with open(os.path.join(out_dir, "val_loss.tsv"), "w") as fh:
        fh.write("epoch\tval_edges\tval_mean_loss\n")
        for e in sorted(losses):
            fh.write(f"{e}\t{losses[e][0]}\t{losses[e][1]:.10f}\n")
    epoch = choose(losses)

    result_file = os.path.join(cfg.evaluation._precision_recall_dir, f"result_model_epoch_{epoch}.pth")
    results = torch.load(result_file, weights_only=False)
    flagged = {int(n): r["score"] for n, r in results.items() if r["y_hat"] == 1}
    uuids = node_uuids(cfg, flagged)
    missing = sorted(set(flagged) - set(uuids))
    if missing:
        raise SystemExit(f"{len(missing)} flagged nodes not in the node tables, e.g. {missing[:5]}")
    with open(os.path.join(out_dir, "flagged.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["node_uuid", "index_id", "node_type", "score"])
        for n in sorted(flagged):
            w.writerow([uuids[n][0], n, uuids[n][1], repr(float(flagged[n]))])

    test_dir = os.path.join(cfg.training._edge_losses_dir, "test")
    choice = {
        "rule": "lowest mean edge loss on the validation runs, ties to the earlier epoch",
        "epoch": epoch,
        "val_mean_loss": losses[epoch][1],
        "epochs_with_val_loss": sorted(losses),
        "epochs_with_test_loss": sorted(int(d.rsplit("_", 1)[1]) for d in os.listdir(test_dir)),
        "nodes_scored": len(results),
        "flagged": len(flagged),
        "result_file": result_file,
        "edge_losses_dir": cfg.training._edge_losses_dir,
    }
    with open(os.path.join(out_dir, "choice.json"), "w") as fh:
        json.dump(choice, fh, indent=2)
    print(f"EPOCH {epoch} val_mean_loss {losses[epoch][1]:.6f} of {len(losses)} epochs; "
          f"flagged {len(flagged)} of {len(results)} nodes -> {out_dir}", flush=True)


if __name__ == "__main__":
    main()
