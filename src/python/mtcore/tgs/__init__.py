"""Time-Aware Graph Store (build step 6; spec/graph/tgs-contract.md).

The TGS reads norm.events.v0, findings.v0, witness.decisions.v0, incidents.v0
and source.completeness.v0 and writes only its own Postgres tables. It never
writes to Kafka and cannot change a correlation decision.

6a: ingest. Every record becomes an evidence row; normalized events become
OBSERVED edges through one extractor per record type (extract.py); repeated
observations merge under the contract's rules (apply.py); each batch and its
applied offsets commit in one transaction (store.py, run.py).
"""
from mtcore.agents import routing  # noqa: F401  (puts spec/tools on the path for mtcodec)

EXTRACTOR_VERSION = "tgs-extract-0.1"
