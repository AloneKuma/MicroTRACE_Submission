"""The frozen finding -> SAGE alert mapping (spec/baselines/sage-mapping.v2.yaml;
v0 and v1 are the records before G1c and before S-11)."""
import hashlib
import os
from dataclasses import dataclass

import yaml

from mtcore import REPO
from microtrace.v0 import common_pb2  # noqa: I100 (after mtcore: it sets up gen/)

DEFAULT = os.path.join(REPO, "spec", "baselines", "sage-mapping.v2.yaml")
RENDERING = os.path.join(REPO, "spec", "generator", "evidence-rendering.v0.yaml")

# MicroAttackStage of SAGE signatures/attack_stages.py at the pinned commit.
# A stage value >= 100 is high severity: SAGE builds attack graphs only
# toward such objectives.
STAGES = {
    "INIT": 0, "TARGET_IDEN": 1, "SURFING": 2, "SOCIAL_ENGINEERING": 3, "HOST_DISC": 4,
    "SERVICE_DISC": 5, "VULN_DISC": 6, "INFO_DISC": 7, "USER_PRIV_ESC": 10, "ROOT_PRIV_ESC": 11,
    "NETWORK_SNIFFING": 12, "BRUTE_FORCE_CREDS": 13, "ACCT_MANIP": 14, "TRUSTED_ORG_EXP": 15,
    "PUBLIC_APP_EXP": 16, "REMOTE_SERVICE_EXP": 17, "SPEARPHISHING": 18, "SERVICE_SPECIFIC": 19,
    "DEFENSE_EVASION": 20, "COMMAND_AND_CONTROL": 21, "LATERAL_MOVEMENT": 22, "ARBITRARY_CODE_EXE": 23,
    "PRIV_ESC": 99, "END_POINT_DOS": 100, "NETWORK_DOS": 101, "SERVICE_STOP": 102,
    "RESOURCE_HIJACKING": 103, "DATA_DESTRUCTION": 104, "CONTENT_WIPE": 105, "DATA_ENCRYPTION": 106,
    "DEFACEMENT": 107, "DATA_MANIPULATION": 108, "DATA_EXFILTRATION": 109, "DATA_DELIVERY": 110,
    "PHISHING": 111,
}
SELECTOR_KINDS = ("entity", "attr", "const")


@dataclass(frozen=True)
class Row:
    stage: str
    source: tuple
    destination: tuple
    port: str = ""


@dataclass(frozen=True)
class Mapping:
    version: str
    sha256: str
    sage_commit: str
    category: str
    rows: dict

    def extra_signatures(self):
        """{signature: stage name} for SAGE's SAGE_EXTRA_SIGNATURES file."""
        return {ftype: row.stage for ftype, row in sorted(self.rows.items())}


def included_types(path=RENDERING):
    """Finding types the rulebook includes (scored in Exp. 1 and 2)."""
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return sorted(f["id"] for f in doc["findings"] if f.get("included"))


def _check_selector(ftype, sel):
    if sel == "self":
        return
    kind, _, arg = sel.partition(":")
    if kind not in SELECTOR_KINDS or not arg:
        raise ValueError(f"{ftype}: bad endpoint selector {sel!r}")
    if kind == "entity" and arg.partition("#")[0] not in common_pb2.EntityType.keys():
        raise ValueError(f"{ftype}: unknown entity type in selector {sel!r}")


def load(path=DEFAULT):
    with open(path, "rb") as fh:
        raw = fh.read()
    doc = yaml.safe_load(raw)
    rows = {}
    for ftype, r in doc["findings"].items():
        if r["stage"] not in STAGES:
            raise ValueError(f"{ftype}: unknown SAGE stage {r['stage']!r}")
        for sel in [*r["source"], *r["destination"]]:
            _check_selector(ftype, sel)
        if "self" in r["source"]:
            raise ValueError(f"{ftype}: 'self' is a destination selector only")
        rows[ftype] = Row(r["stage"], tuple(r["source"]), tuple(r["destination"]), r.get("port", ""))
    return Mapping(doc["version"], hashlib.sha256(raw).hexdigest(), doc["sage_commit"], doc["category"], rows)
