"""World history interval store.

Provides WorldHistory for time-indexed entity state lookups. at(kind, key, t)
returns the single valid state when exactly one state covers t, Ambiguous when
multiple states cover t (e.g. IP reuse boundary before deletion is observed),
or None when none cover t.

Validity intervals represent knowledge time: when the watch stream reports the
state, not when the object actually changed.
"""
import collections
from dataclasses import dataclass
from typing import Any


class _Ambiguous:
    """Singleton sentinel returned when a lookup is ambiguous."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self):
        return "Ambiguous"


#: Returned by WorldHistory.at() when multiple states are valid at t.
Ambiguous = _Ambiguous()

#: Sentinel for "still alive at end of run" (valid_to when not yet deleted).
FOREVER = (1 << 63) - 1


@dataclass
class ContextHistoryRow:
    """One row of the context_history table (unified-dataset-schema.md).

    valid_from/valid_to are actual creation/deletion times. observed_from is
    the knowledge time (creation time + watch delay). history validity
    intervals in WorldHistory use knowledge time.
    """
    run_id: str
    entity_type: str      # "Pod", "Container", "Node", "ServiceAccount", ...
    entity_uid: str
    valid_from: int       # ns since epoch: actual creation time
    valid_to: int         # ns since epoch: actual deletion time (FOREVER if alive)
    observed_from: int    # ns since epoch: knowledge time (creation + watch delay)
    parent_uid: str
    attributes: dict
    history_version: str
    ambiguity_reason: str  # non-empty when this row participates in a reuse ambiguity


class WorldHistory:
    """Time-indexed interval store for world entity states.

    An entity is considered valid at time t when valid_from <= t < valid_to
    (half-open interval). Validity intervals use knowledge time.
    """

    def __init__(self):
        # _entries[(kind, key)] = list of (valid_from, valid_to, state)
        self._entries: dict = collections.defaultdict(list)
        self._rows: list = []

    def add(
        self,
        kind: str,
        key: str,
        valid_from: int,
        valid_to: int,
        state: Any,
    ) -> None:
        """Register a state with its knowledge-time validity interval.

        Args:
            kind: entity kind, e.g. "Pod", "PodIP", "Container", "Cgroup",
                  "Process", "ProcessPID", "Node", "Namespace", "ServiceAccount"
            key: lookup key (UID, IP string, cgroup path, etc.)
            valid_from: start of validity (ns, knowledge time)
            valid_to: end of validity (ns, knowledge time; use FOREVER if alive)
            state: the state object (dataclass)
        """
        self._entries[(kind, key)].append((valid_from, valid_to, state))

    def at(self, kind: str, key: str, t: int) -> Any:
        """Return the state valid at time t, Ambiguous, or None.

        A lookup is ambiguous when two states both cover t. This models
        the case where the watch stream has not yet delivered a deletion
        event before a new object with the same key is observed.

        Args:
            kind: entity kind
            key: lookup key
            t: query time (ns since epoch)

        Returns:
            The single matching state, Ambiguous, or None.
        """
        entries = self._entries.get((kind, key), [])
        matches = [s for (vf, vt, s) in entries if vf <= t < vt]
        if not matches:
            return None
        if len(matches) == 1:
            return matches[0]
        return Ambiguous

    def add_history_row(self, row: "ContextHistoryRow") -> None:
        """Append a context_history row for the offline export table."""
        self._rows.append(row)

    @property
    def history_rows(self) -> list:
        """All context_history rows in insertion order."""
        return list(self._rows)

    def entries_by_kind(self, kind: str) -> list:
        """Return all (valid_from, valid_to, state) tuples for a given kind.

        Used by the scenario engine's tests to verify that a state change is
        visible in the history after a step is executed.
        """
        result = []
        for (k, _key), intervals in self._entries.items():
            if k == kind:
                result.extend(intervals)
        return result
