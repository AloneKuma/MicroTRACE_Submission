"""TGS runner with a fake consumer: it resumes from the store's applied
offsets, applies each consumed batch as one transaction, and never commits
Kafka offsets (tgs-contract.md section 2)."""
import json
import sys
import types

import pytest
from google.protobuf import json_format

import test_tgs_ingest as T
from mtcore.tgs import apply as A
from mtcore.tgs import run as R
from mtcore.tgs.store import MemoryStore

BEGINNING = -2


class TP:
    def __init__(self, topic, partition):
        self.topic, self.partition, self.offset = topic, partition, None


class Msg:
    def __init__(self, topic, partition, offset, env):
        self._t, self._p, self._o, self._v = topic, partition, offset, env.SerializeToString()

    def topic(self):
        return self._t

    def partition(self):
        return self._p

    def offset(self):
        return self._o

    def value(self):
        return self._v

    def error(self):
        return None


class Consumer:
    def __init__(self, conf):
        self.conf, self.queue, self.assigned, self.commits = conf, [], None, []

    def subscribe(self, topics, on_assign):
        self.topics, self.on_assign = topics, on_assign

    def assign(self, partitions):
        self.assigned = {(tp.topic, tp.partition): tp.offset for tp in partitions}

    def consume(self, n, timeout):
        out, self.queue = self.queue[:n], self.queue[n:]
        return out

    def commit(self, *a, **k):
        self.commits.append((a, k))

    def close(self):
        pass


@pytest.fixture(autouse=True)
def fake_kafka(monkeypatch):
    mod = types.ModuleType("confluent_kafka")
    mod.Consumer, mod.OFFSET_BEGINNING = Consumer, BEGINNING
    monkeypatch.setitem(sys.modules, "confluent_kafka", mod)


def test_partitions_resume_after_the_last_applied_offset_or_from_the_beginning():
    store = MemoryStore()
    A.apply_batch(store, [(T.NORM, 0, 41, T.file_read(1))])
    r = R.TgsRunner(store, "unused")
    assert r.consumer.conf["enable.auto.commit"] is False and r.consumer.conf["group.id"] == "graph-view"
    assert sorted(r.consumer.topics) == sorted(R.INPUTS)
    r.consumer.on_assign(r.consumer, [TP(T.NORM, 0), TP(T.NORM, 1), TP(T.FND, 0)])
    assert r.consumer.assigned == {(T.NORM, 0): 42, (T.NORM, 1): BEGINNING, (T.FND, 0): BEGINNING}


def test_each_consumed_batch_is_one_transaction_and_kafka_offsets_are_never_committed():
    store = MemoryStore()
    r = R.TgsRunner(store, "unused", batch_size=2)
    r.consumer.queue = [Msg(T.NORM, 0, i, T.file_read(i + 1)) for i in range(3)]
    assert r.step() == 2 and r.step() == 1 and r.step() == 0
    assert len(store.rows("apply_log")) == 2 and store.offsets() == {(T.NORM, 0): 2}
    assert r.consumer.commits == []


def test_offline_file_matches_the_online_path(tmp_path):
    envs = [T.file_read(1), T.file_read(2), T.file_read(3)]
    path = tmp_path / "records.jsonl"
    path.write_text("".join(json.dumps({"topic": T.NORM, "envelope": json_format.MessageToDict(e)}) + "\n"
                            for e in envs), encoding="utf-8")
    offline = MemoryStore()
    assert R.run_file(offline, str(path), batch_size=2) == 3
    online = MemoryStore()
    r = R.TgsRunner(online, "unused")
    r.consumer.queue = [Msg(T.NORM, 0, i, e) for i, e in enumerate(envs)]
    r.step()
    assert T._shape(offline) == T._shape(online) and offline.offsets() == online.offsets()
