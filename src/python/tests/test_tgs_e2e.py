"""End to end (build step 6a): records on the dev Kafka -> TgsRunner ->
Postgres. The graph built from Kafka equals the one built offline from the
same records, applied offsets are real Kafka offsets, and a restarted runner
resumes after them without duplicating anything. Skipped unless both the dev
Kafka and the TGS Postgres are reachable."""
import os
import socket
import time
import uuid

import pytest

pytest.importorskip("confluent_kafka")
BOOTSTRAP = os.environ.get("MT_KAFKA", "127.0.0.1:9092")


def _kafka_up():
    host, port = BOOTSTRAP.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=2).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _kafka_up(), reason=f"no Kafka at {BOOTSTRAP}")

from confluent_kafka import Consumer, Producer, TopicPartition  # noqa: E402

import test_tgs_ingest as T  # noqa: E402
from mtcore.tgs import apply as A  # noqa: E402
from mtcore.tgs.run import INPUTS, TgsRunner  # noqa: E402
from mtcore.tgs.store import MemoryStore  # noqa: E402


@pytest.fixture
def pg():
    with T.pg_store() as s:
        yield s


def _start_at_topic_ends(store):
    """Record every input partition's current end as applied, so the runner
    skips what earlier runs left on the shared dev topics and resumes, as
    after any restart, from the store's offsets."""
    c = Consumer({"bootstrap.servers": BOOTSTRAP, "group.id": "tgs-e2e-probe"})
    md = c.list_topics(timeout=30).topics
    store.begin()
    for t in INPUTS:
        for p in md[t].partitions:
            _lo, hi = c.get_watermark_offsets(TopicPartition(t, p), timeout=10, cached=False)
            store.set_offset(t, p, hi - 1, 0)
    store.commit()
    c.close()


def _topic_ends():
    """{(topic, partition): high watermark} of every input partition."""
    c = Consumer({"bootstrap.servers": BOOTSTRAP, "group.id": "tgs-e2e-probe"})
    md = c.list_topics(timeout=30).topics
    out = {(t, p): c.get_watermark_offsets(TopicPartition(t, p), timeout=10, cached=False)[1]
           for t in INPUTS for p in md[t].partitions}
    c.close()
    return out


def _records(tag, n0, n):
    evs = [T.file_read(t, tgid=100 + (t % 3)) for t in range(n0, n0 + n)]
    for e in evs:
        e.normalized_event.event_id = f"{tag}-{e.normalized_event.event_id}"
        e.logical_id = e.normalized_event.event_id
    out = [(T.NORM, e) for e in evs]
    out.append((T.FND, T.finding(f"fd-{tag}-{n0}", ("POD", f"pod-{tag}"))))
    out.append((T.WIT, T.witness(f"wt-{tag}-{n0}", f"fd-{tag}-{n0}", f"fd-{tag}-x")))
    out.append((T.INC, T.incident(f"in-{tag}-{n0}", members=(f"fd-{tag}-{n0}",))))
    return out


def _produce(recs):
    prod = Producer({"bootstrap.servers": BOOTSTRAP})
    for topic, env in recs:
        prod.produce(topic, value=env.SerializeToString(), key=env.logical_id.encode())
    assert prod.flush(30) == 0


def _drain(runner, want, timeout=60):
    """Step until `want` records have been applied (or time out)."""
    got, deadline = 0, time.time() + timeout
    while got < want and time.time() < deadline:
        got += runner.step()
    return got


def test_kafka_graph_equals_offline_and_a_restart_resumes(pg):
    tag = uuid.uuid4().hex[:8]
    first = _records(tag, 1, 12)
    group = f"tgs-e2e-{tag}"
    _start_at_topic_ends(pg)
    r = TgsRunner(pg, BOOTSTRAP, group=group, batch_size=5)
    _produce(first)
    assert _drain(r, len(first)) == len(first)
    r.consumer.close()

    offline = MemoryStore()
    for topic, env in first:
        A.apply_batch(offline, [(topic, 0, 0, env)])
    assert T._shape(pg) == T._shape(offline)
    # Every partition holding records has its last record applied. (Was all(o >= 0), which held
    # only on a long-lived dev Kafka: on fresh topics an empty partition is correctly at -1,
    # "nothing applied"; found 2026-11-16 on a fresh kind node.)
    offs, ends = pg.offsets(), _topic_ends()
    assert offs and all(offs.get(k, -1) == hi - 1 for k, hi in ends.items() if hi > 0)

    second = _records(tag, 50, 6)
    _produce(second)
    r2 = TgsRunner(pg, BOOTSTRAP, group=group, batch_size=5)     # resumes from the store's offsets
    assert _drain(r2, len(second)) == len(second)
    r2.consumer.close()
    for topic, env in second:
        A.apply_batch(offline, [(topic, 0, 0, env)])
    assert T._shape(pg) == T._shape(offline)
    assert len(pg.rows("events")) == len(offline.rows("events")) == 18
