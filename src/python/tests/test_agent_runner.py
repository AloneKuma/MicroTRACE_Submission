"""AgentRunner.safe_watermark: the agents advance while side topics keep
growing, and never past a watermark whose side records are still unread."""
from mtcore.agents.run import AgentRunner

SIDE = ("source.completeness.v0", 0)


class _Engine:
    def __init__(self):
        self.wm = None

    def input_watermark(self):
        return self.wm

    def knowledge_time(self, w):
        return w


def runner():
    r = object.__new__(AgentRunner)
    r.engine, r.position, r.side_snapshot = _Engine(), {}, None
    r.end = 0

    def side_ends():                  # the completeness topic grows by one record per look
        r.end += 1
        return {SIDE: (0, r.end)}
    r._side_ends = side_ends
    return r


def test_advances_under_steady_side_traffic():
    r = runner()
    r.engine.wm = 100
    assert r.safe_watermark() is None           # snapshot: end 1, nothing read yet
    r.position[SIDE] = 1                        # read up to the snapshot (end is now further on)
    r.engine.wm = 200                           # a newer heartbeat arrived meanwhile
    assert r.safe_watermark() == 100            # the snapshot's watermark, not the newer one
    assert r.safe_watermark() is None           # new snapshot for 200: end 2, read only to 1
    r.position[SIDE] = 2
    assert r.safe_watermark() == 200


def test_no_watermark_no_snapshot():
    r = runner()
    assert r.safe_watermark() is None and r.side_snapshot is None


def test_assign_all_takes_every_partition_without_group_membership(monkeypatch):
    """Runners assign by hand: side topics from the start, explicit offsets
    when given, else the committed offset; --from-latest pins inputs to the end."""
    import sys
    import types
    from mtcore.restream import assign_all

    class TP:
        def __init__(self, topic, partition, offset=-1001):
            self.topic, self.partition, self.offset = topic, partition, offset

    mod = types.ModuleType("confluent_kafka")
    mod.TopicPartition, mod.OFFSET_BEGINNING, mod.OFFSET_STORED = TP, -2, -1000
    monkeypatch.setitem(sys.modules, "confluent_kafka", mod)

    class Consumer:
        def assign(self, tps):
            self.got = {(tp.topic, tp.partition): tp.offset for tp in tps}

        def get_watermark_offsets(self, tp, timeout, cached):
            return 0, 50

    c = Consumer()
    assign_all(c, {"in": 2, "side": 1}, side=["side"], offsets={("in", 1): 7})
    assert c.got == {("in", 0): -1000, ("in", 1): 7, ("side", 0): -2}
    assign_all(c, {"in": 1, "side": 1}, side=["side"], from_latest=True)
    assert c.got == {("in", 0): 50, ("side", 0): -2}
