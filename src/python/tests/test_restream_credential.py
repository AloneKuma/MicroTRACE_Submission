"""Restreamer credential join (G1b input): a token read waiting for its
TokenFileVersion holds the credential topic's heartbeat promise, so it is not
late when it resolves; a read that waits too long is reported, not dropped."""
import agent_fixtures as F
from microtrace.v0 import ebpf_pb2

from mtcore.agents.events import Ev
from mtcore.restream import CredentialJoin

WAIT = 600 * 10**9                                  # W_w in the dev parameters


def read(t, ino=7):
    ne = F.ebpf(t, "file.read", token=F.token_version(), process="/bin/cat")
    ne.ebpf.file_access.file.dev, ne.ebpf.file_access.file.ino = 1, ino
    return Ev(F.done(ne))


def version(ino=7, jti="jti-1"):
    return ebpf_pb2.TokenFileVersion(node_id=F.NODE, version_dir=F.token_version().version_dir, dev=1, ino=ino,
                                     jti=jti)


def test_waiting_read_holds_the_promise_until_it_resolves():
    cj = CredentialJoin(WAIT)
    assert cj.route(read(10)) == []                 # version not seen yet: waits
    assert cj.hold(F.ns(50)) == F.ns(10)            # promise held at the read
    [(jti, _env)] = cj.add_version(version())
    assert jti == "jti-1"
    assert cj.hold(F.ns(50)) == F.ns(50)            # nothing waiting: input's low
    assert cj.drain_given_up() == []


def test_read_waiting_longer_than_the_bound_is_reported():
    cj = CredentialJoin(WAIT)
    cj.route(read(10))
    assert cj.hold(F.ns(700)) == F.ns(700)          # 10 < 700 - 600: given up
    [ev] = cj.drain_given_up()
    assert ev.t == F.ns(10)
    assert cj.add_version(version()) == []          # too late to route


def test_overflow_gives_up_the_oldest_reads():
    cj = CredentialJoin(WAIT, max_waiting=2)
    for t, ino in ((30, 1), (10, 2), (20, 3)):
        cj.route(read(t, ino))
    assert [e.t for e in cj.drain_given_up()] == [F.ns(10)]
    assert cj.hold(F.ns(40)) == F.ns(20)
