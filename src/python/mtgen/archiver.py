"""Minimal Kafka-to-archive writer for the transport round-trip kit.

Reads from one or more Kafka topics and writes length-delimited Envelope
records to the archive layout::

    <archive_root>/topic=<topic>/partition=<p>/<first_offset>-<last_offset>.pb.zst

Each partition is written to a single zstd-compressed file when flush() or
close() is called.  In-memory accumulation is used; this is intended for
Small dev runs (tens of thousands of records), not multi-GB captures.

``confluent_kafka`` is imported lazily so that tests can run without a Kafka
broker.  The public API (ArchivedRecord, Archiver, OfflineArchiver) does not
require confluent_kafka at import time.
"""
from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data record (broker-independent)
# ---------------------------------------------------------------------------

@dataclass
class ArchivedRecord:
    """One Kafka message as stored in the archive.

    Attributes:
        topic:      Kafka topic name.
        partition:  Kafka partition number.
        offset:     Kafka offset within the partition.
        logical_id: ``Envelope.logical_id`` (empty string when unknown).
        payload:    Raw serialised bytes (the Kafka message value).
    """
    topic: str
    partition: int
    offset: int
    logical_id: str
    payload: bytes


# ---------------------------------------------------------------------------
# Internal per-partition buffer
# ---------------------------------------------------------------------------

@dataclass
class _PartitionBuf:
    topic: str
    partition: int
    records: List[ArchivedRecord] = field(default_factory=list)
    first_offset: int = -1
    last_offset: int = -1

    def append(self, rec: ArchivedRecord) -> None:
        if self.first_offset < 0:
            self.first_offset = rec.offset
        self.last_offset = rec.offset
        self.records.append(rec)


# ---------------------------------------------------------------------------
# Archive writer
# ---------------------------------------------------------------------------

class Archiver:
    """Write Kafka records to the ``topic=/partition=`` archive layout.

    Parameters
    ----------
    archive_root:
        Root directory.  Sub-directories are created on flush.
    extract_logical_id:
        Optional callable ``(bytes) -> str`` that deserialises a payload and
        returns its ``logical_id``.  When omitted, ``logical_id`` is stored as
        an empty string.  Pass ``_envelope_logical_id`` for real use.

    Usage::

        archiver = Archiver(Path("archive"))
        archiver.write(topic, partition, offset, payload_bytes)
        archiver.flush()
        logical_ids = archiver.logical_id_set()
    """

    def __init__(
        self,
        archive_root: Path,
        extract_logical_id=None,
    ) -> None:
        self._root = Path(archive_root)
        self._extract_lid = extract_logical_id
        self._bufs: Dict[Tuple[str, int], _PartitionBuf] = {}
        self._flushed = False

    def write(
        self,
        topic: str,
        partition: int,
        offset: int,
        payload: bytes,
    ) -> None:
        """Buffer one Kafka message."""
        if self._flushed:
            raise RuntimeError("Archiver.write() called after flush()/close()")
        key = (topic, partition)
        if key not in self._bufs:
            self._bufs[key] = _PartitionBuf(topic=topic, partition=partition)
        lid = self._extract_lid(payload) if self._extract_lid else ""
        self._bufs[key].append(ArchivedRecord(
            topic=topic, partition=partition,
            offset=offset, logical_id=lid, payload=payload,
        ))

    def flush(self) -> List[Path]:
        """Write all buffers to disk; returns list of files written."""
        self._flushed = True
        written: List[Path] = []
        for (topic, partition), buf in sorted(self._bufs.items()):
            if not buf.records:
                continue
            path = self._partition_path(topic, partition, buf)
            path.parent.mkdir(parents=True, exist_ok=True)
            data = _encode_partition(buf.records)
            path.write_bytes(data)
            written.append(path)
        return written

    def close(self) -> List[Path]:
        """Alias for flush()."""
        return self.flush()

    def logical_id_set(self) -> frozenset:
        """Return the set of all logical_ids seen (empty strings excluded)."""
        ids: set = set()
        for buf in self._bufs.values():
            for rec in buf.records:
                if rec.logical_id:
                    ids.add(rec.logical_id)
        return frozenset(ids)

    def record_count(self) -> int:
        """Total number of records buffered."""
        return sum(len(b.records) for b in self._bufs.values())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _partition_path(self, topic: str, partition: int, buf: _PartitionBuf) -> Path:
        first = max(0, buf.first_offset)
        last = max(0, buf.last_offset)
        return (
            self._root
            / f"topic={topic}"
            / f"partition={partition}"
            / f"{first:020d}-{last:020d}.pb.zst"
        )


# ---------------------------------------------------------------------------
# Wire encoding (length-delimited + zstd)
# ---------------------------------------------------------------------------

def _encode_partition(records: List[ArchivedRecord]) -> bytes:
    """Encode records as length-delimited payloads, then zstd-compress.

    Format: repeated (4-byte big-endian length, payload bytes).
    zstd compression is applied if the ``zstandard`` package is available;
    otherwise the raw bytes are written with a ``.pb.zst`` extension still
    used (the extension is advisory on disk, not validated here).
    """
    buf = io.BytesIO()
    for rec in records:
        buf.write(struct.pack(">I", len(rec.payload)))
        buf.write(rec.payload)
    raw = buf.getvalue()
    try:
        import zstandard as zstd  # type: ignore
        cctx = zstd.ZstdCompressor(level=3)
        return cctx.compress(raw)
    except ImportError:
        # zstandard not installed; store raw (still usable by tests)
        return raw


def _decode_partition(data: bytes) -> List[bytes]:
    """Decode a partition file written by _encode_partition.

    Tries zstd decompression first; falls back to treating data as raw.
    """
    try:
        import zstandard as zstd  # type: ignore
        dctx = zstd.ZstdDecompressor()
        try:
            data = dctx.decompress(data)
        except Exception:
            pass  # not compressed
    except ImportError:
        pass

    payloads: List[bytes] = []
    view = memoryview(data)
    pos = 0
    while pos < len(view):
        if pos + 4 > len(view):
            break
        length = struct.unpack_from(">I", view, pos)[0]
        pos += 4
        payloads.append(bytes(view[pos:pos + length]))
        pos += length
    return payloads


# ---------------------------------------------------------------------------
# Logical-ID extractor (used by real Archiver instances)
# ---------------------------------------------------------------------------

def envelope_logical_id(payload: bytes) -> str:
    """Extract logical_id from a serialised Envelope.

    Imports protobuf lazily so that tests without a compiled schema can still
    import this module.  Returns an empty string on any decode error.
    """
    try:
        import mtgen  # noqa: F401 — registers gen/ on sys.path
        from microtrace.v0 import envelope_pb2
        env = envelope_pb2.Envelope()
        env.ParseFromString(payload)
        return env.logical_id
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Live Kafka consumer (requires confluent_kafka)
# ---------------------------------------------------------------------------

def end_offsets(
    bootstrap_servers: str,
    topics: List[str],
    timeout_s: float = 10.0,
) -> Dict[Tuple[str, int], int]:
    """Return ``{(topic, partition): high_watermark}`` for every partition.

    Taken before a replay and passed to ``KafkaArchiver(start_offsets=...)``
    so the archive holds only that replay's records.
    """
    from confluent_kafka import Consumer, TopicPartition  # type: ignore

    consumer = Consumer({"bootstrap.servers": bootstrap_servers,
                         "group.id": "mtgen-archiver-offsets"})
    try:
        meta = consumer.list_topics(timeout=timeout_s)
        out: Dict[Tuple[str, int], int] = {}
        for t in topics:
            for p in sorted(meta.topics[t].partitions):
                _, high = consumer.get_watermark_offsets(
                    TopicPartition(t, p), timeout=timeout_s)
                out[(t, p)] = high
        return out
    finally:
        consumer.close()


class KafkaArchiver:
    """Consume a set of Kafka topics and feed them into an Archiver.

    ``confluent_kafka`` is imported at construction time; if it is not
    installed, ImportError is raised with a helpful message.

    Parameters
    ----------
    bootstrap_servers:
        Kafka bootstrap server(s), e.g. ``"127.0.0.1:9092"``.
    topics:
        List of topic names to consume.
    archive_root:
        Output directory root.
    group_id:
        Consumer group ID (default: ``"mtgen-archiver"``).
    timeout_s:
        Per-poll timeout in seconds (default: 5.0).
    idle_stop_after_s:
        Stop consuming when no message arrives for this many seconds
        (default: 30.0).  Use 0 to consume indefinitely.
    start_offsets:
        Optional ``{(topic, partition): offset}`` (from :func:`end_offsets`
        taken before a replay).  When given, the archiver reads exactly those
        partitions from those offsets, so the archive holds only what was
        written after the snapshot.  Without it, it reads from the earliest
        offset (no offsets are committed).
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topics: List[str],
        archive_root: Path,
        group_id: str = "mtgen-archiver",
        timeout_s: float = 5.0,
        idle_stop_after_s: float = 30.0,
        start_offsets: Optional[Dict[Tuple[str, int], int]] = None,
    ) -> None:
        try:
            from confluent_kafka import Consumer, KafkaError, KafkaException  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "confluent_kafka is required for live Kafka archiving; "
                "install it with: pip install confluent-kafka"
            ) from exc

        self._Consumer = Consumer
        self._KafkaError = KafkaError
        self._KafkaException = KafkaException
        self._bootstrap = bootstrap_servers
        self._topics = list(topics)
        self._archiver = Archiver(archive_root, extract_logical_id=envelope_logical_id)
        self._group_id = group_id
        self._timeout_s = timeout_s
        self._idle_stop = idle_stop_after_s
        self._start_offsets = start_offsets

    def run(self) -> Archiver:
        """Consume until idle; returns the Archiver (not yet flushed)."""
        import time

        conf = {
            "bootstrap.servers": self._bootstrap,
            "group.id": self._group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }
        consumer = self._Consumer(conf)
        if self._start_offsets is not None:
            from confluent_kafka import TopicPartition  # type: ignore
            consumer.assign([
                TopicPartition(t, p, o)
                for (t, p), o in sorted(self._start_offsets.items())
                if t in self._topics
            ])
        else:
            consumer.subscribe(self._topics)
        last_msg_time = time.time()
        try:
            while True:
                msg = consumer.poll(timeout=self._timeout_s)
                if msg is None:
                    if self._idle_stop > 0 and (time.time() - last_msg_time) >= self._idle_stop:
                        break
                    continue
                if msg.error():
                    err = msg.error()
                    if err.code() == self._KafkaError._PARTITION_EOF:
                        continue
                    raise self._KafkaException(err)
                self._archiver.write(
                    topic=msg.topic(),
                    partition=msg.partition(),
                    offset=msg.offset(),
                    payload=msg.value() or b"",
                )
                last_msg_time = time.time()
        finally:
            consumer.close()
        return self._archiver


# ---------------------------------------------------------------------------
# Offline archiver: build from a list of (topic, partition, offset, payload)
# ---------------------------------------------------------------------------

class OfflineArchiver:
    """Build an archive from an in-memory list of records (no Kafka needed).

    Intended for tests and for replaying a saved base stream into the
    archive layout.

    Parameters
    ----------
    archive_root:
        Output directory root.
    extract_logical_id:
        Optional callable ``(bytes) -> str``.
    """

    def __init__(
        self,
        archive_root: Path,
        extract_logical_id=None,
    ) -> None:
        self._archiver = Archiver(archive_root, extract_logical_id=extract_logical_id)

    def feed(
        self,
        records: List[Tuple[str, int, int, bytes]],
    ) -> None:
        """Feed ``[(topic, partition, offset, payload), ...]`` records."""
        for topic, partition, offset, payload in records:
            self._archiver.write(topic, partition, offset, payload)

    def flush(self) -> Archiver:
        """Flush to disk and return the underlying Archiver."""
        self._archiver.flush()
        return self._archiver
