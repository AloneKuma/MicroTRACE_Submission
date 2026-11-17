"""Kafka's default key partitioner (Java client), per spec/kafka/kafka-contract.md.

Every producer must place a key on the same partition as the Java client:
murmur2 of the key bytes, made positive, modulo the partition count
(test KAFKA-KEY-PARTITION).
"""


def murmur2(data: bytes) -> int:
    """Kafka's murmur2 (org.apache.kafka.common.utils.Utils.murmur2), as an unsigned 32-bit value."""
    m, r = 0x5BD1E995, 24
    length = len(data)
    h = (0x9747B28C ^ length) & 0xFFFFFFFF
    for i in range(length // 4):
        j = i * 4
        k = data[j] | (data[j + 1] << 8) | (data[j + 2] << 16) | (data[j + 3] << 24)
        k = (k * m) & 0xFFFFFFFF
        k ^= k >> r
        k = (k * m) & 0xFFFFFFFF
        h = (h * m) & 0xFFFFFFFF
        h ^= k
    tail = length & ~3
    extra = length % 4
    if extra == 3:
        h ^= data[tail + 2] << 16
    if extra >= 2:
        h ^= data[tail + 1] << 8
    if extra >= 1:
        h ^= data[tail]
        h = (h * m) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * m) & 0xFFFFFFFF
    h ^= h >> 15
    return h


def as_signed(h: int) -> int:
    """The same value as Java's signed int."""
    return h - (1 << 32) if h & 0x80000000 else h


def partition_for(key: bytes, partitions: int) -> int:
    """Utils.toPositive(murmur2(key)) % partitions."""
    return (murmur2(key) & 0x7FFFFFFF) % partitions
