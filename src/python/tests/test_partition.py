"""murmur2 must match Kafka's Java implementation exactly (KAFKA-KEY-PARTITION)."""
from mtcore.partition import as_signed, murmur2, partition_for

# Expected values from Kafka's UtilsTest.testMurmur2 (Java signed ints).
KAFKA_VECTORS = {
    b"21": -973932308,
    b"foobar": -790332482,
    b"a-little-bit-long-string": -985981536,
    b"a-little-bit-longer-string": -1486304829,
    b"lkjh234lh9fiuh90y23oiuhsafujhadof229phr9h19h89h8": -58897971,
    bytes([ord("a"), ord("b"), ord("c")]): 479470107,
}


def test_murmur2_matches_kafka_vectors():
    for data, want in KAFKA_VECTORS.items():
        assert as_signed(murmur2(data)) == want, data


def test_partition_is_in_range_and_stable():
    for n in (1, 3, 7, 12):
        for data in KAFKA_VECTORS:
            p = partition_for(data, n)
            assert 0 <= p < n
            assert p == partition_for(data, n)
