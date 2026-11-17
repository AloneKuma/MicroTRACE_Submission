"""Simulated-time helpers: nanosecond integers, protobuf Timestamp, RFC 3339."""
from datetime import datetime, timezone
from google.protobuf.timestamp_pb2 import Timestamp


def ns_to_timestamp(ns: int) -> Timestamp:
    """Convert nanoseconds since epoch to google.protobuf.Timestamp.

    Args:
        ns: nanoseconds since Unix epoch (1970-01-01 00:00:00 UTC)

    Returns:
        Timestamp message
    """
    sec = ns // 1_000_000_000
    nsec = ns % 1_000_000_000
    return Timestamp(seconds=sec, nanos=nsec)


def timestamp_to_ns(ts: Timestamp) -> int:
    """Convert google.protobuf.Timestamp to nanoseconds since epoch.

    Args:
        ts: Timestamp message

    Returns:
        nanoseconds since Unix epoch
    """
    return ts.seconds * 1_000_000_000 + ts.nanos


def ns_to_rfc3339(ns: int) -> str:
    """Convert nanoseconds since epoch to RFC 3339 string.

    Args:
        ns: nanoseconds since Unix epoch

    Returns:
        RFC 3339 formatted timestamp (e.g., "2024-01-01T12:34:56Z")
    """
    ts = ns_to_timestamp(ns)
    dt = datetime.fromtimestamp(ts.seconds, tz=timezone.utc)
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def rfc3339_to_ns(rfc3339: str) -> int:
    """Convert RFC 3339 string to nanoseconds since epoch.

    Args:
        rfc3339: RFC 3339 formatted timestamp

    Returns:
        nanoseconds since Unix epoch
    """
    # Handle both Z and +00:00 endings
    if rfc3339.endswith("Z"):
        rfc3339 = rfc3339[:-1] + "+00:00"
    dt = datetime.fromisoformat(rfc3339)
    ts = int(dt.timestamp() * 1_000_000_000)
    return ts
