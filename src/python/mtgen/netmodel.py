"""Server-side connection timing (exp2-conflict-origin-cases-plan G1, G2).

Under the generator flag ebpf_accept, every in-cluster connect to a Pod is
accepted on the server after an accept delay. A scenario that reconnects
from a fixed source port waits a reconnect delay drawn from the same
distribution (catalogue ``gap_s: accept_delay``), so the time between a
connect and an accept does not tell an accept of the connect from an accept
of a later socket on the same tuple (plan 3.1, gap matching).
"""
import math

# Accept delay: mostly fast (the SYN waits in the accept queue for
# milliseconds), sometimes a backlogged server (up to seconds). Log-uniform
# within each range.
ACCEPT_DELAY_FAST_S = (0.0002, 0.02)
ACCEPT_DELAY_BACKLOG_S = (0.02, 3.0)
BACKLOG_SHARE = 0.1

# A fixed-port reconnect: the probe's exchange and close (request, response,
# FIN; log-uniform), then the new connect, which waits an accept delay too.
# The exchange keeps a reconnect well clear of the clock uncertainty (1-2 ms),
# within which the correlator cannot order it before the accept it follows.
EXCHANGE_S = (0.005, 0.05)

# Symbolic gaps a catalogue step or link may name instead of [lo, hi] seconds.
ACCEPT_DELAY = "accept_delay"
RECONNECT_DELAY = "reconnect_delay"


def accept_delay_ns(rng) -> int:
    """One accept (or reconnect) delay in ns, from rng."""
    lo, hi = ACCEPT_DELAY_BACKLOG_S if float(rng.random()) < BACKLOG_SHARE else ACCEPT_DELAY_FAST_S
    s = math.exp(math.log(lo) + (math.log(hi) - math.log(lo)) * float(rng.random()))
    return max(1, int(s * 1e9))


def reconnect_delay_ns(rng) -> int:
    """One fixed-port reconnect delay in ns (after the previous accept)."""
    lo, hi = EXCHANGE_S
    s = math.exp(math.log(lo) + (math.log(hi) - math.log(lo)) * float(rng.random()))
    return int(s * 1e9) + accept_delay_ns(rng)


def gap_ns(spec, rng) -> int:
    """A catalogue gap: ``[lo, hi]`` seconds (uniform), or a sum of delay
    terms joined by ``+``, each ``accept_delay`` or ``reconnect_delay`` with
    an optional ``*K`` (K draws), e.g. ``reconnect_delay*2+accept_delay*3``:
    the span of a reconnect chain, so a link can mirror another's gap."""
    if isinstance(spec, str):
        total = 0
        for term in spec.split("+"):
            name, _, k = term.strip().partition("*")
            draw = {ACCEPT_DELAY: accept_delay_ns, RECONNECT_DELAY: reconnect_delay_ns}.get(name)
            if draw is None or (k and (not k.isdigit() or int(k) < 1)):
                raise ValueError(f"gap {spec!r}: unknown term {term!r}")
            total += sum(draw(rng) for _ in range(int(k or 1)))
        return total
    lo, hi = (float(v) * 1e9 for v in spec)
    return int(lo + (hi - lo) * float(rng.random()))
