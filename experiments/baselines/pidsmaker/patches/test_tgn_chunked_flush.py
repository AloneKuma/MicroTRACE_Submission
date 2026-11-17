"""Check that tgn-chunked-flush.patch gives the same memory as the original
one-shot flush. Run inside mtpids-app after the patch is applied:

    docker exec -w /home/pids mtpids-app /opt/conda/envs/pids/bin/python \
        /home/pids/test_tgn_chunked_flush.py

120,000 nodes = 3 chunks of 50,000. Also checks that a naive chunked flush,
which writes each chunk before computing the next, does differ, so the test
can tell the two apart. Exits non-zero on failure.
"""

import copy
import sys

import torch

sys.path.insert(0, "/home/pids")
from pidsmaker.tgn import IdentityMessage, LastAggregator, TGNMemory  # noqa: E402

torch.manual_seed(0)
N, RAW, MEM, TIME, EDGES, BATCH = 120_000, 16, 8, 8, 60_000, 2_000

mem = TGNMemory(N, RAW, MEM, TIME, IdentityMessage(RAW, MEM, TIME), LastAggregator(), "cpu")
mem.train()
src_all = torch.randint(0, N, (EDGES,))
dst_all = torch.randint(0, N, (EDGES,))
t_all = torch.sort(torch.randint(0, 10_000, (EDGES,))).values
msg_all = torch.randn(EDGES, RAW)
with torch.no_grad():
    for i in range(0, EDGES, BATCH):
        sl = slice(i, i + BATCH)
        mem.update_state(src_all[sl], dst_all[sl], t_all[sl], msg_all[sl])

    one_shot, patched, naive = copy.deepcopy(mem), copy.deepcopy(mem), copy.deepcopy(mem)
    one_shot._update_memory(torch.arange(N))  # the original line
    patched.train(False)  # the patched flush
    for c in torch.arange(N).split(50_000):  # naive: write each chunk before the next
        naive._update_memory(c)

ok_mem = torch.allclose(one_shot.memory, patched.memory, atol=1e-6)
ok_t = torch.equal(one_shot.last_update, patched.last_update)
naive_differs = not torch.allclose(one_shot.memory, naive.memory, atol=1e-6)
print(
    f"patched == one-shot: memory {ok_mem} (max diff "
    f"{(one_shot.memory - patched.memory).abs().max().item():.2e}), last_update {ok_t}; "
    f"naive chunking differs: {naive_differs}"
)
sys.exit(0 if ok_mem and ok_t and naive_differs else 1)
