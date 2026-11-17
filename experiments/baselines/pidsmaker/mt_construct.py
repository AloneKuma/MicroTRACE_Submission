"""Graph construction only, for the seeded ORTHRUS row: no training, no model."""
import time
from pidsmaker.config import get_runtime_required_args, get_yml_cfg
from pidsmaker.tasks import construction
args = get_runtime_required_args()
cfg = get_yml_cfg(args)
t0 = time.time()
construction.main(cfg)
print("GRAPHS_DIR", cfg.construction._graphs_dir, "seconds", round(time.time() - t0, 1), "window", cfg.construction.time_window_size)
