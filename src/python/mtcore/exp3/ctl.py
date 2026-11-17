"""Control store shared by the analysis host and the sender nodes: a folder, or an S3 prefix.

The analysis host posts jobs/<job>/{certs/, plans/, job.json} (job.json last) and waits for
done/<job>.json; a sender posts done/<job>.json after its fault logs are uploaded to the
fault-log store (a separate prefix, read only by the scoring step). stop.json ends the senders.
"""
import json
import os
import shutil
import subprocess
import tempfile


class LocalCtl:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)

    def _p(self, key):
        return os.path.join(self.root, *key.split("/"))

    def put_json(self, key, obj):
        p = self._p(key)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(obj, fh, sort_keys=True)
        os.replace(p + ".tmp", p)

    def get_json(self, key):
        try:
            with open(self._p(key), encoding="utf-8") as fh:
                return json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def put_tree(self, key, src):
        dst = self._p(key)
        if os.path.exists(dst):
            shutil.rmtree(dst)
        shutil.copytree(src, dst)

    def get_tree(self, key, dst):
        if os.path.exists(dst):
            shutil.rmtree(dst)
        shutil.copytree(self._p(key), dst)

    def list_jobs(self):
        d = self._p("jobs")
        return sorted(j for j in os.listdir(d) if os.path.exists(os.path.join(d, j, "job.json"))) \
            if os.path.isdir(d) else []


class S3Ctl:
    """The same over `aws s3` (the session machines' instance role; no keys on disk)."""

    def __init__(self, url):
        self.url = url.rstrip("/")

    def _aws(self, *args, check=True):
        r = subprocess.run(["aws", "s3", *args, "--only-show-errors"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL)
        if check and r.returncode != 0:
            raise RuntimeError(f"aws s3 {' '.join(args)}: {r.stderr.strip()}")
        return r

    def put_json(self, key, obj):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump(obj, fh, sort_keys=True)
        try:
            self._aws("cp", fh.name, f"{self.url}/{key}")
        finally:
            os.unlink(fh.name)

    def get_json(self, key):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.json")
            if self._aws("cp", f"{self.url}/{key}", p, check=False).returncode != 0 or not os.path.exists(p):
                return None
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)

    def put_tree(self, key, src):
        self._aws("sync", "--no-follow-symlinks", src, f"{self.url}/{key}")

    def get_tree(self, key, dst):
        if os.path.exists(dst):
            shutil.rmtree(dst)
        os.makedirs(dst)
        self._aws("sync", f"{self.url}/{key}", dst)

    def list_jobs(self):
        r = subprocess.run(["aws", "s3", "ls", f"{self.url}/jobs/"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL)
        names = [ln.split()[-1].rstrip("/") for ln in r.stdout.splitlines() if ln.strip().startswith("PRE ")]
        return sorted(names)


def make_ctl(spec):
    if spec is None:
        return None
    return S3Ctl(spec) if spec.startswith("s3://") else LocalCtl(spec)
