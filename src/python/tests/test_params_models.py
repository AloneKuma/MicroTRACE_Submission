"""Model paths in a parameter file: relative ones are read from the file's folder."""
import os

import yaml

from mtcore.agents.params import Params


def _write(tmp_path, models):
    data = {"parameter_set_version": "T", "ml": {"enabled": True, "models": models}}
    p = tmp_path / "set.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)


def test_relative_model_path_resolves_against_the_parameter_file(tmp_path):
    absolute = os.path.abspath(os.path.join(str(tmp_path), "elsewhere", "IF_H.json"))
    p = Params.load(_write(tmp_path, {"B": "models/IF_B.json", "H": absolute}))
    assert p.models["B"] == os.path.normpath(os.path.join(str(tmp_path), "models", "IF_B.json"))
    assert p.models["H"] == absolute
    assert p.with_overrides(ml={"enabled": True}).models == p.models   # copies keep the file's folder


def test_dict_params_keep_paths_as_given():
    p = Params({"parameter_set_version": "T", "ml": {"models": {"B": "models/IF_B.json"}}})
    assert p.models["B"] == "models/IF_B.json"
