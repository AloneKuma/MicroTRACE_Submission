"""Comparing a crash run with the reference: identical runs, a lost link, a
moved member, a sealed exclusion turned into an amendment (band 2), the
A/A' noise floor, unscored path differences, k of N bounds, and the CLI."""
import json

import pytest

from test_harness_project import IN, WI, inc, jsonl, proj, run_a, wit
from mtcore.harness import compare as C


def replace(items, i, item):
    out = list(items)
    out[i] = item
    return out


def test_identical_runs():
    r = C.compare(proj(run_a()), proj(run_a() + run_a()[3:]), proj(run_a()))
    assert r["verdict"] == "identical" and r["view"] == "sealed" and not r["reference_amended"]
    assert all(v == {"missing": [], "extra": [], "noise": {"missing": [], "extra": []}} for v in r["fields"].values())


def test_a_lost_link_is_a_difference():
    x = replace(run_a(), 1, (WI, wit("w2", "UNPROVEN")))
    x = replace(x, 5, (IN, inc("i1", ["f1", "f2", "f3"], links=["w1"], paths=[("f1", "f2", "f3")])))
    r = C.compare(proj(run_a()), proj(x), proj(run_a()))
    assert r["verdict"] == "different"
    assert r["fields"]["confirmed_witness_ids"]["missing"] == ["w2"]
    assert r["fields"]["links"]["missing"] == ["i1|w2"]
    assert r["fields"]["groups"] == {"missing": [], "extra": [], "noise": {"missing": [], "extra": []}}


def test_a_changed_membership_is_a_difference():
    x = replace(run_a(), 5, (IN, inc("i1", ["f1", "f2"], links=["w1", "w2"], paths=[("f1", "f2", "f3")])))
    x = replace(x, 6, (IN, inc("i2", ["f7", "f8", "f3"], start=500)))
    r = C.compare(proj(run_a()), proj(x))
    f = r["fields"]
    assert r["verdict"] == "different" and not r["noise_floor"]
    assert f["groups"]["missing"] == ["i1|member|f3"] and f["groups"]["extra"] == ["i2|member|f3"]
    assert f["finding_ids"]["missing"] == []


def outage_run():
    """i1 sealed without f3 while EBPF was excluded, then amended with it."""
    x = replace(run_a(), 5, (IN, inc("i1", ["f1", "f2"], links=["w1"], at_seal=["EBPF"], current=["EBPF"])))
    return x + [(IN, inc("i1", ["f1", "f2", "f3"], "INCIDENT_AMENDED", version=2, links=["w1", "w2"],
                         at_seal=["EBPF"], current=["EBPF"], paths=[("f1", "f2", "f3")]))]


def test_sealed_exclusion_moved_to_an_amendment_passes_band_2_only():
    a, x = proj(run_a()), proj(outage_run())
    b1 = C.compare(a, x, proj(run_a()), band=1)
    assert b1["verdict"] == "different"
    assert b1["fields"]["at_seal_excluded_sources"]["extra"] == ["i1|EBPF"]
    b2 = C.compare(a, x, proj(run_a()), band=2)
    assert b2["verdict"] == "identical" and b2["view"] == "latest" and b2["exclusion_recorded"]
    assert b2["exclusions"]["at_seal_excluded_sources"]["extra"] == ["i1|EBPF"]
    assert b2["exclusions"]["current_excluded_sources"]["extra"] == ["i1|EBPF"]
    assert "at_seal_excluded_sources" not in b2["fields"]


def test_band_2_needs_the_exclusion_recorded():
    r = C.compare(proj(run_a()), proj(run_a()), band=2)
    assert r["verdict"] == "different" and not r["exclusion_recorded"]


def test_band_2_fails_when_the_amendment_never_comes():
    x = replace(run_a(), 5, (IN, inc("i1", ["f1", "f2"], links=["w1", "w2"], at_seal=["EBPF"], current=["EBPF"])))
    r = C.compare(proj(run_a()), proj(x), band=2)
    assert r["verdict"] == "different" and r["fields"]["groups"]["missing"] == ["i1|member|f3"]


def test_band_3_is_scored_separately():
    r = C.compare(proj(run_a()), proj(outage_run()), band=3)
    assert r["verdict"] == "separate"


def test_differences_also_between_a_and_a_prime_are_noise():
    a2 = run_a() + [(WI, wit("w9"))]                          # A' confirmed one more
    x = run_a() + [(WI, wit("w9")), (WI, wit("w8"))]          # X too, and one A' did not
    r = C.compare(proj(run_a()), proj(x), proj(a2))
    w = r["fields"]["confirmed_witness_ids"]
    assert w["extra"] == ["w8"] and w["noise"]["extra"] == ["w9"] and r["verdict"] == "different"
    x2 = run_a() + [(WI, wit("w9"))]
    assert C.compare(proj(run_a()), proj(x2), proj(a2))["verdict"] == "identical"
    assert C.compare(proj(run_a()), proj(x2))["verdict"] == "different"


def test_paths_and_times_differ_but_the_verdict_does_not():
    x = replace(run_a(), 5, (IN, inc("i1", ["f1", "f2", "f3"], links=["w1", "w2"], paths=[("f1", "f3")], start=101)))
    r = C.compare(proj(run_a()), proj(x[:4] + x[5:]), proj(run_a()))
    assert r["verdict"] == "identical"
    assert r["report"]["paths"] == {"missing": ["i1|ranked|p-f1-f2-f3"], "extra": ["i1|ranked|p-f1-f3"]}
    assert r["report"]["timestamps"]["i1"]["event_start"] == [100 * 10**9, 101 * 10**9]
    assert r["report"]["open_records"] == {"reference": 2, "run": 1}


def test_tgs_hashes_are_compared():
    r = C.compare(proj(run_a(), {"integrity": "a"}), proj(run_a(), {"integrity": "b"}))
    assert r["fields"]["tgs"] == {"missing": ["integrity=a"], "extra": ["integrity=b"],
                                  "noise": {"missing": [], "extra": []}}


def test_reference_amended_is_flagged():
    a = run_a() + [(IN, inc("i2", ["f7", "f8", "f9"], "INCIDENT_AMENDED", version=2, start=500))]
    r = C.compare(proj(a), proj(a), band=2)
    assert r["reference_amended"]


def test_band_for():
    assert C.band_for(5, 10, 300) == 1
    assert C.band_for(10, 10, 300) == 2
    assert C.band_for(301, 10, 300) == 3
    assert C.band_for(900, 10, 300, component="go") == 1


def test_k_of_n_bounds():
    assert C.k_of_n(30, 30)["failure_rate_upper"] == pytest.approx(1 - 0.05 ** (1 / 30), rel=1e-9)
    assert C.k_of_n(30, 30)["failure_rate_upper"] == pytest.approx(3 / 30, rel=0.05)
    # Clopper-Pearson upper bound for 1 failure in 10 at 95 % one-sided: 0.3942
    assert C.k_of_n(9, 10)["failure_rate_upper"] == pytest.approx(0.39416, abs=1e-4)
    assert C.k_of_n(0, 5)["failure_rate_upper"] == 1.0
    assert C.tally([{"verdict": "identical"}] * 4 + [{"verdict": "separate"}]) == {
        **C.k_of_n(4, 4), "separate": 1}


def test_cli_diff_and_tally(tmp_path, capsys):
    for name, items in (("a", run_a()), ("a2", run_a()), ("x", outage_run())):
        (tmp_path / f"{name}.jsonl").write_text(jsonl(items), encoding="utf-8")
    args = ["diff", "--reference", str(tmp_path / "a.jsonl"), "--run", str(tmp_path / "x.jsonl"),
            "--noise", str(tmp_path / "a2.jsonl")]
    assert C.main(args) == 1
    one = capsys.readouterr().out
    assert C.main(args + ["--band", "2"]) == 0
    two = capsys.readouterr().out
    (tmp_path / "r1.json").write_text(one)
    (tmp_path / "r2.json").write_text(two)
    assert C.main(["tally", str(tmp_path / "r1.json"), str(tmp_path / "r2.json")]) == 0
    t = json.loads(capsys.readouterr().out)
    assert t["identical"] == 1 and t["runs"] == 2
