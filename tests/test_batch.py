"""Tests for candidate collection and the batch runner."""

import os

import pytest

from modules.batch import BATCH_ASSET_EXTENSIONS, collect_candidates, run_batch_analysis


def _make_tree(root):
    (root / "a.txt").write_text("alpha")
    (root / "b.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("ignored")
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / "node_modules" / "pkg" / "index.js").write_text("ignored")
    (root / "sub").mkdir()
    (root / "sub" / "c.bin").write_bytes(b"MZ" + b"\x00" * 64)
    return root


def test_collect_candidates_filters_assets_and_ignored_dirs(tmp_path):
    tree = _make_tree(tmp_path)
    candidates, skipped = collect_candidates(str(tree))
    names = [os.path.basename(path) for path in candidates]
    assert names == ["a.txt", "c.bin"]
    assert len(skipped) == 1 and skipped[0]["file"] == "b.png"
    assert ".git" not in " ".join(candidates) and "node_modules" not in " ".join(candidates)


def test_collect_candidates_asset_extensions_constant_is_complete():
    for extension in (".png", ".jpg", ".mp4", ".ttf"):
        assert extension in BATCH_ASSET_EXTENSIONS


def test_collect_candidates_skips_reparse_point_directories(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    real_dir = target / "real_dir"
    real_dir.mkdir()
    (real_dir / "inside.txt").write_text("inside")
    junction = target / "junction_dir"
    junction.mkdir()
    (junction / "leak.txt").write_text("outside")
    real_join = os.path.join

    def fake_walk(top):
        names = ["junction_dir", "real_dir"]
        yield (str(target), names, [])
        for name in list(names):  # pruned in place by collect_candidates
            if name == "real_dir":
                yield (str(real_dir), [], ["inside.txt"])
            elif name == "junction_dir":
                yield (str(junction), [], ["leak.txt"])

    monkeypatch.setattr("modules.batch.os.walk", fake_walk)
    monkeypatch.setattr(
        "modules.batch.os.path.islink",
        lambda path: path == real_join(str(target), "junction_dir"),
    )
    candidates, _ = collect_candidates(str(target), skip_reparse_points=True)
    assert [os.path.basename(path) for path in candidates] == ["inside.txt"]

    candidates, _ = collect_candidates(str(target), skip_reparse_points=False)
    assert sorted(os.path.basename(path) for path in candidates) == ["inside.txt", "leak.txt"]


def test_collect_candidates_skips_symlinked_files(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "real.txt").write_text("ok")
    linked = target / "link.txt"
    linked.write_text("linked elsewhere")
    real_join = os.path.join
    monkeypatch.setattr(
        "modules.batch.os.path.islink",
        lambda path: path == real_join(str(target), "link.txt"),
    )
    candidates, _ = collect_candidates(str(target), skip_reparse_points=True)
    assert [os.path.basename(path) for path in candidates] == ["real.txt"]
    candidates, _ = collect_candidates(str(target), skip_reparse_points=False)
    assert sorted(os.path.basename(path) for path in candidates) == ["link.txt", "real.txt"]


def _batch_config(output_dir):
    return {
        "blacklist": True, "virustotal": False, "strings": True, "ioc_extract": False,
        "entropy": True, "magic_numbers": True, "pe_analysis": False,
        "gerar_report": True, "report_format": "json", "output_dir": output_dir,
        "quiet": True, "workers": 2, "cache_enabled": False, "max_file_size": 0,
        "skip_reparse_points": True,
    }


@pytest.mark.integration
def test_run_batch_analysis(tmp_path):
    tree = _make_tree(tmp_path)
    config = _batch_config(str(tmp_path / "reports"))
    results, skipped, duration = run_batch_analysis(str(tree), config)
    assert sorted(result["file"] for result in results) == ["a.txt", "c.bin"]
    assert all(result["success"] for result in results)
    assert skipped[0]["file"] == "b.png"
    assert duration >= 0
    reports_dir = tmp_path / "reports"
    assert reports_dir.is_dir()
    assert any(name.startswith("report_a.txt_") or name.startswith("report_c.bin_") or name.endswith(".json")
               for name in os.listdir(reports_dir))


def test_run_batch_analysis_empty_folder(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    results, skipped, duration = run_batch_analysis(str(empty), _batch_config(str(tmp_path / "r")))
    assert results == []
    assert skipped == []
    assert duration == 0.0


def test_clean_worker_config_strips_runtime_keys():
    from modules.batch import _clean_worker_config
    config = {"blacklist": True, "_cache": object(), "event_callback": lambda x: x, "workers": 1}
    cleaned = _clean_worker_config(config)
    assert "_cache" not in cleaned and "event_callback" not in cleaned
    assert cleaned["blacklist"] is True and cleaned["workers"] == 1