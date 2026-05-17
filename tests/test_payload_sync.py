from pathlib import Path

from vulndix.payload_updater import (
    MIN_PAYLOADS_READY,
    categories_missing_payloads,
    count_category_payloads,
    payload_sync_categories,
    payloads_need_download,
)


def test_payloads_need_download_missing(tmp_path: Path):
    assert payloads_need_download(tmp_path, frozenset({"xss"})) is True


def test_payloads_need_download_enough(tmp_path: Path):
    lines = "\n".join(f"p{i}" for i in range(MIN_PAYLOADS_READY))
    (tmp_path / "xss.txt").write_text(lines, encoding="utf-8")
    assert payloads_need_download(tmp_path, frozenset({"xss"})) is False


def test_count_payloads(tmp_path: Path):
    (tmp_path / "sqli.txt").write_text("# c\n' OR 1=1\n", encoding="utf-8")
    assert count_category_payloads(tmp_path, "sqli") == 1


def test_missing_new_category_while_sqli_full(tmp_path: Path):
    lines = "\n".join(f"p{i}" for i in range(MIN_PAYLOADS_READY))
    (tmp_path / "sqli.txt").write_text(lines, encoding="utf-8")
    (tmp_path / "nosql.txt").write_text("seed\n", encoding="utf-8")
    cats = frozenset({"sqli", "nosql"})
    assert payloads_need_download(tmp_path, cats) is True
    assert categories_missing_payloads(tmp_path, cats) == frozenset({"nosql"})


def test_passive_categories_ignored(tmp_path: Path):
    cats = frozenset({"sqli", "idor", "cors"})
    assert payload_sync_categories(cats) == frozenset({"sqli"})
    assert payloads_need_download(tmp_path, cats) is True
