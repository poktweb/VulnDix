import pytest

from vulndix.wordlist_fuzz import build_fuzz_url, load_wordlist, parse_fuzz_target


def test_parse_directory_target():
    t = parse_fuzz_target("https://example.com/FUZZ")
    assert t.mode == "directory"
    assert build_fuzz_url(t, "admin") == "https://example.com/admin"


def test_parse_directory_trailing_slash():
    t = parse_fuzz_target("https://example.com/FUZZ/")
    assert build_fuzz_url(t, "api") == "https://example.com/api/"


def test_parse_subdomain_target():
    t = parse_fuzz_target("https://FUZZ.example.com/")
    assert t.mode == "subdomain"
    assert build_fuzz_url(t, "api") == "https://api.example.com/"


def test_fuzz_dot_url_shorthand():
    t = parse_fuzz_target("FUZZ.example.org")
    assert t.mode == "subdomain"
    assert build_fuzz_url(t, "dev") == "https://dev.example.org/"


def test_load_wordlist_skips_comments(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("# c\nadmin\n\napi\n", encoding="utf-8")
    assert load_wordlist(wl) == ["admin", "api"]


def test_parse_match_codes():
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("vulndix_cli", root / "vulndix.py")
    assert spec and spec.loader
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    codes = cli.parse_match_codes("200,301,403")
    assert codes == frozenset({200, 301, 403})


def test_missing_fuzz_raises():
    with pytest.raises(ValueError, match="FUZZ"):
        parse_fuzz_target("https://example.com/")
