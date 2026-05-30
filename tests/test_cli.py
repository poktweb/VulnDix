import argparse
import importlib.util
from pathlib import Path

import pytest

from vulndix.portswigger import ALL_SCAN_CATEGORIES

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("vulndix_cli", _ROOT / "vulndix.py")
assert _spec and _spec.loader
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)


def _args(**kwargs: object) -> argparse.Namespace:
    defaults = {
        "url": "https://example.com/",
        "all": False,
        "portswigger": False,
        "categories": None,
        "max_depth": 3,
        "max_pages": 150,
        "ignore_robots": False,
        "insecure": False,
        "fuzz_headers": False,
        "max_payloads": 30,
        "delay_ms": 100,
        "threads": 5,
        "no_verify_curl": False,
        "payload_dir": None,
        "user_agent": "test",
        "login_url": None,
        "user": None,
        "password": None,
        "login_user_selector": None,
        "login_pass_selector": None,
        "login_submit_selector": None,
        "cookie": [],
        "header": [],
        "token": None,
        "wordlist": None,
        "fuzz_method": "GET",
        "match_codes": None,
        "no_fuzz_baseline_filter": False,
        "wordlist_max": 0,
        "no_discover_params": False,
        "spa_wait_ms": 2500,
        "stealth": False,
        "deep": False,
        "fuzz_tiers": False,
        "no_toolchain": False,
        "proxy": None,
        "jitter_ms": 0,
        "no_synthetic_probes": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_all_scan_has_21_categories():
    assert len(ALL_SCAN_CATEGORIES) == 21


def test_all_mode_enables_every_category():
    config = cli.build_config(_args(all=True))
    assert config.categories == ALL_SCAN_CATEGORIES
    assert config.fuzz_headers is True
    assert config.ignore_robots is True
    assert config.portswigger_mode is False


def test_portswigger_mode_includes_academy_flag():
    config = cli.build_config(_args(portswigger=True))
    assert config.categories == ALL_SCAN_CATEGORIES
    assert config.portswigger_mode is True


def test_all_conflicts_with_categories():
    with pytest.raises(ValueError, match="preset"):
        cli.build_config(_args(all=True, categories="sqli"))


def test_apply_presets_raises_max_payloads():
    args = _args(all=True)
    cli.apply_scan_presets(args)
    assert args.max_payloads == 8
    assert args.threads == 30
    assert args.delay_ms == 0


def test_stealth_preset():
    args = _args(stealth=True)
    cli.apply_scan_presets(args)
    config = cli.build_config(args)
    assert config.stealth_mode is True
    assert config.fuzz_tier_mode is True
    assert config.fuzz_headers is False
    assert config.ignore_robots is False
    assert config.threads <= 5
    assert config.delay_ms >= 250
    assert "VulnDix" not in config.user_agent


def test_stealth_conflicts_with_all():
    with pytest.raises(ValueError, match="preset"):
        cli.build_config(_args(stealth=True, all=True))
