from unittest.mock import MagicMock, patch

from vulndix.models import ScanConfig
from vulndix.pipeline import run_scan_pipeline


def test_pipeline_stealth_calls_crawl():
    config = ScanConfig(
        url="https://example.com/",
        stealth_mode=True,
        use_toolchain=False,
        categories=frozenset({"xss"}),
        max_pages=1,
        max_depth=0,
    )
    with patch("vulndix.pipeline.crawl") as mock_crawl:
        mock_crawl.return_value = ([], [], 0, [])
        with patch("vulndix.pipeline.fuzz_points") as mock_fuzz:
            mock_fuzz.return_value = []
            run_scan_pipeline(config)
            mock_crawl.assert_called_once()
            mock_fuzz.assert_called_once()
