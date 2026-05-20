from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Location = Literal["query", "body", "header", "json", "path", "xml"]
Confidence = Literal["low", "medium", "high"]
VulnType = Literal[
    "xss",
    "sqli",
    "lfi",
    "ssti",
    "cmdi",
    "redirect",
    "traversal",
    "nosql",
    "ssrf",
    "xxe",
    "host_header",
    "cors",
    "idor",
    "info",
    "clickjacking",
    "csrf",
]


@dataclass
class InjectionPoint:
    url: str
    method: str
    location: Location
    name: str
    baseline_value: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | str | None = None
    url_template: str = ""

    def key(self) -> tuple[str, str, str, str]:
        return (self.method.upper(), self.url_template or self.url, self.name, self.location)


@dataclass
class PageSample:
    url: str
    status: int
    headers: dict[str, str]
    body: str


@dataclass
class BaselineResponse:
    status: int
    body_len: int
    body_hash: str
    elapsed_ms: float
    body_snippet: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ProbeResponse:
    status: int
    body: str
    elapsed_ms: float
    headers: dict[str, str] = field(default_factory=dict)
    content_length: int = 0

    @property
    def body_len(self) -> int:
        return self.content_length if self.content_length > 0 else len(self.body)


@dataclass
class Finding:
    type: VulnType
    endpoint: str
    param: str
    location: Location
    payload: str
    confidence: Confidence
    evidence: str
    curl: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "endpoint": self.endpoint,
            "param": self.param,
            "location": self.location,
            "payload": self.payload,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "curl": self.curl,
        }


@dataclass
class ScanConfig:
    url: str
    max_depth: int = 3
    max_pages: int = 150
    ignore_robots: bool = False
    verify_tls: bool = True
    fuzz_headers: bool = False
    portswigger_mode: bool = False
    fast_fuzz: bool = False
    probe_timeout_s: float = 12.0
    probe_max_body_bytes: int = 98304
    fuzz_category_cap: int = 0
    categories: frozenset[VulnType] = field(
        default_factory=lambda: frozenset(
            {
                "xss",
                "sqli",
                "lfi",
                "ssti",
                "cmdi",
                "redirect",
                "traversal",
            }
        )
    )
    max_payloads: int = 30
    delay_ms: int = 100
    threads: int = 5
    verify_curl: bool = True
    payload_dir: str | None = None
    user_agent: str = (
        "Mozilla/5.0 (compatible; VulnDix/1.0; +https://example.local)"
    )
    login_url: str | None = None
    username: str | None = None
    password: str | None = None
    login_user_selector: str | None = None
    login_pass_selector: str | None = None
    login_submit_selector: str | None = None
    cookies: list[str] = field(default_factory=list)
    extra_headers: dict[str, str] = field(default_factory=dict)
    token: str | None = None
    xss_marker: str = ""
    wordlist_path: str | None = None
    wordlist_method: str = "GET"
    fuzz_match_codes: frozenset[int] | None = None
    fuzz_filter_baseline: bool = True
    wordlist_max_lines: int = 0
    discover_params: bool = True
    spa_wait_ms: int = 2500
