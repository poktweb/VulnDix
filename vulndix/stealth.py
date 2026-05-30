"""Perfil stealth: UA rotativo, jitter, rate limit global e backoff adaptativo."""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field

# User-Agents de browsers reais (sem fingerprint VulnDix)
USER_AGENT_POOL: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
)

BLOCK_STATUSES = frozenset({403, 429, 503})


def pick_user_agent() -> str:
    return random.choice(USER_AGENT_POOL)


def jitter_delay(base_ms: int, *, spread: float = 0.35) -> float:
    """Segundos de espera com jitter em torno de base_ms."""
    if base_ms <= 0:
        return 0.0
    factor = 1.0 + random.uniform(-spread, spread)
    return max(0.0, (base_ms * factor) / 1000.0)


@dataclass
class StealthController:
    """Rate limiter global + backoff ao detectar bloqueio WAF."""

    base_delay_ms: int = 300
    min_interval_s: float = 0.0
    block_window_s: float = 60.0
    block_threshold: int = 5
    max_delay_ms: int = 8000
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _last_request: float = field(default=0.0, repr=False)
    _delay_ms: int = field(default=300, repr=False)
    _block_times: list[float] = field(default_factory=list, repr=False)
    _paused_until: float = field(default=0.0, repr=False)
    _effective_threads: int = field(default=3, repr=False)

    def __post_init__(self) -> None:
        self._delay_ms = self.base_delay_ms
        if self.min_interval_s <= 0 and self.base_delay_ms > 0:
            self.min_interval_s = self.base_delay_ms / 1000.0

    def wait_before_request(self) -> None:
        with self._lock:
            now = time.monotonic()
            if self._paused_until > now:
                time.sleep(self._paused_until - now)
                now = time.monotonic()
            gap = self.min_interval_s + jitter_delay(self._delay_ms)
            elapsed = now - self._last_request
            if elapsed < gap:
                time.sleep(gap - elapsed)
            self._last_request = time.monotonic()

    def record_response(self, status: int) -> None:
        if status not in BLOCK_STATUSES:
            return
        now = time.monotonic()
        with self._lock:
            self._block_times = [t for t in self._block_times if now - t < self.block_window_s]
            self._block_times.append(now)
            if len(self._block_times) >= self.block_threshold:
                self._delay_ms = min(self.max_delay_ms, self._delay_ms * 2)
                self.min_interval_s = max(self.min_interval_s, self._delay_ms / 1000.0)
                self._effective_threads = max(1, self._effective_threads - 1)
                self._paused_until = now + min(30.0, self._delay_ms / 100.0)
                self._block_times.clear()

    @property
    def effective_threads(self) -> int:
        with self._lock:
            return self._effective_threads

    def apply_thread_cap(self, requested: int) -> int:
        return max(1, min(requested, self.effective_threads))


def apply_stealth_defaults_to_args(args: object) -> None:
    """Preset --stealth: baixo ruído para alvos reais."""
    if getattr(args, "max_payloads", 30) == 30:
        args.max_payloads = 5
    if getattr(args, "delay_ms", 100) == 100:
        args.delay_ms = 350
    if getattr(args, "threads", 5) == 5:
        args.threads = 3
    if getattr(args, "max_pages", 150) == 150:
        args.max_pages = 50
    if getattr(args, "spa_wait_ms", 2500) == 2500:
        args.spa_wait_ms = 1200
    if not getattr(args, "user_agent", None) or "VulnDix" in getattr(args, "user_agent", ""):
        args.user_agent = pick_user_agent()
