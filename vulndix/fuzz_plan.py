"""Planejamento de fuzz: menos probes irrelevantes por ponto/categoria."""
from __future__ import annotations

from vulndix.models import BaselineResponse, InjectionPoint, ProbeResponse, ScanConfig, VulnType
from vulndix.portswigger import PRIORITY_PAYLOADS

PASSIVE_TYPES = frozenset(
    {
        "info",
        "clickjacking",
        "csrf",
        "cors",
        "idor",
        "sec_headers",
        "cookie_sec",
        "api_exposed",
    }
)

FAST_HEADER_NAMES = frozenset(
    {"Host", "User-Agent", "X-Original-URL", "X-Rewrite-URL", "Referer"}
)

# Ordem: payloads de alto sinal primeiro; cap em fast_fuzz corta o fim da lista
CATEGORY_PRIORITY: tuple[VulnType, ...] = (
    "sqli",
    "xss",
    "redirect",
    "lfi",
    "ssrf",
    "ssti",
    "cmdi",
    "nosql",
    "crlf",
    "ldap",
    "traversal",
    "xxe",
    "host_header",
)

URL_LIKE_PARAMS = frozenset(
    {
        "url",
        "uri",
        "redirect",
        "return",
        "next",
        "dest",
        "destination",
        "redir",
        "target",
        "link",
        "href",
        "path",
        "file",
        "page",
        "load",
        "fetch",
        "view",
        "dir",
        "folder",
        "document",
        "callback",
        "continue",
        "goto",
        "out",
        "forward",
    }
)

FILE_LIKE_PARAMS = frozenset(
    {
        "file",
        "filename",
        "path",
        "page",
        "template",
        "include",
        "doc",
        "document",
        "folder",
        "dir",
        "load",
        "view",
    }
)

ID_LIKE_SUFFIXES = ("id", "uid", "uuid", "ref", "num", "no")

# Parâmetros genéricos: só falhas mais prováveis (evita cmdi/traversal em tudo)
GENERIC_PARAM_CATS = frozenset({"xss", "sqli", "ssti"})


def _is_url_like_param(name: str) -> bool:
    low = name.lower()
    if low in URL_LIKE_PARAMS:
        return True
    return any(low.endswith(s) for s in ("url", "uri", "link", "path"))


def _is_id_like_param(name: str) -> bool:
    low = name.lower()
    if low in ("id", "userid", "account", "postid", "productid", "cat", "category"):
        return True
    return any(low.endswith(s) for s in ID_LIKE_SUFFIXES)


def _is_generic_param(name: str) -> bool:
    low = name.lower()
    if _is_id_like_param(name) or _is_url_like_param(name):
        return False
    if low in FILE_LIKE_PARAMS or low in ("q", "query", "search", "s", "term", "keyword", "name", "email"):
        return True
    return low not in ("password", "pass", "pwd", "token", "csrf")


def dedupe_injection_points(points: list[InjectionPoint]) -> list[InjectionPoint]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[InjectionPoint] = []
    for p in points:
        k = p.key()
        if k in seen:
            continue
        seen.add(k)
        out.append(p)
    return out


def prioritize_points(points: list[InjectionPoint]) -> list[InjectionPoint]:
    """Query/body antes de headers (mais chance de achado, menos ruído)."""

    def rank(p: InjectionPoint) -> tuple[int, str]:
        loc_score = {
            "query": 0,
            "body": 1,
            "json": 2,
            "path": 3,
            "xml": 4,
            "header": 5,
        }.get(p.location, 9)
        return (loc_score, p.name)

    return sorted(points, key=rank)


def filter_points_for_fast_fuzz(points: list[InjectionPoint]) -> list[InjectionPoint]:
    """Reduz pontos de header repetidos (só Host + User-Agent)."""
    out: list[InjectionPoint] = []
    for p in points:
        if p.location == "header" and p.name not in FAST_HEADER_NAMES:
            continue
        out.append(p)
    return out


def _order_categories(allowed: set[VulnType], cap: int) -> tuple[VulnType, ...]:
    ordered = [c for c in CATEGORY_PRIORITY if c in allowed]
    if cap > 0 and len(ordered) > cap:
        ordered = ordered[:cap]
    return tuple(ordered)


def categories_for_point(
    point: InjectionPoint,
    enabled: frozenset[VulnType],
    *,
    category_cap: int = 0,
) -> tuple[VulnType, ...]:
    active = enabled - PASSIVE_TYPES
    loc = point.location
    name = point.name.lower()

    if loc == "header":
        if name == "host":
            allowed = {"host_header", "xss", "sqli"}
        elif name in (
            "user-agent",
            "referer",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-original-url",
            "x-rewrite-url",
        ):
            allowed = {"xss", "sqli", "ssrf", "crlf", "host_header"}
        else:
            allowed = {"xss", "sqli"}
        return _order_categories(active & allowed, category_cap)

    if loc == "xml":
        return _order_categories(active & {"xxe", "sqli", "xss"}, category_cap)

    if loc == "json":
        return _order_categories(active & {"nosql", "sqli", "xss", "ssti"}, category_cap)

    allowed = set(active) - {"host_header", "xxe"}

    if loc == "path" or name in FILE_LIKE_PARAMS:
        allowed |= {"lfi", "traversal"}
    elif name not in FILE_LIKE_PARAMS:
        allowed.discard("traversal")

    if _is_url_like_param(name):
        allowed |= {"ssrf", "redirect"}
    else:
        allowed.discard("ssrf")
        if name not in ("redirect", "return", "next", "url"):
            allowed.discard("redirect")

    if name in ("user", "username", "email", "login", "uid", "cn", "dn", "filter"):
        allowed |= {"ldap"}

    if _is_id_like_param(name):
        allowed |= {"sqli", "nosql"}
    elif _is_generic_param(name):
        allowed &= GENERIC_PARAM_CATS | {"redirect", "ssrf", "lfi", "traversal", "crlf"}
        allowed.discard("cmdi")
        allowed.discard("nosql")
        allowed.discard("ldap")

    return _order_categories(allowed, category_cap)


def estimate_fuzz_tasks(
    points: list[InjectionPoint],
    config: ScanConfig,
    payloads_map: dict[VulnType, list[str]],
) -> int:
    total = 0
    cap = config.fuzz_category_cap if config.fast_fuzz else 0
    use_smart = config.fast_fuzz
    for point in points:
        if use_smart:
            cats = categories_for_point(point, config.categories, category_cap=cap)
        else:
            cats = tuple(c for c in CATEGORY_PRIORITY if c in config.categories - PASSIVE_TYPES)
        for vuln_type in cats:
            total += len(payloads_map.get(vuln_type, ()))
    return total


# Tier 0: um canário por categoria (alto sinal, mínimo ruído)
CANARY_PAYLOADS: dict[VulnType, str] = {
    "sqli": "'",
    "xss": "<vdx>",
    "lfi": "../../../../etc/passwd",
    "ssti": "{{7*7}}",
    "cmdi": ";id",
    "redirect": "https://evil.example/",
    "traversal": "../",
    "nosql": '{"$gt":""}',
    "ssrf": "http://127.0.0.1/",
    "xxe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "t">]><foo>&xxe;</foo>',
    "host_header": "evil.example",
    "crlf": "%0d%0aSet-Cookie: x=1",
    "ldap": "*)(uid=*",
}


def probe_has_anomaly(
    baseline: BaselineResponse,
    probe: ProbeResponse,
    *,
    len_delta_min: int = 12,
    time_delta_ms: float = 400.0,
) -> bool:
    """Indica se vale abrir Tier 2 (resto da wordlist)."""
    if probe.status == 0:
        return False
    if probe.status != baseline.status:
        return True
    if abs(probe.body_len - baseline.body_len) >= len_delta_min:
        return True
    if abs(probe.elapsed_ms - baseline.elapsed_ms) >= time_delta_ms:
        return True
    from vulndix.transport import body_hash

    if body_hash(probe.body) != baseline.body_hash:
        return True
    return False


def payloads_for_tier(
    cat: VulnType,
    all_payloads: list[str],
    tier: int,
    *,
    fast: bool = False,
) -> list[str]:
    """Tier 0=canário, 1=prioridade, 2=resto (só se caller habilitar após anomalia)."""
    priority = list(PRIORITY_PAYLOADS.get(cat, ()))
    canary = CANARY_PAYLOADS.get(cat)
    tier0: list[str] = []
    if canary:
        tier0.append(canary)
    elif priority:
        tier0.append(priority[0])
    elif all_payloads:
        tier0.append(all_payloads[0])

    if tier == 0:
        return tier0[:1]

    seen: set[str] = set()
    tier1: list[str] = []
    for p in priority:
        if p not in seen:
            tier1.append(p)
            seen.add(p)
    for p in all_payloads:
        if p not in seen:
            tier1.append(p)
            seen.add(p)

    if tier == 1:
        if fast:
            return tier1[: max(5, len(priority) + 2)]
        return tier1

    # tier 2: tudo que não entrou em 0/1
    tier01 = set(tier0) | set(tier1[: max(5, len(priority) + 2)] if fast else tier1)
    return [p for p in all_payloads if p not in tier01]


def estimate_fuzz_tasks_tiered(
    points: list[InjectionPoint],
    config: ScanConfig,
    payloads_map: dict[VulnType, list[str]],
) -> int:
    """Estimativa conservadora (assume ~tier0+tier1 por par)."""
    cap = config.fuzz_category_cap if config.fast_fuzz else 0
    total = 0
    for point in points:
        cats = categories_for_point(point, config.categories, category_cap=cap)
        for vuln_type in cats:
            pls = payloads_map.get(vuln_type, ())
            if config.fuzz_tier_mode:
                total += min(2, len(pls)) + (1 if pls else 0)
            else:
                total += len(pls)
    return total


def build_fuzz_tasks(
    points: list[InjectionPoint],
    config: ScanConfig,
    payloads_map: dict[VulnType, list[str]],
) -> list[tuple[InjectionPoint, VulnType, str]]:
    """Lista plana (legado / estimativa). Execução real usa fuzz_point_worker."""
    tasks: list[tuple[InjectionPoint, VulnType, str]] = []
    cap = config.fuzz_category_cap if config.fast_fuzz else 0
    use_smart = config.fast_fuzz
    for point in points:
        cats = (
            categories_for_point(point, config.categories, category_cap=cap)
            if use_smart
            else tuple(c for c in CATEGORY_PRIORITY if c in config.categories - PASSIVE_TYPES)
        )
        for vuln_type in cats:
            for payload in payloads_map.get(vuln_type, ()):
                tasks.append((point, vuln_type, payload))
    return tasks
