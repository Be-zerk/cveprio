"""Network access: the only module that talks to the internet.

Safety properties (see docs/ARCHITECTURE.md, "Retrieval safety"):

* HTTPS only, to an explicit host allowlist (no user-supplied or retrieved URL is
  ever fetched unless its host is on the list).
* Every resolved address must be a public (global) IP: loopback, private,
  link-local, multicast and reserved ranges are refused, so a poisoned DNS answer
  or a future allowlist mistake cannot reach internal services.
* Redirects are not followed automatically; each hop is re-validated (max 3).
* Response bodies are streamed with a hard byte limit; timeouts on every request.
* Retries are bounded (3 attempts) on 429/5xx/timeouts, honouring ``Retry-After``
  up to a cap; after that the caller gets an explicit ``rate_limited``/``failed``.
* Responses are cached in SQLite together with their *original* retrieval time,
  so provenance stays honest when a cached copy is reused.

Fixture (offline demo) mode is a separate class, ``FixtureFetcher``; it never
falls back to the network and the network fetcher never falls back to fixtures.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

import httpx

ALLOWED_HOSTS = frozenset(
    {
        "cveawg.mitre.org",
        "services.nvd.nist.gov",
        "api.first.org",
        "www.cisa.gov",
        "api.osv.dev",
        "ubuntu.com",
        "access.redhat.com",
    }
)
USER_AGENT = "cveprio/0.1 (evidence-backed CVE prioritization; research prototype)"
DEFAULT_MAX_BYTES = 4 * 1024 * 1024
MAX_ATTEMPTS = 3
MAX_RETRY_AFTER_S = 30.0
MAX_REDIRECTS = 3


class FetchError(Exception):
    """Raised for any retrieval failure. ``kind`` drives the reported status."""

    def __init__(self, kind: str, message: str, *, url: str | None = None, http_status: int | None = None):
        super().__init__(message)
        self.kind = kind  # blocked | timeout | network | http | too_large | rate_limited | not_in_fixtures
        self.url = url
        self.http_status = http_status


@dataclass
class FetchResult:
    url: str
    status_code: int
    body: bytes
    retrieved_at: datetime
    from_cache: bool = False
    demo: bool = False

    def json(self) -> object:
        return json.loads(self.body)


class Fetcher(Protocol):
    demo: bool

    def get(
        self, url: str, *, headers: dict[str, str] | None = None, max_bytes: int = DEFAULT_MAX_BYTES,
        ttl: timedelta = timedelta(hours=24), accept_status: tuple[int, ...] = (200,),
    ) -> FetchResult: ...

    def post_json(
        self, url: str, body: dict[str, object], *, max_bytes: int = DEFAULT_MAX_BYTES,
        ttl: timedelta = timedelta(hours=24),
    ) -> FetchResult: ...


def post_cache_key(url: str, body: dict[str, object]) -> str:
    return url + "#" + json.dumps(body, sort_keys=True, separators=(",", ":"))


Resolver = Callable[[str], list[str]]


def _system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return sorted({str(info[4][0]) for info in infos})


def validate_url(url: str, *, resolver: Resolver = _system_resolver, allowed_hosts: frozenset[str] = ALLOWED_HOSTS) -> None:
    """Raise ``FetchError('blocked')`` unless ``url`` is safe to request."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise FetchError("blocked", f"only https URLs are allowed: {url!r}", url=url)
    if parts.username or parts.password:
        raise FetchError("blocked", "credentials in URL are not allowed", url=url)
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.port not in (None, 443):
        raise FetchError("blocked", f"non-standard port refused: {parts.port}", url=url)
    if host not in allowed_hosts:
        raise FetchError("blocked", f"host not on allowlist: {host!r}", url=url)
    try:
        addresses = resolver(host)
    except OSError as exc:
        raise FetchError("network", f"DNS resolution failed for {host}: {exc}", url=url) from exc
    if not addresses:
        raise FetchError("network", f"no addresses for {host}", url=url)
    for addr in addresses:
        ip = ipaddress.ip_address(addr.split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise FetchError("blocked", f"{host} resolved to non-public address {ip}", url=url)


class ResponseCache:
    """Tiny SQLite cache keyed by URL. Stores the original retrieval timestamp."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS responses (url TEXT PRIMARY KEY, status INTEGER, body BLOB, fetched_at TEXT)"
        )

    def get(self, url: str, ttl: timedelta) -> FetchResult | None:
        row = self._db.execute("SELECT status, body, fetched_at FROM responses WHERE url = ?", (url,)).fetchone()
        if not row:
            return None
        fetched = datetime.fromisoformat(row[2])
        if datetime.now(UTC) - fetched > ttl:
            return None
        return FetchResult(url=url, status_code=row[0], body=row[1], retrieved_at=fetched, from_cache=True)

    def put(self, result: FetchResult) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO responses VALUES (?, ?, ?, ?)",
            (result.url, result.status_code, result.body, result.retrieved_at.isoformat()),
        )
        self._db.commit()


class SafeFetcher:
    demo = False

    def __init__(
        self,
        cache: ResponseCache | None = None,
        *,
        resolver: Resolver = _system_resolver,
        transport: httpx.BaseTransport | None = None,
        timeout_s: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        min_interval_s: dict[str, float] | None = None,
    ):
        self.cache = cache
        self.resolver = resolver
        self.sleep = sleep
        self.client = httpx.Client(
            transport=transport, timeout=httpx.Timeout(timeout_s), follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        # Politeness per host (NVD without a key: 5 requests / 30 s -> 6 s spacing).
        self.min_interval_s = min_interval_s or {}
        self._last_request: dict[str, float] = {}

    def _throttle(self, host: str) -> None:
        gap = self.min_interval_s.get(host, 0.0)
        last = self._last_request.get(host)
        if gap and last is not None:
            wait = gap - (time.monotonic() - last)
            if wait > 0:
                self.sleep(wait)
        self._last_request[host] = time.monotonic()

    def get(
        self, url: str, *, headers: dict[str, str] | None = None, max_bytes: int = DEFAULT_MAX_BYTES,
        ttl: timedelta = timedelta(hours=24), accept_status: tuple[int, ...] = (200,),
    ) -> FetchResult:
        if self.cache:
            cached = self.cache.get(url, ttl)
            if cached and cached.status_code in accept_status:
                return cached
        result = self._get_with_retries(url, headers or {}, max_bytes, accept_status)
        if self.cache:
            self.cache.put(result)
        return result

    def post_json(
        self, url: str, body: dict[str, object], *, max_bytes: int = DEFAULT_MAX_BYTES,
        ttl: timedelta = timedelta(hours=24),
    ) -> FetchResult:
        """POST a JSON query (used for OSV). Same validation, limits, retries; cached by URL + body."""
        key = post_cache_key(url, body)
        if self.cache:
            cached = self.cache.get(key, ttl)
            if cached and cached.status_code == 200:
                return cached
        result = self._get_with_retries(url, {"Content-Type": "application/json"}, max_bytes, (200,),
                                        method="POST", content=json.dumps(body).encode())
        if self.cache:
            self.cache.put(FetchResult(url=key, status_code=result.status_code, body=result.body,
                                       retrieved_at=result.retrieved_at))
        return result

    def _get_with_retries(
        self, url: str, headers: dict[str, str], max_bytes: int, accept_status: tuple[int, ...],
        method: str = "GET", content: bytes | None = None,
    ) -> FetchResult:
        last_error: FetchError | None = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                return self._get_once(url, headers, max_bytes, accept_status, method, content)
            except FetchError as err:
                last_error = err
                retryable = err.kind in ("timeout", "network", "rate_limited") or (
                    err.kind == "http" and (err.http_status or 0) >= 500
                )
                if not retryable or attempt == MAX_ATTEMPTS:
                    raise
                delay = getattr(err, "retry_after", None) or min(2.0**attempt, MAX_RETRY_AFTER_S)
                self.sleep(min(delay, MAX_RETRY_AFTER_S))
        assert last_error is not None  # pragma: no cover
        raise last_error  # pragma: no cover

    def _get_once(
        self, url: str, headers: dict[str, str], max_bytes: int, accept_status: tuple[int, ...],
        method: str = "GET", content: bytes | None = None,
    ) -> FetchResult:
        current = url
        for _hop in range(MAX_REDIRECTS + 1):
            validate_url(current, resolver=self.resolver)
            self._throttle(urlsplit(current).hostname or "")
            try:
                with self.client.stream(method, current, headers=headers, content=content) as resp:
                    if resp.is_redirect:
                        location = resp.headers.get("location", "")
                        current = str(httpx.URL(current).join(location))
                        continue
                    if resp.status_code == 429 or (resp.status_code == 403 and "nvd.nist.gov" in current):
                        # NVD signals throttling with 403 as well as 429.
                        err = FetchError("rate_limited", f"rate limited (HTTP {resp.status_code})",
                                         url=url, http_status=resp.status_code)
                        err.retry_after = _parse_retry_after(resp.headers.get("retry-after"))  # type: ignore[attr-defined]
                        raise err
                    declared = resp.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > max_bytes:
                        raise FetchError("too_large", f"response declares {declared} bytes > limit {max_bytes}",
                                         url=url, http_status=resp.status_code)
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in resp.iter_bytes():
                        total += len(chunk)
                        if total > max_bytes:
                            raise FetchError("too_large", f"response exceeded {max_bytes} bytes",
                                             url=url, http_status=resp.status_code)
                        chunks.append(chunk)
                    if resp.status_code not in accept_status:
                        raise FetchError("http", f"HTTP {resp.status_code}", url=url, http_status=resp.status_code)
                    return FetchResult(url=url, status_code=resp.status_code, body=b"".join(chunks),
                                       retrieved_at=datetime.now(UTC))
            except httpx.TimeoutException as exc:
                raise FetchError("timeout", f"timed out: {exc}", url=url) from exc
            except httpx.TransportError as exc:
                raise FetchError("network", f"network error: {exc}", url=url) from exc
        raise FetchError("blocked", f"too many redirects for {url}", url=url)


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, min(float(value), MAX_RETRY_AFTER_S))
    except ValueError:
        return None


class FixtureFetcher:
    """Serves recorded responses from ``fixtures/<set>/manifest.json``. Never touches the network."""

    demo = True

    def __init__(self, root: Path):
        self.root = root
        manifest_path = root / "manifest.json"
        self.manifest: dict[str, dict[str, object]] = json.loads(manifest_path.read_text())["responses"]

    def get(
        self, url: str, *, headers: dict[str, str] | None = None, max_bytes: int = DEFAULT_MAX_BYTES,
        ttl: timedelta = timedelta(hours=24), accept_status: tuple[int, ...] = (200,),
    ) -> FetchResult:
        entry = self.manifest.get(url)
        if entry is None:
            raise FetchError("not_in_fixtures", f"no offline fixture recorded for {url}", url=url)
        status = int(entry["status"])  # type: ignore[call-overload]
        body = (self.root / str(entry["file"])).read_bytes()
        result = FetchResult(
            url=url, status_code=status, body=body,
            retrieved_at=datetime.fromisoformat(str(entry["retrieved_at"])), from_cache=True, demo=True,
        )
        if status not in accept_status:
            raise FetchError("http", f"HTTP {status} (recorded)", url=url, http_status=status)
        return result

    def post_json(
        self, url: str, body: dict[str, object], *, max_bytes: int = DEFAULT_MAX_BYTES,
        ttl: timedelta = timedelta(hours=24),
    ) -> FetchResult:
        return self.get(post_cache_key(url, body))
