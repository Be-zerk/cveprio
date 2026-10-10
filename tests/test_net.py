"""AC19–AC20: URL restrictions, private-address blocking, limits, retries, cache, fixture isolation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from cveprio.net import FetchError, FixtureFetcher, ResponseCache, SafeFetcher, validate_url
from cveprio.sources import fetch_cve_org

PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731  (documentation-range-like public IP for tests)
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"


@pytest.mark.parametrize("url,reason", [
    ("http://services.nvd.nist.gov/x", "https"),
    ("https://evil.example.com/x", "allowlist"),
    ("https://services.nvd.nist.gov.evil.example/x", "allowlist"),
    ("https://user:pw@services.nvd.nist.gov/x", "credentials"),
    ("https://services.nvd.nist.gov:8443/x", "port"),
    ("file:///etc/passwd", "https"),
])
def test_disallowed_urls(url, reason):
    with pytest.raises(FetchError) as e:
        validate_url(url, resolver=PUBLIC)
    assert e.value.kind == "blocked" and reason in str(e.value)


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "fd00::1",
                                  "100.64.0.1", "0.0.0.0"])
def test_allowlisted_host_resolving_to_private_address_is_blocked(addr):
    with pytest.raises(FetchError) as e:
        validate_url(NVD, resolver=lambda h: [addr])
    assert e.value.kind == "blocked" and "non-public" in str(e.value)


def fetcher(handler, **kw):
    sleeps: list[float] = []
    f = SafeFetcher(resolver=PUBLIC, transport=httpx.MockTransport(handler), sleep=sleeps.append, **kw)
    return f, sleeps


def test_size_limit_enforced_even_without_content_length():
    def handler(req):
        return httpx.Response(200, content=b"x" * 5000, headers={"content-length": ""})

    f, _ = fetcher(handler)
    with pytest.raises(FetchError) as e:
        f.get(NVD, max_bytes=1000)
    assert e.value.kind == "too_large"


def test_retry_after_honoured_and_bounded():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(429, headers={"retry-after": "999"})

    f, sleeps = fetcher(handler)
    with pytest.raises(FetchError) as e:
        f.get(NVD)
    assert e.value.kind == "rate_limited"
    assert len(calls) == 3 and sleeps == [30.0, 30.0]  # 3 attempts, Retry-After capped at 30 s


def test_transient_5xx_then_success():
    responses = iter([httpx.Response(503), httpx.Response(200, json={"ok": 1})])
    f, sleeps = fetcher(lambda req: next(responses))
    assert f.get(NVD).json() == {"ok": 1} and len(sleeps) == 1


def test_404_not_retried():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(404)

    f, _ = fetcher(handler)
    with pytest.raises(FetchError):
        f.get(NVD)
    assert len(calls) == 1


def test_redirect_to_disallowed_host_blocked():
    f, _ = fetcher(lambda req: httpx.Response(302, headers={"location": "https://169.254.169.254/latest/meta-data"}))
    with pytest.raises(FetchError) as e:
        f.get(NVD)
    assert e.value.kind == "blocked"


def test_timeout_reported_after_bounded_retries():
    def handler(req):
        raise httpx.ReadTimeout("slow")

    f, sleeps = fetcher(handler)
    with pytest.raises(FetchError) as e:
        f.get(NVD)
    assert e.value.kind == "timeout" and len(sleeps) == 2


def test_api_key_header_not_part_of_cache_key(tmp_path):
    seen = []

    def handler(req):
        seen.append(req.headers.get("apiKey"))
        return httpx.Response(200, json={"v": 1})

    cache = ResponseCache(tmp_path / "c.sqlite")
    f, _ = fetcher(handler, cache=cache)
    first = f.get(NVD, headers={"apiKey": "SECRET-TEST-KEY"})
    second = f.get(NVD, headers={"apiKey": "SECRET-TEST-KEY"})
    assert seen == ["SECRET-TEST-KEY"] and second.from_cache
    assert second.retrieved_at == first.retrieved_at  # original retrieval time preserved
    assert b"SECRET-TEST-KEY" not in (tmp_path / "c.sqlite").read_bytes()


def test_cache_expiry(tmp_path):
    cache = ResponseCache(tmp_path / "c.sqlite")
    from cveprio.net import FetchResult
    cache.put(FetchResult(url=NVD, status_code=200, body=b"{}", retrieved_at=datetime.now(UTC) - timedelta(days=2)))
    assert cache.get(NVD, timedelta(hours=24)) is None
    assert cache.get(NVD, timedelta(days=3)) is not None


def test_fixture_fetcher_never_falls_back_to_network(fixtures_fetcher: FixtureFetcher):
    with pytest.raises(FetchError) as e:
        fixtures_fetcher.get("https://cveawg.mitre.org/api/cve/CVE-2020-0001")
    assert e.value.kind == "not_in_fixtures"
    data = fetch_cve_org(fixtures_fetcher, "CVE-2020-0001")
    assert data.outcome.status.value == "skipped" and data.outcome.demo


def test_malformed_json_is_failure_not_empty_result():
    from cveprio.models import SourceStatus
    from cveprio.sources import fetch_nvd
    f, _ = fetcher(lambda req: httpx.Response(200, content=b"<html>maintenance</html>"))
    assert fetch_nvd(f, "CVE-2021-44228").outcome.status == SourceStatus.FAILED
