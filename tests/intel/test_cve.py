import httpx
import pytest

from vulnclaw.intel import cve
from vulnclaw.intel.cve import (
    CVEEntry,
    cve_lookup_tool,
    format_cve_report,
    lookup_cve_id,
    search_cve,
)

# Minimal NVD 2.0 response shaped like the real API.
NVD_SAMPLE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 JNDI features allow RCE."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "vectorString": "CVSS:3.1/AV:N/AC:L",
                                "baseSeverity": "CRITICAL",
                            },
                            "baseSeverity": "CRITICAL",
                        }
                    ]
                },
                "published": "2021-12-10T00:00:00.000",
                "lastModified": "2023-04-03T00:00:00.000",
                "references": [{"url": "https://logging.apache.org/log4j/"}],
                "weaknesses": [{"description": [{"value": "CWE-502"}]}],
                "configurations": [
                    {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:2.0"}]}]}
                ],
            }
        }
    ]
}

GITHUB_SAMPLE = {
    "items": [
        {
            "full_name": "owner/log4shell-poc",
            "html_url": "https://github.com/owner/log4shell-poc",
            "description": "PoC",
            "stargazers_count": 1234,
            "language": "Java",
        }
    ]
}


def _mock_client() -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "services.nvd.nist.gov" in url:
            return httpx.Response(200, json=NVD_SAMPLE)
        if "api.github.com" in url:
            return httpx.Response(200, json=GITHUB_SAMPLE)
        return httpx.Response(404, json={})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_parse_nvd_item_extracts_fields():
    entry = cve._parse_nvd_item(NVD_SAMPLE["vulnerabilities"][0])
    assert entry.cve_id == "CVE-2021-44228"
    assert entry.cvss_score == 10.0
    assert entry.severity_label == "Critical"
    assert "CWE-502" in entry.weaknesses
    assert entry.references and entry.cpe_matches


@pytest.mark.asyncio
async def test_search_cve_returns_sorted_entries():
    async with _mock_client() as client:
        results = await search_cve(
            "log4j", max_results=5, client=client, rate_limit=False
        )
    assert len(results) == 1
    assert isinstance(results[0], CVEEntry)
    assert results[0].cve_id == "CVE-2021-44228"


@pytest.mark.asyncio
async def test_lookup_cve_id_attaches_exploits():
    async with _mock_client() as client:
        entry = await lookup_cve_id(
            "CVE-2021-44228", client=client, rate_limit=False, with_exploits=True
        )
    assert entry is not None
    assert entry.exploits and entry.exploits[0]["source"] == "GitHub"


@pytest.mark.asyncio
async def test_lookup_cve_id_rejects_malformed_id():
    async with _mock_client() as client:
        entry = await lookup_cve_id("not-a-cve", client=client, rate_limit=False)
    assert entry is None


def test_format_cve_report_renders_table_and_detail():
    entry = cve._parse_nvd_item(NVD_SAMPLE["vulnerabilities"][0])
    out = format_cve_report([entry], title="CVE search: log4j")
    assert "CVE search: log4j" in out
    assert "CVE-2021-44228" in out
    assert "| CVE ID | CVSS | Severity |" in out


def test_format_cve_report_empty():
    assert "No CVEs found" in format_cve_report([], title="x")


@pytest.mark.asyncio
async def test_tool_empty_query_is_structured_error():
    out = await cve_lookup_tool(agent=None, args={"query": "  "})
    assert out.startswith("[cve_lookup]") and "query" in out


@pytest.mark.asyncio
async def test_tool_routes_cve_id_vs_keyword(monkeypatch):
    calls = {}

    async def fake_lookup(cve_id, **kw):
        calls["id"] = cve_id
        return cve._parse_nvd_item(NVD_SAMPLE["vulnerabilities"][0])

    async def fake_search(keyword, **kw):
        calls["kw"] = keyword
        return [cve._parse_nvd_item(NVD_SAMPLE["vulnerabilities"][0])]

    monkeypatch.setattr(cve, "lookup_cve_id", fake_lookup)
    monkeypatch.setattr(cve, "search_cve", fake_search)

    out_id = await cve_lookup_tool(agent=None, args={"query": "CVE-2021-44228"})
    out_kw = await cve_lookup_tool(agent=None, args={"query": "log4j"})

    assert calls.get("id") == "CVE-2021-44228"
    assert calls.get("kw") == "log4j"
    assert "CVE-2021-44228" in out_id and "CVE-2021-44228" in out_kw


# ── 别名回退：NVD 不认漏洞绰号，GitHub 认（2026-10-19 实测） ──────────────────
#
# 实测 NVD：
#   search_cve('log4j')     -> CVE-2017-5645 / 2019-17571 / 2014-0722（全是旧的，
#                              CVE-2021-44228 不在里面）
#   search_cve('log4shell') -> 0 条
#   search_cve('Log4j2')    -> CVE-2021-44228 排第一
#
# 也就是说，agent 按操作者/题面的说法（绰号）去查，会拿到"没有"或一堆十年前的
# CVE —— "用新披露的漏洞"这条路就断在这里。GitHub 仓库名/描述里是写绰号的，实测
# log4shell -> CVE-2021-44228、springshell -> CVE-2022-22965、
# text4shell -> CVE-2022-42889 都能提出来。


@pytest.mark.asyncio
async def test_alias_resolves_to_a_cve_id_via_github(monkeypatch):
    async def fake_exploits(query, **kw):
        return [
            {"title": "NCSC-NL/log4shell", "url": "https://x/1", "description": "CVE-2021-44228 scanner", "stars": "1882"},
            {"title": "someone/other", "url": "https://x/2", "description": "CVE-2021-44228 PoC", "stars": "10"},
            {"title": "mixed/collection", "url": "https://x/3", "description": "CVE-2021-21972 too", "stars": "5"},
        ]

    async def fake_lookup(cve_id, **kw):
        return cve.CVEEntry(cve_id=cve_id, description=f"desc {cve_id}", cvss_score=9.8)

    monkeypatch.setattr(cve, "search_exploits", fake_exploits)
    monkeypatch.setattr(cve, "lookup_cve_id", fake_lookup)

    entries, repos = await cve.resolve_alias_to_cves("log4shell", max_results=3)
    assert len(repos) == 3
    # Ranked by how many repos mention the id: 44228 appears twice, 21972 once.
    assert [e.cve_id for e in entries] == ["CVE-2021-44228", "CVE-2021-21972"]


@pytest.mark.asyncio
async def test_alias_fallback_fires_only_when_nvd_is_empty(monkeypatch):
    """A keyword NVD DOES understand must not pay for a GitHub round trip."""
    calls = {"alias": 0}

    async def fake_search(keyword, **kw):
        return []

    async def fake_alias(query, **kw):
        calls["alias"] += 1
        return [cve.CVEEntry(cve_id="CVE-2021-44228", description="via alias", cvss_score=10.0)], [{"title": "x", "url": "u", "stars": "1"}]

    monkeypatch.setattr(cve, "search_cve", fake_search)
    monkeypatch.setattr(cve, "resolve_alias_to_cves", fake_alias)

    out = await cve_lookup_tool(agent=None, args={"query": "log4shell"})
    assert calls["alias"] == 1
    assert "CVE-2021-44228" in out
    # The mapping is inferred, and the caller must be told so.
    assert "inferred, not authoritative" in out


@pytest.mark.asyncio
async def test_a_nonempty_nvd_result_skips_the_alias_path(monkeypatch):
    calls = {"alias": 0}

    async def fake_search(keyword, **kw):
        return [cve.CVEEntry(cve_id="CVE-2017-5645", description="old", cvss_score=9.8)]

    async def fake_alias(query, **kw):
        calls["alias"] += 1
        return [], []

    monkeypatch.setattr(cve, "search_cve", fake_search)
    monkeypatch.setattr(cve, "resolve_alias_to_cves", fake_alias)

    out = await cve_lookup_tool(agent=None, args={"query": "log4j"})
    assert calls["alias"] == 0
    assert "CVE-2017-5645" in out


@pytest.mark.asyncio
async def test_a_stale_nvd_answer_says_so(monkeypatch):
    """实测：查 'log4j' 返回 2017/2019/2014，Log4Shell 不在其中。

    NVD 关键词是全文本匹配，按相关度而不是时间排；一个只报最新 5 条的列表会让
    agent 相信"这就是全部"。所以当最新年份早于今年时必须明说，并提示换更精确的
    产品名或绰号重试。
    """

    async def fake_search(keyword, **kw):
        return [
            cve.CVEEntry(cve_id="CVE-2017-5645", description="old", cvss_score=9.8),
            cve.CVEEntry(cve_id="CVE-2014-0722", description="older", cvss_score=7.5),
        ]

    monkeypatch.setattr(cve, "search_cve", fake_search)
    out = await cve_lookup_tool(agent=None, args={"query": "log4j"})
    assert "CVE-2017-5645" in out
    assert "Newest match here is 2017" in out
    assert "nickname" in out


@pytest.mark.asyncio
async def test_a_current_year_answer_carries_no_stale_note(monkeypatch):
    import time as _time

    year = _time.gmtime().tm_year

    async def fake_search(keyword, **kw):
        return [
            cve.CVEEntry(cve_id=f"CVE-{year}-12345", description="new", cvss_score=9.8)
        ]

    monkeypatch.setattr(cve, "search_cve", fake_search)
    out = await cve_lookup_tool(agent=None, args={"query": "some product"})
    assert "Newest match here is" not in out
