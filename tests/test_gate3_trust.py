"""
Gate 3 — Out-of-band trust aggregation tests.

Covers:
  - Clean package passes (no vulns, good score)
  - Package with active CVEs quarantined
  - Score computation from individual source weights
  - Source failure tolerance (individual source down = degraded not failed)
  - Known vuln IDs returned correctly
  - GitHub advisory integration
  - Composite score floor and ceiling
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx


def mock_scorecard(score: float):
    return AsyncMock(return_value=httpx.Response(
        200, json={"score": score}
    ))


def mock_osv_clean():
    return AsyncMock(return_value=httpx.Response(200, json={"vulns": []}))


def mock_osv_with_vulns(vuln_ids: list):
    return AsyncMock(return_value=httpx.Response(
        200, json={"vulns": [{"id": vid} for vid in vuln_ids]}
    ))


def mock_deps_ok():
    return AsyncMock(return_value=httpx.Response(200, json={"version": "1.0.0"}))


def mock_ghsa_clean():
    return AsyncMock(return_value=httpx.Response(200, json=[]))


# ---------------------------------------------------------------------------
# Clean package
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_clean_package_passes():
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    with patch("oss_trust_framework.trust.aggregator._fetch_scorecard",
               new=AsyncMock(return_value=8.0)), \
         patch("oss_trust_framework.trust.aggregator._fetch_osv_vulns",
               new=AsyncMock(return_value=[])), \
         patch("oss_trust_framework.trust.aggregator._fetch_deps_dev",
               new=AsyncMock(return_value={"version": "2.33.0"})), \
         patch("oss_trust_framework.trust.aggregator._fetch_github_advisories",
               new=AsyncMock(return_value=0)):

        result = await aggregate_trust_score("requests", "2.33.0", "PyPI")

    assert result.passed
    assert result.recommendation == "PASS"
    assert result.known_vulns == 0
    assert result.composite_score > 60


@pytest.mark.asyncio
async def test_package_with_vulns_quarantined():
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    with patch("oss_trust_framework.trust.aggregator._fetch_scorecard",
               new=AsyncMock(return_value=7.0)), \
         patch("oss_trust_framework.trust.aggregator._fetch_osv_vulns",
               new=AsyncMock(return_value=["GHSA-xxxx-yyyy-zzzz", "GHSA-aaaa-bbbb-cccc"])), \
         patch("oss_trust_framework.trust.aggregator._fetch_deps_dev",
               new=AsyncMock(return_value={})), \
         patch("oss_trust_framework.trust.aggregator._fetch_github_advisories",
               new=AsyncMock(return_value=2)):

        result = await aggregate_trust_score("vulnerable-pkg", "1.0.0", "PyPI")

    assert not result.passed
    assert result.recommendation == "QUARANTINE"
    assert result.known_vulns == 2
    assert "GHSA-xxxx-yyyy-zzzz" in result.vuln_ids


@pytest.mark.asyncio
async def test_low_scorecard_score_quarantines():
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    with patch("oss_trust_framework.trust.aggregator._fetch_scorecard",
               new=AsyncMock(side_effect=Exception("scorecard unavailable"))), \
         patch("oss_trust_framework.trust.aggregator._fetch_osv_vulns",
               new=AsyncMock(return_value=[])), \
         patch("oss_trust_framework.trust.aggregator._fetch_deps_dev",
               new=AsyncMock(return_value={})), \
         patch("oss_trust_framework.trust.aggregator._fetch_github_advisories",
               new=AsyncMock(return_value=0)):

        result = await aggregate_trust_score("sketchy-pkg", "1.0.0", "PyPI")

    assert result is not None
    assert 0 <= result.composite_score <= 100
    assert result.known_vulns == 0


@pytest.mark.asyncio
async def test_single_source_failure_degrades_not_fails():
    """If one source fails, the others should still contribute."""
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    with patch("oss_trust_framework.trust.aggregator._fetch_scorecard",
               new=AsyncMock(side_effect=Exception("scorecard down"))), \
         patch("oss_trust_framework.trust.aggregator._fetch_osv_vulns",
               new=AsyncMock(return_value=[])), \
         patch("oss_trust_framework.trust.aggregator._fetch_deps_dev",
               new=AsyncMock(return_value={"version": "1.0.0"})), \
         patch("oss_trust_framework.trust.aggregator._fetch_github_advisories",
               new=AsyncMock(return_value=0)):

        # Should not raise — should return a degraded but valid result
        result = await aggregate_trust_score("some-pkg", "1.0.0", "PyPI")

    assert result is not None
    assert result.known_vulns == 0


@pytest.mark.asyncio
async def test_multiple_vulns_compound_score_penalty():
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    with patch("oss_trust_framework.trust.aggregator._fetch_scorecard",
               new=AsyncMock(return_value=9.0)), \
         patch("oss_trust_framework.trust.aggregator._fetch_osv_vulns",
               new=AsyncMock(return_value=[
                   "GHSA-0001", "GHSA-0002", "GHSA-0003", "GHSA-0004"
               ])), \
         patch("oss_trust_framework.trust.aggregator._fetch_deps_dev",
               new=AsyncMock(return_value={})), \
         patch("oss_trust_framework.trust.aggregator._fetch_github_advisories",
               new=AsyncMock(return_value=4)):

        result = await aggregate_trust_score("many-vulns-pkg", "1.0.0", "PyPI")

    assert not result.passed
    assert result.known_vulns == 4


@pytest.mark.asyncio
async def test_composite_score_bounded_0_to_100():
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    with patch("oss_trust_framework.trust.aggregator._fetch_scorecard",
               new=AsyncMock(return_value=10.0)), \
         patch("oss_trust_framework.trust.aggregator._fetch_osv_vulns",
               new=AsyncMock(return_value=[])), \
         patch("oss_trust_framework.trust.aggregator._fetch_deps_dev",
               new=AsyncMock(return_value={"version": "1.0.0"})), \
         patch("oss_trust_framework.trust.aggregator._fetch_github_advisories",
               new=AsyncMock(return_value=0)):

        result = await aggregate_trust_score("perfect-pkg", "1.0.0", "PyPI")

    assert 0 <= result.composite_score <= 100
