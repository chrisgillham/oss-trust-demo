"""
Integration tests — cross-gate scenarios.

These tests exercise multiple gates together to verify:
  - A real known-good package clears all implemented gates
  - A CVE-affected package is caught at Gate 3 despite passing Gate 1
  - IronWorm and Miasma full chains are independently caught by Gate 5
  - Zero-day quorum + behavioral sandbox work in sequence
  - Fixtures from conftest produce the expected outcomes
"""

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Full pipeline simulations (mocked external calls)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_old_clean_package_clears_gates_1_and_3():
    """requests 2.33.0 simulated: old enough, no vulns, good score."""
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    release_time = datetime.now(timezone.utc) - timedelta(hours=1800)

    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=release_time)), \
         patch("oss_trust_framework.trust.aggregator._fetch_scorecard",
               new=AsyncMock(return_value=8.5)), \
         patch("oss_trust_framework.trust.aggregator._fetch_osv_vulns",
               new=AsyncMock(return_value=[])), \
         patch("oss_trust_framework.trust.aggregator._fetch_deps_dev",
               new=AsyncMock(return_value={"version": "2.33.0"})), \
         patch("oss_trust_framework.trust.aggregator._fetch_github_advisories",
               new=AsyncMock(return_value=0)):

        age = await check_release_age("requests", "2.33.0", "PyPI")
        trust = await aggregate_trust_score("requests", "2.33.0", "PyPI")

    assert age.decision == AgeDecision.PASS
    assert trust.passed
    assert trust.known_vulns == 0


@pytest.mark.asyncio
async def test_new_package_blocked_at_gate_1_regardless_of_trust():
    """Even a package with good trust score is blocked if < 24h old."""
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age

    release_time = datetime.now(timezone.utc) - timedelta(hours=2)

    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=release_time)):
        age = await check_release_age("new-pkg", "1.0.0", "PyPI")

    assert age.decision == AgeDecision.BLOCK


@pytest.mark.asyncio
async def test_old_vulnerable_package_quarantined_at_gate_3():
    """pillow 9.0.0: passes Gate 1 (old) but Gate 3 catches CVEs."""
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    release_time = datetime.now(timezone.utc) - timedelta(days=365)

    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=release_time)), \
         patch("oss_trust_framework.trust.aggregator._fetch_scorecard",
               new=AsyncMock(return_value=6.0)), \
         patch("oss_trust_framework.trust.aggregator._fetch_osv_vulns",
               new=AsyncMock(return_value=["GHSA-xxxx-1111", "GHSA-yyyy-2222"])), \
         patch("oss_trust_framework.trust.aggregator._fetch_deps_dev",
               new=AsyncMock(return_value={})), \
         patch("oss_trust_framework.trust.aggregator._fetch_github_advisories",
               new=AsyncMock(return_value=2)):

        age = await check_release_age("Pillow", "9.0.0", "PyPI")
        trust = await aggregate_trust_score("Pillow", "9.0.0", "PyPI")

    assert age.decision == AgeDecision.PASS   # Old enough
    assert not trust.passed                    # But has CVEs
    assert trust.known_vulns >= 2


# ---------------------------------------------------------------------------
# Gate 5 integration using conftest fixtures
# ---------------------------------------------------------------------------

def test_ironworm_chain_all_critical(ironworm_events):
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings, get_attack_family
    )
    findings = evaluate_sandbox_events(ironworm_events)
    assert has_critical_findings(findings)
    assert "IronWorm" in get_attack_family(findings)
    assert len(findings) >= 10


def test_miasma_chain_all_critical(miasma_events):
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings, get_attack_family
    )
    findings = evaluate_sandbox_events(miasma_events)
    assert has_critical_findings(findings)
    assert "Miasma/Shai-Hulud" in get_attack_family(findings)


def test_clean_install_no_critical(clean_events):
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    findings = evaluate_sandbox_events(clean_events)
    assert not has_critical_findings(findings)


# ---------------------------------------------------------------------------
# Zero-day lane + behavioral sandbox in sequence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_zeroday_approval_then_sandbox_blocks_malicious(quorum_manager, ironworm_events):
    """
    Even after zero-day quorum approval, a malicious payload is caught by Gate 5.
    The zero-day lane bypasses the AGE gate only.
    """
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )

    # Step 1: Get zero-day approval
    req = quorum_manager.create_request(
        "CVE-2024-99999", "requests", "2.33.1", "PyPI", "dev@example.com"
    )
    await quorum_manager.record_approval(req.request_id, "approver_001", "123456")
    result = await quorum_manager.record_approval(req.request_id, "approver_002", "123456")
    assert result["status"] == "approved"

    # Step 2: Sandbox still catches the malicious payload
    findings = evaluate_sandbox_events(ironworm_events)
    assert has_critical_findings(findings)
    # This would cause a BLOCK even with zero-day approval
    # Demonstrating gates are independent


@pytest.mark.asyncio
async def test_zeroday_approval_with_clean_package_proceeds(quorum_manager, clean_events):
    """Zero-day approval + clean sandbox = package can proceed."""
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )

    req = quorum_manager.create_request(
        "CVE-2024-99999", "requests", "2.33.1", "PyPI", "dev@example.com"
    )
    await quorum_manager.record_approval(req.request_id, "approver_001", "123456")
    result = await quorum_manager.record_approval(req.request_id, "approver_002", "123456")
    assert result["status"] == "approved"

    findings = evaluate_sandbox_events(clean_events)
    assert not has_critical_findings(findings)
    # Both zero-day approved AND sandbox clean = proceed to deploy


# ---------------------------------------------------------------------------
# Regression tests — previously failing scenarios
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_requests_2330_is_clean():
    """
    Regression: requests 2.32.3 had 2 active CVEs.
    2.33.0 should be clean per OSV.
    This test mocks the expected clean state.
    """
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
    assert result.known_vulns == 0


@pytest.mark.asyncio
async def test_requests_2323_has_vulns():
    """
    Regression: requests 2.32.3 was flagged with:
      GHSA-9hjg-9r4m-mvj7 (.netrc leak)
      GHSA-gc5v-m9x4-r6x2 (temp file reuse)
    """
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    with patch("oss_trust_framework.trust.aggregator._fetch_scorecard",
               new=AsyncMock(return_value=7.0)), \
         patch("oss_trust_framework.trust.aggregator._fetch_osv_vulns",
               new=AsyncMock(return_value=[
                   "GHSA-9hjg-9r4m-mvj7",
                   "GHSA-gc5v-m9x4-r6x2",
               ])), \
         patch("oss_trust_framework.trust.aggregator._fetch_deps_dev",
               new=AsyncMock(return_value={})), \
         patch("oss_trust_framework.trust.aggregator._fetch_github_advisories",
               new=AsyncMock(return_value=2)):

        result = await aggregate_trust_score("requests", "2.32.3", "PyPI")

    assert not result.passed
    assert result.known_vulns == 2
    assert "GHSA-9hjg-9r4m-mvj7" in result.vuln_ids
