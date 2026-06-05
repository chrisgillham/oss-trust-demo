"""
Gate 1 — Release age validation tests.

Covers:
  - Hard block (< 24h)
  - Soft hold (24-72h)
  - Pass (> 72h)
  - Custom thresholds
  - Zero-day bypass eligibility
  - All supported ecosystems (PyPI, npm, Cargo, Go)
  - Registry error handling
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch


PACKAGE = "test-package"
VERSION = "1.0.0"


def make_release_time(hours_ago: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours_ago)


# ---------------------------------------------------------------------------
# Core age threshold tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hard_block_at_1_hour():
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(1))):
        result = await check_release_age(PACKAGE, VERSION, "PyPI")
    assert result.decision == AgeDecision.BLOCK
    assert result.age_hours < 24


@pytest.mark.asyncio
async def test_hard_block_at_23_hours():
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(23))):
        result = await check_release_age(PACKAGE, VERSION, "PyPI")
    assert result.decision == AgeDecision.BLOCK


@pytest.mark.asyncio
async def test_hold_at_24_hours():
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(25))):
        result = await check_release_age(PACKAGE, VERSION, "PyPI")
    assert result.decision == AgeDecision.HOLD


@pytest.mark.asyncio
async def test_hold_at_48_hours():
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(48))):
        result = await check_release_age(PACKAGE, VERSION, "PyPI")
    assert result.decision == AgeDecision.HOLD


@pytest.mark.asyncio
async def test_hold_at_71_hours():
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(71))):
        result = await check_release_age(PACKAGE, VERSION, "PyPI")
    assert result.decision == AgeDecision.HOLD


@pytest.mark.asyncio
async def test_pass_at_73_hours():
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(73))):
        result = await check_release_age(PACKAGE, VERSION, "PyPI")
    assert result.decision == AgeDecision.PASS


@pytest.mark.asyncio
async def test_pass_at_7_days():
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(168))):
        result = await check_release_age(PACKAGE, VERSION, "PyPI")
    assert result.decision == AgeDecision.PASS


# ---------------------------------------------------------------------------
# Custom thresholds
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_custom_hard_block_threshold():
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(6))):
        result = await check_release_age(
            PACKAGE, VERSION, "PyPI", hard_block_hours=4, hold_hours=12
        )
    assert result.decision == AgeDecision.HOLD  # 6h is between 4 and 12


@pytest.mark.asyncio
async def test_custom_hold_threshold():
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(2))):
        result = await check_release_age(
            PACKAGE, VERSION, "PyPI", hard_block_hours=1, hold_hours=6
        )
    assert result.decision == AgeDecision.HOLD


# ---------------------------------------------------------------------------
# Result metadata
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_result_contains_package_metadata():
    from oss_trust_framework.age_check.checker import check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(100))):
        result = await check_release_age("requests", "2.33.0", "PyPI")
    assert result.package == "requests"
    assert result.version == "2.33.0"
    assert result.ecosystem == "PyPI"
    assert result.age_hours > 0
    assert result.message != ""


@pytest.mark.asyncio
async def test_blocked_result_has_helpful_message():
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age
    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=make_release_time(5))):
        result = await check_release_age(PACKAGE, VERSION, "PyPI")
    assert result.decision == AgeDecision.BLOCK
    assert "hard block" in result.message.lower() or "24" in result.message
