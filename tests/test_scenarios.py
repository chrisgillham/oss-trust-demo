"""
Tests for the OSS Trust Demo scenarios.

These tests verify the framework's core capabilities without requiring
network access — all external API calls are mocked.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch


# ---------------------------------------------------------------------------
# Gate 1 — Age check
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_age_gate_blocks_new_package():
    """A package published 3 hours ago must be hard-blocked."""
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age

    release_time = datetime.now(timezone.utc) - timedelta(hours=3)

    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=release_time)):
        result = await check_release_age("test-pkg", "1.0.0", "PyPI")

    assert result.decision == AgeDecision.BLOCK
    assert result.age_hours < 24


@pytest.mark.asyncio
async def test_age_gate_holds_day_old_package():
    """A package published 36 hours ago must enter the hold state."""
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age

    release_time = datetime.now(timezone.utc) - timedelta(hours=36)

    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=release_time)):
        result = await check_release_age("test-pkg", "1.0.0", "PyPI")

    assert result.decision == AgeDecision.HOLD


@pytest.mark.asyncio
async def test_age_gate_passes_old_package():
    """A package published 5 days ago must pass."""
    from oss_trust_framework.age_check.checker import AgeDecision, check_release_age

    release_time = datetime.now(timezone.utc) - timedelta(days=5)

    with patch("oss_trust_framework.age_check.checker._pypi_release_time",
               new=AsyncMock(return_value=release_time)):
        result = await check_release_age("test-pkg", "1.0.0", "PyPI")

    assert result.decision == AgeDecision.PASS


# ---------------------------------------------------------------------------
# Gate 5 — IronWorm behavioral patterns
# ---------------------------------------------------------------------------

def test_ironworm_tor_c2_blocked():
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    events = [{"type": "network", "value": "http://abc123.onion/api/agent"}]
    findings = evaluate_sandbox_events(events)
    assert has_critical_findings(findings)
    assert any(f["pattern_id"] == "IRONWORM-001" for f in findings)


def test_ironworm_openai_key_harvest_blocked():
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    events = [{"type": "env_access", "value": "OPENAI_API_KEY=sk-abc123"}]
    findings = evaluate_sandbox_events(events)
    assert has_critical_findings(findings)
    assert any(f["pattern_id"] == "IRONWORM-003" for f in findings)


def test_ironworm_anthropic_key_harvest_blocked():
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    events = [{"type": "env_access", "value": "ANTHROPIC_API_KEY=sk-ant-xyz"}]
    findings = evaluate_sandbox_events(events)
    assert has_critical_findings(findings)


def test_ironworm_ebpf_rootkit_blocked():
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    events = [{"type": "process", "value": "BPF_PROG_LOAD fd=3"}]
    findings = evaluate_sandbox_events(events)
    assert has_critical_findings(findings)
    assert any(f["pattern_id"] == "IRONWORM-002" for f in findings)


def test_ironworm_exodus_wallet_blocked():
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    events = [{"type": "file_read", "value": "/root/.config/Exodus/exodus.wallet"}]
    findings = evaluate_sandbox_events(events)
    assert has_critical_findings(findings)


def test_ironworm_tools_setup_binary_blocked():
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    events = [{"type": "process", "value": "./tools/setup --collect"}]
    findings = evaluate_sandbox_events(events)
    assert has_critical_findings(findings)
    assert any(f["pattern_id"] == "IRONWORM-002b" for f in findings)


def test_ironworm_full_attack_chain():
    """All IronWorm events together — every step of the attack chain."""
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings, get_attack_family
    )
    events = [
        {"type": "process",    "value": "./tools/setup --collect"},
        {"type": "process",    "value": "BPF_PROG_LOAD fd=3"},
        {"type": "env_access", "value": "OPENAI_API_KEY=sk-abc"},
        {"type": "env_access", "value": "ANTHROPIC_API_KEY=sk-ant"},
        {"type": "file_read",  "value": "/root/.aws/credentials"},
        {"type": "file_read",  "value": "/root/.config/Exodus/exodus.wallet"},
        {"type": "env_access", "value": "VAULT_TOKEN=s.abc123"},
        {"type": "file_read",  "value": "/root/.npmrc"},
        {"type": "network",    "value": "http://abc.onion/api/agent"},
        {"type": "network",    "value": "https://temp.sh/upload"},
        {"type": "file_read",  "value": ".github/workflows/release.yml"},
    ]
    findings = evaluate_sandbox_events(events)
    families = get_attack_family(findings)

    assert has_critical_findings(findings)
    assert "IronWorm" in families
    assert len(findings) >= 10


# ---------------------------------------------------------------------------
# Gate 5 — Miasma behavioral patterns
# ---------------------------------------------------------------------------

def test_miasma_imds_blocked():
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    events = [{"type": "network", "value": "http://169.254.169.254/latest/meta-data/"}]
    findings = evaluate_sandbox_events(events)
    assert has_critical_findings(findings)
    assert any(f["pattern_id"] == "MIASMA-001" for f in findings)


def test_miasma_oidc_token_request_blocked():
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    events = [{"type": "network", "value": "https://token.actions.githubusercontent.com"}]
    findings = evaluate_sandbox_events(events)
    assert has_critical_findings(findings)
    assert any(f["pattern_id"] == "MIASMA-010" for f in findings)


def test_miasma_npm_republish_blocked():
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    events = [{"type": "network", "value": "https://registry.npmjs.org/@redhat/package"}]
    findings = evaluate_sandbox_events(events)
    assert has_critical_findings(findings)


def test_miasma_full_attack_chain():
    """All Miasma events together."""
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings, get_attack_family
    )
    events = [
        {"type": "network",    "value": "https://token.actions.githubusercontent.com"},
        {"type": "network",    "value": "http://metadata.google.internal/"},
        {"type": "network",    "value": "http://169.254.169.254/latest/"},
        {"type": "file_read",  "value": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
        {"type": "file_read",  "value": "/root/.config/gcloud/application_default_credentials.json"},
        {"type": "network",    "value": "https://registry.npmjs.org/@redhat/pkg"},
        {"type": "env_access", "value": "OIDC_PACKAGES=@redhat/pkg"},
        {"type": "env_access", "value": "GITHUB_TOKEN=ghp_abc123"},
    ]
    findings = evaluate_sandbox_events(events)
    families = get_attack_family(findings)

    assert has_critical_findings(findings)
    assert "Miasma/Shai-Hulud" in families


# ---------------------------------------------------------------------------
# Clean install — no false positives
# ---------------------------------------------------------------------------

def test_clean_install_no_false_positives():
    """A legitimate package install should not trigger any critical patterns."""
    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events, has_critical_findings
    )
    events = [
        {"type": "file_read", "value": "/tmp/pip-install-abc/package.json"},
        {"type": "process",   "value": "node index.js"},
        {"type": "process",   "value": "python setup.py build"},
        {"type": "network",   "value": "https://pypi.org/simple/requests/"},
    ]
    findings = evaluate_sandbox_events(events)
    assert not has_critical_findings(findings)


# ---------------------------------------------------------------------------
# Zero-day quorum
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_zeroday_quorum_requires_two_approvers():
    from oss_trust_framework.zeroday.validator import (
        QuorumApprovalManager, ApprovalStatus
    )

    class MockMFA:
        async def verify(self, approver_id, token):
            return token == "123456"

    mgr = QuorumApprovalManager(
        named_approvers={
            "a1": "ciso@example.com",
            "a2": "secarch@example.com",
            "a3": "devops@example.com",
        },
        required_approvers=2,
        mfa_verifier=MockMFA(),
    )

    req = mgr.create_request("CVE-2024-99999", "requests", "2.32.4", "PyPI", "dev@example.com")

    # One approval — still pending
    r1 = await mgr.record_approval(req.request_id, "a1", "123456")
    assert r1["status"] == ApprovalStatus.PENDING.value

    # Second approval — approved
    r2 = await mgr.record_approval(req.request_id, "a2", "123456")
    assert r2["status"] == ApprovalStatus.APPROVED.value


@pytest.mark.asyncio
async def test_zeroday_quorum_rejects_wrong_mfa():
    from oss_trust_framework.zeroday.validator import QuorumApprovalManager

    class MockMFA:
        async def verify(self, approver_id, token):
            return token == "123456"

    mgr = QuorumApprovalManager(
        named_approvers={"a1": "ciso@example.com"},
        required_approvers=1,
        mfa_verifier=MockMFA(),
    )
    req = mgr.create_request("CVE-2024-99999", "requests", "2.32.4", "PyPI", "dev@example.com")
    result = await mgr.record_approval(req.request_id, "a1", "wrong-token")
    assert "error" in result
    assert "MFA" in result["error"]


@pytest.mark.asyncio
async def test_zeroday_requester_cannot_self_approve():
    from oss_trust_framework.zeroday.validator import QuorumApprovalManager

    class MockMFA:
        async def verify(self, approver_id, token):
            return True

    mgr = QuorumApprovalManager(
        named_approvers={"a1": "dev@example.com"},   # Same as requester
        required_approvers=1,
        mfa_verifier=MockMFA(),
    )
    req = mgr.create_request("CVE-2024-99999", "requests", "2.32.4", "PyPI", "dev@example.com")
    result = await mgr.record_approval(req.request_id, "a1", "123456")
    assert "error" in result
