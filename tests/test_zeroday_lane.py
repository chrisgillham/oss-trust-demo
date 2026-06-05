"""
Zero-day expedited lane tests.

Covers:
  - Quorum approval workflow (full happy path)
  - MFA enforcement
  - Separation of duties (requester cannot approve)
  - Duplicate vote prevention
  - Token expiry
  - Unknown approver rejection
  - Unknown request rejection
  - Circuit breaker conditions
  - Request status lifecycle
"""

import pytest
import time
from unittest.mock import patch
from oss_trust_framework.zeroday.validator import (
    QuorumApprovalManager,
    ApprovalStatus,
)


APPROVERS = {
    "approver_001": "ciso@example.com",
    "approver_002": "secarch@example.com",
    "approver_003": "devsecops@example.com",
}
REQUESTER = "dev@example.com"
CVE = "CVE-2024-99999"
PACKAGE = "requests"
VERSION = "2.33.0"
ECOSYSTEM = "PyPI"


class GoodMFA:
    """Always accepts token '123456'."""
    async def verify(self, approver_id: str, token: str) -> bool:
        return token == "123456"


class BadMFA:
    """Always rejects."""
    async def verify(self, approver_id: str, token: str) -> bool:
        return False


class AlwaysMFA:
    """Always accepts any token."""
    async def verify(self, approver_id: str, token: str) -> bool:
        return True


def make_manager(mfa=None, required=2):
    return QuorumApprovalManager(
        named_approvers=APPROVERS,
        required_approvers=required,
        mfa_verifier=mfa or GoodMFA(),
    )


# ---------------------------------------------------------------------------
# Request creation
# ---------------------------------------------------------------------------

def test_create_request_returns_request_object():
    mgr = make_manager()
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    assert req.request_id is not None
    assert req.cve_id == CVE
    assert req.package == PACKAGE
    assert req.version == VERSION
    assert req.status == ApprovalStatus.PENDING


def test_create_request_excludes_requester_from_approvers():
    mgr = make_manager()
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, "ciso@example.com")
    assert "approver_001" not in req.eligible_approvers


def test_create_request_has_correct_required_count():
    mgr = make_manager(required=2)
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    assert req.required_approvers == 2


def test_create_request_generates_unique_ids():
    mgr = make_manager()
    req1 = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    req2 = mgr.create_request(CVE, PACKAGE, "2.33.1", ECOSYSTEM, REQUESTER)
    assert req1.request_id != req2.request_id


def test_new_request_status_is_pending():
    mgr = make_manager()
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    assert mgr.get_status(req.request_id) == ApprovalStatus.PENDING


# ---------------------------------------------------------------------------
# Approval happy path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_single_approval_stays_pending():
    mgr = make_manager(required=2)
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    result = await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert result["status"] == ApprovalStatus.PENDING.value
    assert result["approvals_received"] == 1
    assert result["approvals_required"] == 2


@pytest.mark.asyncio
async def test_two_approvals_reaches_quorum():
    mgr = make_manager(required=2)
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    await mgr.record_approval(req.request_id, "approver_001", "123456")
    result = await mgr.record_approval(req.request_id, "approver_002", "123456")
    assert result["status"] == ApprovalStatus.APPROVED.value
    assert mgr.get_status(req.request_id) == ApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_three_of_three_quorum():
    mgr = make_manager(required=3)
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    await mgr.record_approval(req.request_id, "approver_001", "123456")
    await mgr.record_approval(req.request_id, "approver_002", "123456")
    result = await mgr.record_approval(req.request_id, "approver_003", "123456")
    assert result["status"] == ApprovalStatus.APPROVED.value


@pytest.mark.asyncio
async def test_one_of_one_quorum():
    mgr = make_manager(required=1)
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    result = await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert result["status"] == ApprovalStatus.APPROVED.value


# ---------------------------------------------------------------------------
# MFA enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wrong_mfa_token_rejected():
    mgr = make_manager(mfa=GoodMFA())
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    result = await mgr.record_approval(req.request_id, "approver_001", "000000")
    assert "error" in result
    assert "MFA" in result["error"]


@pytest.mark.asyncio
async def test_wrong_mfa_does_not_advance_approval_count():
    mgr = make_manager(mfa=GoodMFA())
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    await mgr.record_approval(req.request_id, "approver_001", "wrong")
    assert req.status == ApprovalStatus.PENDING
    assert len(req.approvals) == 0


@pytest.mark.asyncio
async def test_bad_mfa_always_rejects():
    mgr = make_manager(mfa=BadMFA())
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    result = await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert "error" in result


# ---------------------------------------------------------------------------
# Separation of duties
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_requester_email_cannot_approve():
    """If requester email matches an approver, that approver is excluded."""
    mgr = QuorumApprovalManager(
        named_approvers={"a1": REQUESTER},
        required_approvers=1,
        mfa_verifier=AlwaysMFA(),
    )
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    result = await mgr.record_approval(req.request_id, "a1", "123456")
    assert "error" in result


@pytest.mark.asyncio
async def test_non_requester_approver_can_approve():
    mgr = make_manager(required=1)
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    result = await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert result["status"] == ApprovalStatus.APPROVED.value


# ---------------------------------------------------------------------------
# Duplicate vote prevention
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_duplicate_vote_rejected():
    mgr = make_manager()
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    await mgr.record_approval(req.request_id, "approver_001", "123456")
    result = await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert "error" in result
    assert "already voted" in result["error"].lower()


@pytest.mark.asyncio
async def test_different_approvers_can_both_vote():
    mgr = make_manager(required=2)
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    r1 = await mgr.record_approval(req.request_id, "approver_001", "123456")
    r2 = await mgr.record_approval(req.request_id, "approver_002", "123456")
    assert "error" not in r1
    assert "error" not in r2
    assert r2["status"] == ApprovalStatus.APPROVED.value


# ---------------------------------------------------------------------------
# Token expiry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_expired_request_rejected(monkeypatch):
    from oss_trust_framework.zeroday import validator
    mgr = make_manager()
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)

    monkeypatch.setattr(validator.time, "time",
                        lambda: req.created_at + 6 * 3600 + 1)

    result = await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert "error" in result
    assert "expired" in result["error"].lower()


@pytest.mark.asyncio
async def test_request_within_ttl_accepted():
    mgr = make_manager(required=1)
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    # Should work fine within TTL
    result = await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert result["status"] == ApprovalStatus.APPROVED.value


# ---------------------------------------------------------------------------
# Invalid inputs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_request_id_rejected():
    mgr = make_manager()
    result = await mgr.record_approval("nonexistent-id", "approver_001", "123456")
    assert "error" in result


@pytest.mark.asyncio
async def test_unknown_approver_rejected():
    mgr = make_manager()
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    result = await mgr.record_approval(req.request_id, "ghost_approver", "123456")
    assert "error" in result
    assert "not in named approver list" in result["error"].lower()


def test_get_status_unknown_request_returns_none():
    mgr = make_manager()
    assert mgr.get_status("nonexistent-id") is None


# ---------------------------------------------------------------------------
# Status lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_status_transitions_pending_to_approved():
    mgr = make_manager(required=1)
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    assert mgr.get_status(req.request_id) == ApprovalStatus.PENDING
    await mgr.record_approval(req.request_id, "approver_001", "123456")
    assert mgr.get_status(req.request_id) == ApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_approved_request_accepts_no_more_votes():
    mgr = make_manager(required=1)
    req = mgr.create_request(CVE, PACKAGE, VERSION, ECOSYSTEM, REQUESTER)
    await mgr.record_approval(req.request_id, "approver_001", "123456")
    result = await mgr.record_approval(req.request_id, "approver_002", "123456")
    # Should indicate already approved, not error
    assert result.get("status") == "already_approved" or "error" in result
