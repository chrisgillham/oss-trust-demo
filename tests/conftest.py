"""
Shared pytest configuration and fixtures for the OSS Trust Demo test suite.
"""

import pytest
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def make_release_time():
    """Factory fixture for creating release timestamps relative to now."""
    def _make(hours_ago: float) -> datetime:
        return datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return _make


@pytest.fixture
def good_mfa():
    """MFA verifier that accepts token '123456'."""
    class GoodMFA:
        async def verify(self, approver_id: str, token: str) -> bool:
            return token == "123456"
    return GoodMFA()


@pytest.fixture
def always_mfa():
    """MFA verifier that always accepts."""
    class AlwaysMFA:
        async def verify(self, approver_id: str, token: str) -> bool:
            return True
    return AlwaysMFA()


@pytest.fixture
def standard_approvers():
    return {
        "approver_001": "ciso@example.com",
        "approver_002": "secarch@example.com",
        "approver_003": "devsecops@example.com",
    }


@pytest.fixture
def quorum_manager(standard_approvers, good_mfa):
    from oss_trust_framework.zeroday.validator import QuorumApprovalManager
    return QuorumApprovalManager(
        named_approvers=standard_approvers,
        required_approvers=2,
        mfa_verifier=good_mfa,
    )


@pytest.fixture
def ironworm_events():
    """Full IronWorm attack event chain."""
    return [
        {"type": "process",    "value": "./tools/setup --collect"},
        {"type": "process",    "value": "BPF_PROG_LOAD fd=3 flags=0"},
        {"type": "env_access", "value": "OPENAI_API_KEY=sk-abc123def456"},
        {"type": "env_access", "value": "ANTHROPIC_API_KEY=sk-ant-xyz789"},
        {"type": "file_read",  "value": "/root/.aws/credentials"},
        {"type": "file_read",  "value": "/root/.ssh/id_rsa"},
        {"type": "file_read",  "value": "/root/.config/Exodus/exodus.wallet"},
        {"type": "env_access", "value": "VAULT_TOKEN=s.abc123def456xyz"},
        {"type": "file_read",  "value": "/root/.npmrc"},
        {"type": "env_access", "value": "NPM_AUTH_TOKEN=npm_abc123"},
        {"type": "network",    "value": "http://abc123def456789.onion/api/agent"},
        {"type": "network",    "value": "https://temp.sh/upload/secrets.enc"},
        {"type": "file_read",  "value": ".github/workflows/release.yml"},
    ]


@pytest.fixture
def miasma_events():
    """Full Miasma attack event chain."""
    return [
        {"type": "network",    "value": "https://token.actions.githubusercontent.com"},
        {"type": "network",    "value": "http://metadata.google.internal/computeMetadata/v1/"},
        {"type": "network",    "value": "http://169.254.169.254/latest/meta-data/iam/"},
        {"type": "file_read",  "value": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
        {"type": "file_read",  "value": "/root/.config/gcloud/application_default_credentials.json"},
        {"type": "network",    "value": "https://registry.npmjs.org/@redhat-cloud-services/frontend-components"},
        {"type": "env_access", "value": "OIDC_PACKAGES=@redhat-cloud-services/frontend-components"},
        {"type": "env_access", "value": "GITHUB_TOKEN=ghp_abc123def456"},
    ]


@pytest.fixture
def clean_events():
    """Legitimate package install events — should produce no critical findings."""
    return [
        {"type": "file_read", "value": "/tmp/pip-install-abc/package.json"},
        {"type": "process",   "value": "python setup.py build"},
        {"type": "network",   "value": "https://pypi.org/simple/requests/"},
    ]
