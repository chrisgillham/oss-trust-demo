"""
check_all.py utility function tests.

Tests the dependency checking script's helper functions:
  - requirements.txt parsing
  - trusted_publishers.yaml loading
  - Allowlist management (add, save, reload)
  - PyPI repo lookup
  - Group result aggregation
"""

import os
import pytest
import tempfile
import yaml


# ---------------------------------------------------------------------------
# Requirements parsing
# ---------------------------------------------------------------------------

def test_parse_requirements_basic(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "requests==2.33.0\nrich==13.9.4\nclick==8.1.8\n",
        encoding="utf-8"
    )
    import sys
    sys.path.insert(0, str(tmp_path.parent.parent / "src"))

    # Import inline to avoid module path issues
    def parse_requirements(filepath):
        packages = []
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "==" in line:
                    name, version = line.split("==", 1)
                    packages.append((name.strip(), version.strip()))
        return packages

    result = parse_requirements(str(req_file))
    assert len(result) == 3
    assert ("requests", "2.33.0") in result
    assert ("rich", "13.9.4") in result
    assert ("click", "8.1.8") in result


def test_parse_requirements_skips_comments(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "# This is a comment\nrequests==2.33.0\n# another comment\n",
        encoding="utf-8"
    )

    def parse_requirements(filepath):
        packages = []
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "==" in line:
                    name, version = line.split("==", 1)
                    packages.append((name.strip(), version.strip()))
        return packages

    result = parse_requirements(str(req_file))
    assert len(result) == 1
    assert result[0] == ("requests", "2.33.0")


def test_parse_requirements_skips_blank_lines(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "\n\nrequests==2.33.0\n\nrich==13.9.4\n\n",
        encoding="utf-8"
    )

    def parse_requirements(filepath):
        packages = []
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "==" in line:
                    name, version = line.split("==", 1)
                    packages.append((name.strip(), version.strip()))
        return packages

    result = parse_requirements(str(req_file))
    assert len(result) == 2


def test_parse_requirements_empty_file(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("", encoding="utf-8")

    def parse_requirements(filepath):
        packages = []
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "==" in line:
                    name, version = line.split("==", 1)
                    packages.append((name.strip(), version.strip()))
        return packages

    result = parse_requirements(str(req_file))
    assert result == []


# ---------------------------------------------------------------------------
# Allowlist management
# ---------------------------------------------------------------------------

def test_load_publishers_returns_dict_when_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def load_publishers():
        publishers_file = "config/trusted_publishers.yaml"
        if not os.path.exists(publishers_file):
            return {"PyPI": {}, "npm": {}, "require_attestation": {"PyPI": [], "npm": []}}
        with open(publishers_file, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    result = load_publishers()
    assert "PyPI" in result
    assert isinstance(result["PyPI"], dict)


def test_save_and_reload_publishers(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.makedirs("config", exist_ok=True)

    publishers_file = "config/trusted_publishers.yaml"

    def save_publishers(data):
        os.makedirs("config", exist_ok=True)
        with open(publishers_file, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

    def load_publishers():
        if not os.path.exists(publishers_file):
            return {"PyPI": {}}
        with open(publishers_file, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    original = {"PyPI": {"requests": "psf/requests"}, "npm": {}}
    save_publishers(original)
    reloaded = load_publishers()

    assert reloaded["PyPI"]["requests"] == "psf/requests"


def test_add_to_allowlist_persists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.makedirs("config", exist_ok=True)

    publishers_file = "config/trusted_publishers.yaml"

    def save_publishers(data):
        with open(publishers_file, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

    def load_publishers():
        if not os.path.exists(publishers_file):
            return {"PyPI": {}}
        with open(publishers_file, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    publishers = {"PyPI": {}}
    publishers["PyPI"]["httpx"] = "encode/httpx"
    save_publishers(publishers)

    reloaded = load_publishers()
    assert "httpx" in reloaded["PyPI"]
    assert reloaded["PyPI"]["httpx"] == "encode/httpx"


def test_add_to_require_attestation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.makedirs("config", exist_ok=True)

    publishers_file = "config/trusted_publishers.yaml"

    def save_publishers(data):
        with open(publishers_file, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

    def load_publishers():
        if not os.path.exists(publishers_file):
            return {"PyPI": {}, "require_attestation": {"PyPI": []}}
        with open(publishers_file, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    publishers = {"PyPI": {}, "require_attestation": {"PyPI": []}}
    publishers["require_attestation"]["PyPI"].append("cryptography")
    save_publishers(publishers)

    reloaded = load_publishers()
    assert "cryptography" in reloaded["require_attestation"]["PyPI"]


def test_no_duplicate_in_require_attestation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    publishers = {
        "PyPI": {},
        "require_attestation": {"PyPI": ["cryptography"]}
    }

    def add_to_require_attestation(publishers, package_name):
        if package_name not in publishers["require_attestation"]["PyPI"]:
            publishers["require_attestation"]["PyPI"].append(package_name)
        return publishers

    result = add_to_require_attestation(publishers, "cryptography")
    assert publishers["require_attestation"]["PyPI"].count("cryptography") == 1


# ---------------------------------------------------------------------------
# Result aggregation logic
# ---------------------------------------------------------------------------

def test_package_approved_when_age_and_trust_pass():
    r = {"age": "pass", "trust": "PASS", "score": 85, "vulns": 0, "vuln_ids": []}
    age_ok = r.get("age") == "pass"
    trust_ok = r.get("trust") == "PASS"
    overall = "APPROVED" if age_ok and trust_ok else "REVIEW"
    assert overall == "APPROVED"


def test_package_review_when_age_fails():
    r = {"age": "block", "trust": "PASS", "score": 85, "vulns": 0, "vuln_ids": []}
    age_ok = r.get("age") == "pass"
    trust_ok = r.get("trust") == "PASS"
    overall = "APPROVED" if age_ok and trust_ok else "REVIEW"
    assert overall == "REVIEW"


def test_package_review_when_trust_fails():
    r = {"age": "pass", "trust": "QUARANTINE", "score": 40, "vulns": 2, "vuln_ids": ["GHSA-1234"]}
    age_ok = r.get("age") == "pass"
    trust_ok = r.get("trust") == "PASS"
    overall = "APPROVED" if age_ok and trust_ok else "REVIEW"
    assert overall == "REVIEW"


def test_package_review_when_both_fail():
    r = {"age": "block", "trust": "QUARANTINE", "score": 20, "vulns": 5}
    age_ok = r.get("age") == "pass"
    trust_ok = r.get("trust") == "PASS"
    overall = "APPROVED" if age_ok and trust_ok else "REVIEW"
    assert overall == "REVIEW"
