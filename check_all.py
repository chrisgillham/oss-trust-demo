# -*- coding: utf-8 -*-
import asyncio
import os
import sys
import json
import urllib.request
import yaml


# ---------------------------------------------------------------------------
# Package checking
# ---------------------------------------------------------------------------

async def check_package(name, version, repo=None):
    from oss_trust_framework.age_check.checker import check_release_age
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    results = {}

    try:
        age = await check_release_age(name, version, "PyPI")
        results["age"] = age.decision.value
        results["age_hours"] = round(age.age_hours)
    except Exception as e:
        results["age"] = f"error: {e}"

    try:
        trust = await aggregate_trust_score(
            package=name, version=version, ecosystem="PyPI", github_repo=repo
        )
        results["trust"] = trust.recommendation
        results["score"] = trust.composite_score
        results["vulns"] = trust.known_vulns
        results["vuln_ids"] = trust.vuln_ids
    except Exception as e:
        results["trust"] = f"error: {e}"

    return results


def parse_requirements(filepath):
    packages = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "==" in line:
                name, version = line.split("==", 1)
                packages.append((name.strip(), version.strip()))
    return packages


def lookup_canonical_repo(package_name):
    """Query PyPI for the canonical GitHub repo URL."""
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        resp = urllib.request.urlopen(url, timeout=10)
        data = json.loads(resp.read())
        info = data.get("info", {})
        urls = info.get("project_urls") or {}

        for key in ["Source", "Repository", "Source Code", "GitHub", "Homepage"]:
            val = urls.get(key) or ""
            if not val:
                val = info.get("home_page") or ""
            if val and "github.com" in val:
                parts = val.rstrip("/").replace("https://github.com/", "").replace("http://github.com/", "")
                parts = parts.split("/")
                if len(parts) >= 2:
                    return f"{parts[0]}/{parts[1]}"
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Allowlist management
# ---------------------------------------------------------------------------

PUBLISHERS_FILE = "config/trusted_publishers.yaml"


def load_publishers():
    if not os.path.exists(PUBLISHERS_FILE):
        return {"PyPI": {}, "npm": {}, "Cargo": {}, "require_attestation": {"PyPI": [], "npm": []}}
    with open(PUBLISHERS_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def save_publishers(data):
    os.makedirs("config", exist_ok=True)
    with open(PUBLISHERS_FILE, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def add_to_allowlist(publishers, package_name, repo):
    if "PyPI" not in publishers:
        publishers["PyPI"] = {}
    publishers["PyPI"][package_name] = repo
    save_publishers(publishers)
    print(f"    Added to allowlist: \"{package_name}\": \"{repo}\"")


def add_to_require_attestation(publishers, package_name):
    if "require_attestation" not in publishers:
        publishers["require_attestation"] = {}
    if "PyPI" not in publishers["require_attestation"]:
        publishers["require_attestation"]["PyPI"] = []
    if package_name not in publishers["require_attestation"]["PyPI"]:
        publishers["require_attestation"]["PyPI"].append(package_name)
    save_publishers(publishers)
    print(f"    Added to require_attestation: {package_name}")


def prompt_for_allowlist(package_name, publishers):
    """Interactively offer to add a package to the allowlist."""
    print(f"\n    Package '{package_name}' is not in your trusted publisher allowlist.")
    print(f"    Looking up canonical GitHub repo...")

    repo = lookup_canonical_repo(package_name)
    if repo:
        print(f"    Found: github.com/{repo}")
    else:
        print(f"    Could not auto-detect repo. You can enter it manually.")

    print()
    print(f"    Options for '{package_name}':")
    print(f"      [1] Add to allowlist (Gate 2 repo verification)")
    if repo:
        print(f"          -> will add \"{package_name}\": \"{repo}\"")
    else:
        print(f"          -> you will be prompted to enter the repo")
    print(f"      [2] Add to allowlist AND require_attestation (strongest protection)")
    print(f"          -> missing attestation = BLOCK, repo mismatch = BLOCK")
    print(f"      [3] Skip (accept current risk for this package)")
    print()

    while True:
        choice = input(f"    Choice for '{package_name}' [1/2/3]: ").strip()

        if choice == "1":
            if not repo:
                repo = input(f"    Enter GitHub repo (owner/repo): ").strip()
            if repo:
                add_to_allowlist(publishers, package_name, repo)
            break

        elif choice == "2":
            if not repo:
                repo = input(f"    Enter GitHub repo (owner/repo): ").strip()
            if repo:
                add_to_allowlist(publishers, package_name, repo)
                add_to_require_attestation(publishers, package_name)
            break

        elif choice == "3":
            print(f"    Skipped '{package_name}' - not added to allowlist.")
            break

        else:
            print(f"    Please enter 1, 2, or 3.")

    return publishers


# ---------------------------------------------------------------------------
# Group checking
# ---------------------------------------------------------------------------

async def check_group(label, packages, pypi_publishers):
    print(f"  {'=' * 60}")
    print(f"  {label} ({len(packages)} packages)")
    print(f"  {'=' * 60}")

    approved = []
    warned = []
    not_in_allowlist = []

    for name, version in packages:
        repo = pypi_publishers.get(name)
        r = await check_package(name, version, repo)

        age_ok = r.get("age") == "pass"
        trust_ok = r.get("trust") == "PASS"
        overall = "APPROVED" if age_ok and trust_ok else "REVIEW"

        if overall == "APPROVED":
            approved.append(name)
        else:
            warned.append(name)

        if not repo:
            not_in_allowlist.append(name)

        icon = "v" if overall == "APPROVED" else "!"
        repo_str = f"repo: {repo}" if repo else "repo: NOT IN ALLOWLIST"

        print(f"  [{icon}] {name}=={version}")
        print(f"         Age   : {r.get('age')} ({r.get('age_hours', '?')}h old)")
        print(f"         Trust : {r.get('trust')}  score={r.get('score', '?')}  vulns={r.get('vulns', '?')}")
        print(f"         {repo_str}")
        if r.get("vuln_ids"):
            for vid in r["vuln_ids"]:
                print(f"         CVE   : {vid}")
        print()

    return approved, warned, not_in_allowlist


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    publishers = load_publishers()

    groups = []

    if os.path.exists("requirements.txt"):
        pkgs = parse_requirements("requirements.txt")
        if pkgs:
            groups.append(("Demo app - requirements.txt", pkgs))

    if os.path.exists("framework_deps.txt"):
        pkgs = parse_requirements("framework_deps.txt")
        if pkgs:
            groups.append(("Framework dependencies - framework_deps.txt", pkgs))

    if not groups:
        print("No requirements.txt or framework_deps.txt found.")
        return

    total = sum(len(g[1]) for g in groups)
    print()
    print("  OSS Trust Framework - Dependency Check")
    print(f"  Checking {total} packages across {len(groups)} file(s)")
    print()

    all_approved = []
    all_warned = []
    all_not_in_allowlist = []

    for label, packages in groups:
        approved, warned, not_in_allowlist = await check_group(
            label, packages, publishers.get("PyPI", {})
        )
        all_approved.extend(approved)
        all_warned.extend(warned)
        all_not_in_allowlist.extend(not_in_allowlist)
        print()

    # Summary
    print(f"  {'=' * 60}")
    print("  OVERALL SUMMARY")
    print(f"  {'=' * 60}")
    print(f"  Approved          : {len(all_approved)}")
    print(f"  Need review       : {len(all_warned)}")
    print(f"  Not in allowlist  : {len(all_not_in_allowlist)}")
    print(f"  Total             : {total}")

    if all_warned:
        print()
        print("  Packages needing review (CVEs or trust issues):")
        for name in all_warned:
            print(f"    - {name}")

    # Interactive allowlist prompt
    if all_not_in_allowlist:
        print()
        print(f"  {'=' * 60}")
        print("  ALLOWLIST UPDATE")
        print(f"  {'=' * 60}")
        print(f"  {len(all_not_in_allowlist)} package(s) are not in your trusted publisher allowlist.")
        print("  Adding packages strengthens Gate 2 (publisher repo verification).")
        print()

        update = input("  Would you like to update the allowlist now? [y/n]: ").strip().lower()

        if update == "y":
            publishers = load_publishers()
            for name in all_not_in_allowlist:
                if name not in publishers.get("PyPI", {}):
                    publishers = prompt_for_allowlist(name, publishers)
                    print()

            print()
            print(f"  Allowlist saved to {PUBLISHERS_FILE}")
            print("  Run python check_all.py again to verify all packages pass.")
        else:
            print()
            print("  Allowlist unchanged. Run python check_all.py again at any time to update.")

    print()


asyncio.run(main())
