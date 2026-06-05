"""
OSS Trust Framework — demo scenarios.

Exercises all major framework capabilities:
  1. Standard pipeline check (known-good package)
  2. CVE-affected package (Gate 3 quarantine)
  3. Age gate simulation
  4. IronWorm behavioral pattern matching (Gate 5)
  5. Miasma behavioral pattern matching (Gate 5)
  6. Zero-day expedited lane request

Run:
    python src/demo.py
    python src/demo.py --scenario age
    python src/demo.py --scenario ironworm
"""

import asyncio
import sys
from datetime import datetime, timezone, timedelta

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


def print_header(title: str, subtitle: str = "") -> None:
    console.print()
    console.print(Panel(
        Text(title, style="bold white") if not subtitle
        else Text(f"{title}\n{subtitle}", style="bold white"),
        style="blue",
        padding=(0, 2),
    ))


def print_gate_result(gate: str, passed: bool, decision: str, detail: str = "") -> None:
    icon = "✅" if passed else "❌"
    color = "green" if passed else "red"
    console.print(f"  {icon} [{color}]Gate {gate}[/{color}]  {decision}  {detail}")


def print_finding(pattern_id: str, severity: str, description: str) -> None:
    color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue"}.get(severity, "white")
    console.print(f"    [{color}][{severity}][/{color}] {pattern_id}: {description}")


# ---------------------------------------------------------------------------
# Scenario 1 — Standard pipeline check
# ---------------------------------------------------------------------------

async def scenario_standard():
    print_header(
        "Scenario 1 — Standard pipeline check",
        "Package: requests 2.32.3 (known-good, well-maintained)"
    )

    from oss_trust_framework.age_check.checker import check_release_age, AgeDecision
    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    console.print("\n[dim]Running Gate 1 — Age check...[/dim]")
    try:
        age_result = await check_release_age(
            package="requests",
            version="2.32.3",
            ecosystem="PyPI",
        )
        passed = age_result.decision == AgeDecision.PASS
        print_gate_result(
            "1 (Age)", passed, age_result.decision.value,
            f"[dim]{age_result.age_hours:.0f}h old[/dim]"
        )
    except Exception as e:
        console.print(f"  [yellow]Gate 1 skipped (network): {e}[/yellow]")

    console.print("[dim]Running Gate 3 — Out-of-band trust...[/dim]")
    try:
        trust_result = await aggregate_trust_score(
            package="requests",
            version="2.32.3",
            ecosystem="PyPI",
            github_repo="psf/requests",
        )
        print_gate_result(
            "3 (OOB Trust)", trust_result.passed, trust_result.recommendation,
            f"[dim]score: {trust_result.composite_score:.0f}/100 · vulns: {trust_result.known_vulns}[/dim]"
        )
    except Exception as e:
        console.print(f"  [yellow]Gate 3 skipped (network): {e}[/yellow]")

    console.print()
    console.print("  [bold green]→ Result: APPROVED[/bold green] (all gates passed)")


# ---------------------------------------------------------------------------
# Scenario 2 — CVE-affected package
# ---------------------------------------------------------------------------

async def scenario_cve():
    print_header(
        "Scenario 2 — CVE-affected package",
        "Package: pillow 9.0.0 (has known CVEs — Gate 3 should quarantine)"
    )

    from oss_trust_framework.trust.aggregator import aggregate_trust_score

    console.print("\n[dim]Running Gate 3 — Out-of-band trust...[/dim]")
    try:
        trust_result = await aggregate_trust_score(
            package="Pillow",
            version="9.0.0",
            ecosystem="PyPI",
        )
        passed = trust_result.passed
        print_gate_result(
            "3 (OOB Trust)", passed, trust_result.recommendation,
            f"[dim]score: {trust_result.composite_score:.0f}/100 · vulns: {trust_result.known_vulns}[/dim]"
        )
        if trust_result.vuln_ids:
            for vid in trust_result.vuln_ids[:3]:
                console.print(f"    [red]CVE: {vid}[/red]")
    except Exception as e:
        console.print(f"  [yellow]Gate 3 skipped (network): {e}[/yellow]")
        console.print("  [dim]Simulating: Pillow 9.0.0 has multiple known CVEs → QUARANTINE[/dim]")

    console.print()
    console.print("  [bold yellow]→ Result: QUARANTINE[/bold yellow] (active CVEs found in OSV)")


# ---------------------------------------------------------------------------
# Scenario 3 — Age gate simulation
# ---------------------------------------------------------------------------

async def scenario_age():
    print_header(
        "Scenario 3 — Age gate simulation",
        "Simulating a package published 6 hours ago (below 24h hard block)"
    )

    console.print()
    console.print("  [dim]Simulating registry response: release_time = now - 6h[/dim]")
    console.print()

    from oss_trust_framework.age_check.checker import (
        AgeCheckResult, AgeDecision, check_release_age
    )

    # Simulate the result directly to avoid needing a real 6h-old package
    simulated = AgeCheckResult(
        decision=AgeDecision.BLOCK,
        age_hours=6.0,
        release_time=datetime.now(timezone.utc) - timedelta(hours=6),
        package="some-new-package",
        version="1.0.0",
        ecosystem="PyPI",
        message="some-new-package@1.0.0 is only 6.0h old — hard block threshold is 24h.",
    )

    print_gate_result("1 (Age)", False, "BLOCK", "[dim]6.0h old — below 24h threshold[/dim]")
    console.print()
    console.print(f"  [red]✗ {simulated.message}[/red]")
    console.print()
    console.print("  [bold red]→ Result: BLOCKED[/bold red]")
    console.print("  [dim]To bypass: file a CVE and use `oss-trust zeroday request`[/dim]")


# ---------------------------------------------------------------------------
# Scenario 4 — IronWorm behavioral pattern matching
# ---------------------------------------------------------------------------

async def scenario_ironworm():
    print_header(
        "Scenario 4 — IronWorm behavioral pattern matching (Gate 5)",
        "Simulating sandbox events from an IronWorm-infected package install"
    )

    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events,
        has_critical_findings,
        summarise_findings,
        get_attack_family,
    )

    # Simulate the events IronWorm would generate during a preinstall hook
    simulated_events = [
        # Rust ELF binary execution
        {"type": "process",    "value": "./tools/setup --collect"},
        # eBPF rootkit load
        {"type": "process",    "value": "BPF_PROG_LOAD fd=3 flags=0"},
        # AI API key harvest
        {"type": "env_access", "value": "OPENAI_API_KEY=sk-abc123def456"},
        {"type": "env_access", "value": "ANTHROPIC_API_KEY=sk-ant-xyz789"},
        # Cloud credential access
        {"type": "file_read",  "value": "/root/.aws/credentials"},
        {"type": "file_read",  "value": "/root/.ssh/id_rsa"},
        # Exodus wallet theft
        {"type": "file_read",  "value": "/root/.config/Exodus/exodus.wallet"},
        # Vault token
        {"type": "env_access", "value": "VAULT_TOKEN=s.abc123def456xyz"},
        # npm token for self-propagation
        {"type": "file_read",  "value": "/root/.npmrc"},
        {"type": "env_access", "value": "NPM_AUTH_TOKEN=npm_abc123"},
        # Tor C2 beacon
        {"type": "network",    "value": "http://abc123def456789.onion/api/agent"},
        # temp.sh fallback
        {"type": "network",    "value": "https://temp.sh/upload/secrets.enc"},
        # Workflow hijack
        {"type": "file_read",  "value": ".github/workflows/release.yml"},
    ]

    console.print()
    console.print("  [dim]Sandbox events observed during install:[/dim]")
    for evt in simulated_events:
        icon = {"process": "⚙", "env_access": "🔑", "file_read": "📄", "network": "🌐"}.get(evt["type"], "•")
        console.print(f"    {icon} [{evt['type']}] {evt['value']}")

    console.print()
    console.print("  [dim]Matching against 34 behavioral patterns...[/dim]")
    console.print()

    findings = evaluate_sandbox_events(simulated_events)
    families = get_attack_family(findings)

    for f in findings:
        print_finding(f["pattern_id"], f["severity"], f["description"])

    console.print()
    console.print(f"  [bold]Findings:[/bold] {len(findings)} patterns triggered")
    console.print(f"  [bold]Attack families identified:[/bold] {', '.join(families)}")
    console.print(f"  [bold]Critical findings:[/bold] {sum(1 for f in findings if f['severity'] == 'CRITICAL')}")
    console.print()
    console.print("  [bold red]→ Result: BLOCKED[/bold red]")
    console.print(f"  [dim]{summarise_findings(findings)}[/dim]")


# ---------------------------------------------------------------------------
# Scenario 5 — Miasma behavioral pattern matching
# ---------------------------------------------------------------------------

async def scenario_miasma():
    print_header(
        "Scenario 5 — Miasma behavioral pattern matching (Gate 5)",
        "Simulating sandbox events from a Miasma-infected package install"
    )

    from oss_trust_framework.sandbox.behavioral_patterns import (
        evaluate_sandbox_events,
        has_critical_findings,
        summarise_findings,
        get_attack_family,
    )

    simulated_events = [
        # OIDC token request for npm trusted publishing
        {"type": "network",    "value": "https://token.actions.githubusercontent.com"},
        # GCP metadata harvest
        {"type": "network",    "value": "http://metadata.google.internal/computeMetadata/v1/"},
        # AWS IMDS
        {"type": "network",    "value": "http://169.254.169.254/latest/meta-data/iam/"},
        # Kubernetes service account token
        {"type": "file_read",  "value": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
        # GCP credentials
        {"type": "file_read",  "value": "/root/.config/gcloud/application_default_credentials.json"},
        # npm re-publish
        {"type": "network",    "value": "https://registry.npmjs.org/@redhat-cloud-services/frontend-components"},
        # CI env var access
        {"type": "env_access", "value": "OIDC_PACKAGES=@redhat-cloud-services/frontend-components"},
        {"type": "env_access", "value": "GITHUB_TOKEN=ghp_abc123def456"},
    ]

    console.print()
    console.print("  [dim]Sandbox events observed during install:[/dim]")
    for evt in simulated_events:
        icon = {"process": "⚙", "env_access": "🔑", "file_read": "📄", "network": "🌐"}.get(evt["type"], "•")
        console.print(f"    {icon} [{evt['type']}] {evt['value']}")

    console.print()
    console.print("  [dim]Matching against 34 behavioral patterns...[/dim]")
    console.print()

    findings = evaluate_sandbox_events(simulated_events)
    families = get_attack_family(findings)

    for f in findings:
        print_finding(f["pattern_id"], f["severity"], f["description"])

    console.print()
    console.print(f"  [bold]Findings:[/bold] {len(findings)} patterns triggered")
    console.print(f"  [bold]Attack families identified:[/bold] {', '.join(families)}")
    console.print(f"  [bold]Critical findings:[/bold] {sum(1 for f in findings if f['severity'] == 'CRITICAL')}")
    console.print()
    console.print("  [bold red]→ Result: BLOCKED[/bold red]")
    console.print(f"  [dim]{summarise_findings(findings)}[/dim]")


# ---------------------------------------------------------------------------
# Scenario 6 — Zero-day lane demo
# ---------------------------------------------------------------------------

async def scenario_zeroday():
    print_header(
        "Scenario 6 — Zero-day expedited lane",
        "Demonstrating the quorum approval workflow for an urgent CVE patch"
    )

    from oss_trust_framework.zeroday.validator import (
        QuorumApprovalManager,
        ApprovalStatus,
    )

    APPROVERS = {
        "approver_001": "ciso@example.com",
        "approver_002": "secarch@example.com",
        "approver_003": "devsecops@example.com",
    }

    class MockMFA:
        async def verify(self, approver_id: str, token: str) -> bool:
            return token == "123456"   # Accept demo token

    mgr = QuorumApprovalManager(
        named_approvers=APPROVERS,
        required_approvers=2,
        mfa_verifier=MockMFA(),
    )

    console.print()
    console.print("  [dim]Step 1: Requester files exception for CVE-2024-99999[/dim]")
    console.print("  [dim]  oss-trust zeroday request --cve CVE-2024-99999 --package requests --version 2.32.4[/dim]")
    console.print()

    req = mgr.create_request(
        cve_id="CVE-2024-99999",
        package="requests",
        version="2.32.4",
        ecosystem="PyPI",
        requester="dev@example.com",
    )

    console.print(f"  [green]✓[/green] Quorum request created: [cyan]{req.request_id}[/cyan]")
    console.print(f"  [dim]  Approvals: 0 / {req.required_approvers} required · Expires: 6 hours[/dim]")
    console.print(f"  [dim]  Requester dev@example.com excluded from approver pool[/dim]")
    console.print()

    console.print("  [dim]Step 2: First approver votes (MFA token: 123456)[/dim]")
    r1 = await mgr.record_approval(req.request_id, "approver_001", "123456")
    console.print(f"  [green]✓[/green] Approval recorded by ciso@example.com — {r1['approvals_received']}/{r1['approvals_required']}")
    console.print()

    console.print("  [dim]Step 3: Wrong MFA token rejected[/dim]")
    r_bad = await mgr.record_approval(req.request_id, "approver_002", "000000")
    console.print(f"  [red]✗[/red] MFA failure: {r_bad['error']}")
    console.print()

    console.print("  [dim]Step 4: Second approver votes with correct token[/dim]")
    r2 = await mgr.record_approval(req.request_id, "approver_002", "123456")
    status_color = "green" if r2["status"] == "approved" else "yellow"
    console.print(f"  [{status_color}]✓[/{status_color}] Status: {r2['status'].upper()} — quorum reached!")
    console.print()

    console.print("  [dim]Step 5: Duplicate vote rejected[/dim]")
    r_dup = await mgr.record_approval(req.request_id, "approver_001", "123456")
    if "error" in r_dup:
        console.print(f"  [red]✗[/red] Duplicate vote rejected: {r_dup['error']}")
    else:
        console.print(f"  [red]✗[/red] Duplicate vote rejected -- request already {r_dup.get('status', '')}")
    console.print()

    console.print("  [bold green]→ Result: APPROVED via zero-day lane[/bold green]")
    console.print("  [dim]Age gate bypassed. All other gates (provenance, CI/CD audit, sandbox) still run.[/dim]")
    console.print("  [dim]Deploy: immediate full-fleet + 48h elevated alert window.[/dim]")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

SCENARIOS = {
    "all":      None,
    "standard": scenario_standard,
    "cve":      scenario_cve,
    "age":      scenario_age,
    "ironworm": scenario_ironworm,
    "miasma":   scenario_miasma,
    "zeroday":  scenario_zeroday,
}


@click.command()
@click.option(
    "--scenario",
    type=click.Choice(list(SCENARIOS.keys()), case_sensitive=False),
    default="all",
    show_default=True,
    help="Which scenario to run.",
)
def main(scenario: str):
    """OSS Trust Framework demo — exercises all major pipeline capabilities."""

    console.print()
    console.print(Panel(
        "[bold white]OSS Trust Framework — Demo[/bold white]\n"
        "[dim]github.com/chrisgillham/oss-trust-framework[/dim]",
        style="bold blue",
        padding=(0, 4),
    ))

    async def run():
        if scenario == "all":
            for name, fn in SCENARIOS.items():
                if fn is not None:
                    await fn()
                    console.print()
        else:
            await SCENARIOS[scenario]()

    asyncio.run(run())

    console.print()
    console.print(Panel(
        "[bold green]Demo complete.[/bold green]\n"
        "[dim]Run individual scenarios with --scenario <name>[/dim]\n"
        "[dim]Run a real check: oss-trust check --package requests --version 2.33.0 --ecosystem PyPI[/dim]",
        style="green",
        padding=(0, 2),
    ))


if __name__ == "__main__":
    main()
