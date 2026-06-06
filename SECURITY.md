# Security Policy

## About this repository

`oss-trust-demo` is a test application and demonstration harness for the [OSS Trust Framework](https://github.com/chrisgillham/oss-trust-framework). It contains demo scenarios, a 131-test suite, and a dependency checking utility.

Security vulnerabilities in the **core framework** (gates, behavioral patterns, zero-day lane, provenance verification) should be reported to the [framework repository](https://github.com/chrisgillham/oss-trust-framework/security/advisories/new).

Vulnerabilities specific to this demo repository (CI/CD workflows, demo scripts, test utilities) should be reported here.

---

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (current) | ✅ Active support |

---

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

### Contact

**Chris Gillham**
📧 [chris@gillham.net](mailto:chris@gillham.net)

Please use the subject line: `[SECURITY] oss-trust-demo — <brief description>`

### GitHub Security Advisories (preferred)

1. Go to [Security Advisories](https://github.com/chrisgillham/oss-trust-demo/security/advisories/new)
2. Click **New draft security advisory**
3. Fill in the details — the report remains private until a fix is ready

---

## What to include in your report

- **Description** — a clear explanation of the vulnerability
- **Component** — which file is affected (e.g. `src/demo.py`, `check_all.py`, `.github/workflows/ci.yml`)
- **Impact** — what an attacker could achieve by exploiting it
- **Reproduction steps** — a minimal, reproducible example or proof of concept
- **Environment** — Python version, OS, framework version (`oss-trust --version`)
- **Suggested fix** — optional but appreciated

---

## Response timeline

| Milestone | Target |
|---|---|
| Acknowledgement of report | Within 48 hours |
| Initial triage and severity assessment | Within 5 business days |
| Fix development begins | Within 10 business days for Critical/High |
| Patch release | Coordinated with reporter |
| Public disclosure | After patch is available (maximum 90 days) |

---

## Scope

### In scope

- **CI/CD workflow vulnerabilities** — code injection, secret exfiltration, or privilege escalation in `.github/workflows/ci.yml` (e.g. user-controlled input interpolated into `run:` blocks — CWE-94)
- **`check_all.py` vulnerabilities** — path traversal, arbitrary file write, or command injection when processing `requirements.txt` or `trusted_publishers.yaml`
- **Demo script vulnerabilities** — in `src/demo.py` that could affect users running the demo in a production-adjacent environment
- **Dependency vulnerabilities** — known CVEs in demo dependencies (`rich`, `click`, `pyyaml`, `pytest`) that create meaningful risk for demo users
- **Test suite vulnerabilities** — weaknesses that could allow a malicious test payload to escape the test environment

### Out of scope

- Vulnerabilities in the OSS Trust Framework core — report those to [chrisgillham/oss-trust-framework](https://github.com/chrisgillham/oss-trust-framework/security/advisories/new)
- Vulnerabilities in packages the demo validates (e.g. `requests`, `pillow`) — report those to the relevant package maintainers
- Demo scenarios that intentionally simulate malicious behavior (Scenarios 4 and 5 deliberately inject attack event patterns — this is expected behavior)
- Theoretical attacks requiring attacker control of the local machine running the demo
- Missing security controls in stub gate implementations (`sbom/differ.py`, `sandbox/runner.py`) — these are explicitly documented as unimplemented

---

## Known security considerations for demo users

### Scenario 4 and 5 — synthetic attack events

Scenarios 4 (IronWorm) and 5 (Miasma) deliberately inject synthetic sandbox events representing malicious behavior. These events are processed entirely in memory by the behavioral pattern matcher — no actual malicious code executes. The events are string literals in `src/demo.py`.

### `check_all.py` — interactive allowlist management

`check_all.py` reads `requirements.txt` and `framework_deps.txt`, queries PyPI and OSV for each package, and writes to `config/trusted_publishers.yaml`. Ensure these files are not world-writable in shared environments.

### CI/CD workflow — GitHub Actions

The `ci.yml` workflow installs the OSS Trust Framework from GitHub source (`git+https://github.com/chrisgillham/oss-trust-framework.git`). If the framework repository were compromised, this installation step would pull malicious code. This is an inherent risk of installing from source — the framework's own pipeline gates are designed to detect exactly this class of attack.

---

## Coordinated disclosure

We follow coordinated disclosure:

1. Reporter submits vulnerability privately
2. We confirm receipt and begin investigation
3. We develop and test a fix
4. We coordinate a disclosure date (maximum 90 days from initial report)
5. We release the fix and publish a GitHub Security Advisory
6. Reporter may publish their own writeup after the fix is public

---

## Past advisories

| Advisory | Severity | Summary | Fixed in |
|---|---|---|---|
| — | — | No advisories to date | — |

Advisories published at:
`https://github.com/chrisgillham/oss-trust-demo/security/advisories`

---

## Related

- [OSS Trust Framework SECURITY.md](https://github.com/chrisgillham/oss-trust-framework/blob/main/SECURITY.md) — security policy for the core framework
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [GitHub Security Advisories documentation](https://docs.github.com/en/code-security/security-advisories)
