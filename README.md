# oss-trust-demo

A test application for exercising the [OSS Trust Framework](https://github.com/chrisgillham/oss-trust-framework) — a multi-gate supply chain security pipeline that defends against active attack campaigns including Miasma, Shai-Hulud, and IronWorm.

---

## What this repo does

- Validates Python dependencies against all framework gates (age, out-of-band trust, behavioral sandbox)
- Runs 6 interactive demo scenarios covering every major attack class and framework capability
- Checks all packages in `requirements.txt` and `framework_deps.txt` with an interactive allowlist builder
- Provides a 131-test suite covering every gate and the full zero-day quorum lifecycle — all offline

---

## Prerequisites

The framework is not yet published to PyPI. Install it from the source repo first:

```powershell
# Windows
pip install -e "C:\path\to\oss-trust-framework"

# Mac/Linux
pip install -e /path/to/oss-trust-framework
```

Then install demo dependencies:

```powershell
pip install rich click pytest pytest-asyncio pyyaml
```

Verify:

```powershell
oss-trust --version
# oss-trust, version 0.2.0
```

---

## Quick start

```powershell
# Clone this repo
git clone https://github.com/YOUR_ORG/oss-trust-demo
cd oss-trust-demo

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Mac/Linux

# Install framework from local source
pip install -e "C:\Users\chris\Github Repositories\oss-trust-framework"
pip install rich click pytest pytest-asyncio pyyaml

# Run all 6 demo scenarios
python src/demo.py

# Run a specific scenario
python src/demo.py --scenario ironworm
python src/demo.py --scenario miasma
python src/demo.py --scenario zeroday

# Check all dependencies in requirements.txt and framework_deps.txt
python check_all.py

# Run the full test suite (131 tests, all offline)
pytest
```

---

## Demo scenarios

| # | Scenario | Package / Input | Expected outcome | What it demonstrates |
|---|---|---|---|---|
| 1 | Standard pipeline | `requests 2.33.0` | APPROVED | Full gate pipeline against live PyPI + OSV data |
| 2 | CVE-affected package | `pillow 9.0.0` | QUARANTINE | Gate 3 catching 14 active CVEs from live OSV query |
| 3 | Age gate | Synthetic (6h old) | BLOCKED | 24-hour hard block in action |
| 4 | IronWorm patterns | Synthetic sandbox events | BLOCKED | All 13 IronWorm attack events matched by Gate 5 |
| 5 | Miasma patterns | Synthetic sandbox events | BLOCKED | All 8 Miasma attack events matched by Gate 5 |
| 6 | Zero-day lane | Mock CVE + quorum | APPROVED | Full MFA quorum workflow — wrong token rejected, duplicate vote rejected, 2-of-3 approved |

Run individually:

```powershell
python src/demo.py --scenario standard
python src/demo.py --scenario cve
python src/demo.py --scenario age
python src/demo.py --scenario ironworm
python src/demo.py --scenario miasma
python src/demo.py --scenario zeroday
```

---

## Dependency checking

`check_all.py` checks every package in `requirements.txt` and `framework_deps.txt` against Gate 1 (age) and Gate 3 (out-of-band trust), then interactively offers to add unlisted packages to your publisher allowlist.

```powershell
python check_all.py
```

At the end of each run, for every package showing `NOT IN ALLOWLIST`:

```
  ============================================================
  ALLOWLIST UPDATE
  ============================================================
  3 package(s) are not in your trusted publisher allowlist.

  Would you like to update the allowlist now? [y/n]: y

    Package 'httpx' is not in your trusted publisher allowlist.
    Looking up canonical GitHub repo...
    Found: github.com/encode/httpx

    Options for 'httpx':
      [1] Add to allowlist (Gate 2 repo verification)
      [2] Add to allowlist AND require_attestation (strongest protection)
      [3] Skip (accept current risk for this package)

    Choice for 'httpx' [1/2/3]: 2
```

Option 2 adds the package to both the allowlist and `require_attestation` — meaning a missing or mismatched provenance attestation is a BLOCK rather than a QUARANTINE.

To check the framework's own dependencies, create `framework_deps.txt`:

```
httpx==0.28.1
pyyaml==6.0.3
click==8.1.8
pydantic==2.13.4
pyotp==2.9.0
cryptography==48.0.0
rich==15.0.0
```

Then run `python check_all.py` — both files are checked automatically if present.

**Real-world example from this repo:** `requests 2.32.3` was flagged with 2 active CVEs:
- `GHSA-9hjg-9r4m-mvj7` — `.netrc` credentials leak (fixed in 2.32.4)
- `GHSA-gc5v-m9x4-r6x2` — insecure temp file reuse (fixed in 2.33.0)

Upgrading to `2.33.0` cleared both findings. This is the framework doing its job.

---

## Test suite

131 tests across 7 files — all run offline with mocked API calls:

```powershell
# Full suite
pytest

# Individual files
pytest tests/test_gate1_age.py        # 11 tests — age threshold boundaries
pytest tests/test_gate3_trust.py      # 6 tests  — OOB trust, source resilience
pytest tests/test_gate5_behavioral.py # 50 tests — all 34 named patterns individually
pytest tests/test_zeroday_lane.py     # 23 tests — full quorum lifecycle
pytest tests/test_integration.py      # 10 tests — cross-gate and regression tests
pytest tests/test_check_all.py        # 13 tests — dependency check utilities
pytest tests/test_scenarios.py        # 18 tests — original demo scenarios

# With coverage
pytest --cov=. --cov-report=term-missing
```

### Test coverage summary

| Area | Tests | Key scenarios covered |
|---|---|---|
| Gate 1 — Age | 11 | Hard block at 1h/23h; hold at 24h/48h/71h; pass at 73h/7d; custom thresholds |
| Gate 3 — Trust | 6 | Clean pass; CVE quarantine; low score quarantine; source failure resilience |
| Gate 5 — Behavioral | 50 | Every named pattern individually; both attack chains; clean install false-positive prevention |
| Zero-day lane | 23 | Full quorum: create/approve/approve→approved; wrong MFA; duplicate vote; expiry; self-approval blocked |
| Integration | 10 | Old+clean clears G1+G3; new blocked at G1 regardless of trust; ZD approval + sandbox in sequence |
| Utilities | 13 | Requirements parsing; allowlist save/reload; result aggregation logic |

---

## Files

```
oss-trust-demo/
├── src/
│   └── demo.py                 # 6 interactive demo scenarios
├── tests/
│   ├── conftest.py             # Shared fixtures (quorum manager, attack event chains)
│   ├── test_gate1_age.py       # Gate 1 age threshold tests
│   ├── test_gate3_trust.py     # Gate 3 OOB trust tests
│   ├── test_gate5_behavioral.py # Gate 5 all 34 pattern tests
│   ├── test_zeroday_lane.py    # Zero-day quorum tests
│   ├── test_integration.py     # Cross-gate integration tests
│   ├── test_check_all.py       # Dependency checker utility tests
│   └── test_scenarios.py       # Original scenario tests
├── config/
│   └── trusted_publishers.yaml # Publisher allowlist (populated by check_all.py)
├── check_all.py                # Interactive dependency checker + allowlist manager
├── framework_deps.txt          # Framework's own dependencies to check
├── requirements.txt            # Demo app dependencies
├── pytest.ini                  # Test configuration
└── pyproject.toml
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'oss_trust_framework'`**
The framework venv and demo venv are separate. Run:
```powershell
pip install -e "C:\Users\chris\Github Repositories\oss-trust-framework"
```
from inside the demo repo's activated venv.

**`oss-trust --version` shows wrong version**
The version is hardcoded in `oss_trust_framework/pipeline/cli.py`. Check it matches `pyproject.toml`, then reinstall.

**Gate 3 returns QUARANTINE for a package you expect to pass**
Run the OSV query directly to see what's flagged:
```powershell
python -c "
import urllib.request, json
data = json.dumps({'version':'VERSION','package':{'name':'PACKAGE','ecosystem':'PyPI'}}).encode()
req = urllib.request.Request('https://api.osv.dev/v1/query', data=data, headers={'Content-Type':'application/json'})
print(json.loads(urllib.request.urlopen(req).read()))
"
```
Then check which version fixes the CVEs and upgrade.

---

## Related

- [OSS Trust Framework](https://github.com/chrisgillham/oss-trust-framework) — the framework this demo exercises
- [IronWorm analysis — JFrog](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)
- [Miasma analysis — devops.com](https://devops.com/shai-hulud-clone-miasma-compromises-32-red-hat-npm-packages/)
