# oss-trust-demo

A minimal test application for exercising the [OSS Trust Framework](https://github.com/chrisgillham/oss-trust-framework).

This repo simulates a real project that:
- Has Python dependencies that need trust validation
- Uses the `oss-trust` CLI to check packages before installing them
- Runs the full gate pipeline including age check, out-of-band trust, and behavioral pattern matching
- Demonstrates the zero-day expedited lane workflow

---

## Quick start

```bash
# Clone this repo
git clone https://github.com/YOUR_ORG/oss-trust-demo
cd oss-trust-demo

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Mac/Linux

# Install the framework
pip install oss-trust-framework

# Install demo app dependencies
pip install -r requirements.txt

# Run a trust check against a known-good package
oss-trust check --package requests --version 2.32.3 --ecosystem PyPI --github-repo psf/requests

# Run all demo scenarios
python src/demo.py
```

---

## What each demo scenario tests

| Scenario | Package | Expected outcome | Gate triggered |
|---|---|---|---|
| Known-good package | `requests 2.32.3` | APPROVED | All pass |
| Package with active CVE | `pillow 9.0.0` | QUARANTINE | Gate 3 (OSV) |
| Simulate age block | any package < 24 h | BLOCKED | Gate 1 |
| Simulate IronWorm patterns | synthetic events | BLOCKED | Gate 5 |
| Simulate Miasma patterns | synthetic events | BLOCKED | Gate 5 |
| Zero-day lane demo | mock CVE | PENDING_QUORUM | ZD lane |
