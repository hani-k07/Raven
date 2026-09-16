# Contributing to RAVEN 2.0

Thank you for your interest in RAVEN 2.0! To maintain the high forensic integrity of the system, we follow a strict contribution process.

## 🛠 Contribution Workflow

1. **Feature Branching**: Always create a new branch for your feature or fix:
   `git checkout -b feature/your-feature-name`
2. **Local Testing**: Ensure all existing tests pass before submitting:
   `python -m pytest -v`
3. **Documentation**: Update the `README.md` or relevant module docstrings if you change the system behavior.
4. **Pull Requests**: Submit a clear PR describing the change and providing evidence of its efficacy.

## 🛡 The Data Integrity Guarantee

RAVEN 2.0 is a forensic tool. Its credibility depends on the fact that **every threat record originates from real detection**.

**The Golden Rule:**
Do not implement any path that allows manual or synthetic insertion of records into the `threats` table. 

All new detection capabilities must be implemented within the authorized pipeline:
- `log_parser.py`
- `fim.py`
- `honeypot.py`
- `process_monitor.py`

Any PR that introduces a manual injection path (even for "testing" purposes) will be rejected. Use the "Real Pipeline Testing Guide" in `SECURITY.md` to validate your changes.

## ⚖️ License
This project is licensed under the MIT License.
