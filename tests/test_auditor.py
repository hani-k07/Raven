import pytest
import os
from auditor import run_audit

def test_run_audit_basic(temp_db):
    # run_audit() usually writes to the DB. We check if it runs without crashing.
    # Since it performs real system checks (e.g. check for files), it should be safe to run in sandbox.
    try:
        run_audit()
    except Exception as e:
        pytest.fail(f"run_audit raised exception: {e}")
