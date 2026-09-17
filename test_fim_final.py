import os
import sqlite3
from datetime import datetime
from pathlib import Path

# We must import config and set the env var BEFORE importing fim
# Or just monkeypatch fim.WATCHED_PATHS
import fim
fim.WATCHED_PATHS = ['README.md']

# 1. Clean DB
conn = sqlite3.connect('raven.db')
conn.execute('DELETE FROM fim_baseline')
conn.commit()
conn.close()

# 2. Init
fim.init_baseline()

# 3. Modify
with open('README.md', 'a') as f:
    f.write('\nFIM_TRIGGER_FINAL')

# 4. Check
changes = fim.check_integrity()
print(f"Changes: {changes}")
if changes:
    for c in changes:
        fim.report_fim_change(c)
