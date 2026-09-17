import os
os.environ['FIM_PATHS'] = 'README.md'
import fim
import time

print("Initializing baseline...")
fim.init_baseline()

print("Modifying file...")
with open('README.md', 'a') as f:
    f.write('\nFIM_TRIGGER_EVENT')

print("Checking integrity...")
changes = fim.check_integrity()
print(f"Changes found: {changes}")
for c in changes:
    fim.report_fim_change(c)
