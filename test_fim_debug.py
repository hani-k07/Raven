import os
os.environ['FIM_PATHS'] = 'README.md'
import fim
import hashlib

def get_hash(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

print(f"Hash 1: {get_hash('README.md')}")
fim.init_baseline()
with open('README.md', 'a') as f:
    f.write('\nTRIGGER')
print(f"Hash 2: {get_hash('README.md')}")
print(f"Changes: {fim.check_integrity()}")
