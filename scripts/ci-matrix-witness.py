#!/usr/bin/env python3
"""Opt-in hosted matrix witness: hang lib, fail bins, delegate other suites."""
import os
from pathlib import Path
import shutil


if __name__ == "__main__":
    cargo = shutil.which("cargo")
    if cargo is None:
        raise SystemExit("cargo missing")
    directory = Path(os.environ["RUNNER_TEMP"]) / "matrix-witness-bin"
    directory.mkdir()
    shim = directory / "cargo"
    shim.write_text(f'''#!/usr/bin/env python3
import os
import sys
import time
args = sys.argv[1:]
if args[:3] == ["test", "--locked", "--lib"]:
    print("test deliberately_hanging_matrix_suite ...", flush=True)
    time.sleep(600)
    raise SystemExit(99)
if args[:3] == ["test", "--locked", "--bins"]:
    print("test deliberately_failing_matrix_suite ... FAILED", flush=True)
    raise SystemExit(42)
os.execv({cargo!r}, [{cargo!r}, *args])
''')
    shim.chmod(0o755)
    with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as output:
        print(directory, file=output)
