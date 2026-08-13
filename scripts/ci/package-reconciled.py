#!/usr/bin/env python3
"""Package what `cargo xtask reconcile` changed, for the privileged job.

Runs in the *unprivileged* regeneration job. Produces a directory holding a
manifest and a copy of every changed file, so the job that can write to the
repository never has to inspect a git working tree it did not create.

The manifest is the interface between the two jobs, and it is deliberately
boring: one `status<TAB>path` line per change, `M` for present and `D` for
deleted. Deriving the change set here, where the regeneration happened, is what
lets the committing job reject anything that is not on it.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys


def changes() -> list[tuple[str, str]]:
    """`(status, path)` for every change in the working tree, NUL-delimited.

    `-z` because a path with a space in it must not become two paths; the
    generated names have none today, and relying on that is how it stops being
    true later.
    """
    out = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z"],
        check=True, capture_output=True, text=True,
    ).stdout
    result = []
    for record in out.split("\0"):
        if len(record) <= 3:
            continue
        path = record[3:]
        result.append(("D" if not pathlib.Path(path).is_file() else "M", path))
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: package-reconciled.py <output-dir>", file=sys.stderr)
        return 2
    out = pathlib.Path(sys.argv[1])
    (out / "files").mkdir(parents=True, exist_ok=True)

    found = changes()
    if not found:
        print("nothing changed; no package written")
        return 0

    lines = []
    for status, path in found:
        lines.append(f"{status}\t{path}")
        if status == "M":
            dest = out / "files" / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
    (out / "MANIFEST").write_text("\n".join(lines) + "\n")
    print(f"packaged {len(found)} change(s):")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
