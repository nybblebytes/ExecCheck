"""Fail CI if built distributions contain machine-local generated files."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path


FORBIDDEN_PARTS = {
    ".DS_Store",
    ".venv",
    "venv",
    "env",
    ".virtualenv",
    "pyvenv.cfg",
    "site-packages",
}


def members(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            return archive.getnames()
    return []


def main() -> int:
    distribution_directory = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    distributions = sorted(distribution_directory.iterdir())
    if not distributions:
        raise SystemExit("No distributions found")
    for distribution in distributions:
        for member in members(distribution):
            parts = set(Path(member).parts)
            forbidden = parts & FORBIDDEN_PARTS
            if forbidden:
                raise SystemExit(
                    f"{distribution.name} contains forbidden path {member!r}: "
                    f"{sorted(forbidden)}"
                )
    print(f"Verified {len(distributions)} distribution files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
