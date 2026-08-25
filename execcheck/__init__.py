"""ExecCheck: macOS ExecPolicy analysis utilities."""

import sys


if sys.version_info < (3, 10):
    detected = ".".join(str(part) for part in sys.version_info[:3])
    raise RuntimeError(
        "ExecCheck requires Python 3.10 or newer. "
        f"Detected Python {detected}."
    )

__all__ = []
