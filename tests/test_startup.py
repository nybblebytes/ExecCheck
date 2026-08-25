import subprocess
import sys


def test_module_help_imports_successfully():
    result = subprocess.run(
        [sys.executable, "-m", "execcheck", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "--db" in result.stdout
    assert "--output-format" in result.stdout
