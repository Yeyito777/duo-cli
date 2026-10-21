from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

BIN = Path(__file__).resolve().parents[1] / "bin" / "duo"


class LauncherTests(unittest.TestCase):
    def test_caller_working_directory_cannot_shadow_cli_modules(self) -> None:
        # A caller cwd holding a `src` package must never be imported by duo.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            marker = root / "imported"
            (root / "src" / "__init__.py").write_text(f"open({str(marker)!r}, 'w').close()\n")
            result = subprocess.run([str(BIN), "requests", "--help"], cwd=root, capture_output=True, text=True, timeout=60)
            self.assertFalse(marker.exists(), "caller cwd src package was imported")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage: duo requests", result.stdout)


if __name__ == "__main__":
    unittest.main()
