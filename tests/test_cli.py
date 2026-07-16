import contextlib
import io
import unittest
from pathlib import Path

from agent_tool_audit.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class TestCli(unittest.TestCase):
    def test_scan_clean_exits_zero(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["scan", str(FIXTURES / "clean_mcp.json")])
        self.assertEqual(code, 0)
        self.assertIn("grade A", buf.getvalue())

    def test_scan_fail_under_trips_on_risky_config(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["scan", str(FIXTURES / "risky_mcp.json"), "--fail-under", "80"])
        self.assertEqual(code, 1)

    def test_scan_missing_file_exits_nonzero(self):
        errbuf = io.StringIO()
        with contextlib.redirect_stderr(errbuf):
            code = main(["scan", str(FIXTURES / "does-not-exist.json")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
