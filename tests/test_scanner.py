import unittest
from pathlib import Path

from agent_tool_audit.scanner import ConfigError, scan_file, score_to_grade

FIXTURES = Path(__file__).parent / "fixtures"


class TestScanner(unittest.TestCase):
    def test_clean_mcp_config_grades_a(self):
        report = scan_file(FIXTURES / "clean_mcp.json")
        self.assertEqual(len(report.tools), 1)
        self.assertEqual(report.overall_grade, "A")

    def test_risky_mcp_config_flags_everything(self):
        report = scan_file(FIXTURES / "risky_mcp.json")
        self.assertEqual(len(report.tools), 3)
        by_name = {t.name: t for t in report.tools}

        delete_ids = {f.rule_id for f in by_name["delete_files"].findings}
        self.assertIn("OVERRIDE_LANGUAGE", delete_ids)
        self.assertIn("BROAD_SCOPE_LANGUAGE", delete_ids)
        self.assertIn("SENSITIVE_NAME", delete_ids)

        fetch_ids = {f.rule_id for f in by_name["fetch_notes"].findings}
        self.assertIn("MISSING_DESCRIPTION", fetch_ids)

        email_ids = {f.rule_id for f in by_name["send_email"].findings}
        self.assertIn("SECRET_IN_DESCRIPTION", email_ids)

        self.assertLess(report.overall_score, 80)
        self.assertEqual(by_name["delete_files"].grade, "D")
        self.assertEqual(by_name["send_email"].grade, "B")

    def test_openai_style_tool_list_parses(self):
        report = scan_file(FIXTURES / "openai_style.json")
        self.assertEqual(len(report.tools), 1)
        self.assertEqual(report.tools[0].name, "search_docs")
        self.assertEqual(report.overall_grade, "A")

    def test_bad_shape_raises(self):
        import json
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"nope": True}, f)
            path = Path(f.name)
        try:
            with self.assertRaises(ConfigError):
                scan_file(path)
        finally:
            path.unlink()

    def test_score_to_grade_boundaries(self):
        self.assertEqual(score_to_grade(90), "A")
        self.assertEqual(score_to_grade(89), "B")
        self.assertEqual(score_to_grade(75), "B")
        self.assertEqual(score_to_grade(59), "D")
        self.assertEqual(score_to_grade(39), "F")


if __name__ == "__main__":
    unittest.main()
