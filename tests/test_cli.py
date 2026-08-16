import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_sbom.cli import main


class CliTests(unittest.TestCase):
    def test_scan_command_writes_bundle(self):
        corpus = Path(__file__).parent / "fixtures" / "corpus"
        with tempfile.TemporaryDirectory() as temp:
            code = main(["scan", str(corpus), "--out", temp])
            self.assertEqual(code, 0)
            self.assertTrue((Path(temp) / "report.html").exists())

    def test_invalid_root_returns_two(self):
        self.assertEqual(main(["scan", "definitely-does-not-exist"]), 2)

    def test_demo_does_not_depend_on_repository_examples(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "demo"
            code = main(["demo", "--out", str(output)])
            self.assertEqual(code, 0)
            artifact = (output / "agent-sbom.json").read_text(encoding="utf-8")
            self.assertIn('"name": "agent-sbom-demo"', artifact)
            self.assertIn('"network"', artifact)

    def test_diff_rejects_malformed_artifacts_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(json.dumps([]), encoding="utf-8")
            after.write_text(json.dumps({}), encoding="utf-8")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                code = main(["diff", str(before), str(after)])
            self.assertEqual(code, 2)
            self.assertIn("must be a JSON object", errors.getvalue())
            self.assertNotIn("Traceback", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
