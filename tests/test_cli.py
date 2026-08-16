import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_sbom.cli import main
from agent_sbom.reporting import stable_json
from agent_sbom.scanner import scan


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

    def test_diff_refuses_to_follow_output_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subject = root / "subject"
            subject.mkdir()
            (subject / "safe.py").write_text("value = 1\n", encoding="utf-8")
            artifact = stable_json(scan(str(subject)))
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(artifact, encoding="utf-8")
            after.write_text(artifact, encoding="utf-8")
            victim = root / "victim.txt"
            victim.write_text("sentinel", encoding="utf-8")
            output = root / "diff.json"
            try:
                output.symlink_to(victim)
            except (NotImplementedError, OSError) as exc:
                self.skipTest("symbolic links are unavailable: %s" % exc)
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                code = main(["diff", str(before), str(after), "--out", str(output)])
            self.assertEqual(code, 2)
            self.assertEqual(victim.read_text(encoding="utf-8"), "sentinel")


if __name__ == "__main__":
    unittest.main()
