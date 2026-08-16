import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from agent_sbom.reporting import markdown_report, write_bundle
from agent_sbom.scanner import cyclonedx, diff_artifacts, sarif, scan, validate_artifact


ROOT = Path(__file__).parent
CORPUS = ROOT / "fixtures" / "corpus"


class ScannerTests(unittest.TestCase):
    def test_finds_capabilities_with_evidence(self):
        artifact = scan(str(CORPUS))
        capabilities = artifact["summary"]["capabilities"]
        self.assertIn("credential", capabilities)
        self.assertIn("network", capabilities)
        self.assertIn("process", capabilities)
        self.assertIn("destructive", capabilities)
        self.assertTrue(all("path" in finding and "line" in finding for finding in artifact["findings"]))
        self.assertFalse(any("super-secret-value" in finding["evidence"] for finding in artifact["findings"]))

    def test_output_is_deterministic_and_relative(self):
        first = scan(str(CORPUS))
        second = scan(str(CORPUS))
        self.assertEqual(first, second)
        self.assertEqual(first["subject"]["root"], ".")
        self.assertFalse(any(str(CORPUS) in item["path"] for item in first["components"]))

    def test_diff_reports_new_capability(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.py").write_text(
                "from pathlib import Path\nPath('input').read_text()\n", encoding="utf-8"
            )
            before = scan(str(root))
            (root / "a.py").write_text(
                "import subprocess\nsubprocess.run(['true'])\n", encoding="utf-8"
            )
            (root / "b.sh").write_text("echo stable\n", encoding="utf-8")
            after = scan(str(root))
            result = diff_artifacts(before, after)
            self.assertEqual(result["added_components"], ["b.sh"])
            self.assertEqual(result["changed_components"], ["a.py"])
            self.assertEqual(result["added_capabilities"], ["process"])
            self.assertGreaterEqual(result["summary"]["introduced_findings"], 1)

    def test_diff_rejects_malformed_or_wrong_version_artifacts(self):
        with self.assertRaisesRegex(ValueError, "JSON object"):
            validate_artifact([], "before artifact")
        artifact = scan(str(CORPUS))
        artifact["schema_version"] = "agent-sbom/v999"
        with self.assertRaisesRegex(ValueError, "schema_version"):
            diff_artifacts(artifact, artifact)

    def test_nested_artifact_shape_errors_are_always_controlled(self):
        artifact = scan(str(CORPUS))
        malformed_values = []
        relationship = copy.deepcopy(artifact)
        relationship["relationships"][0]["from"] = []
        malformed_values.append(relationship)
        severity = copy.deepcopy(artifact)
        severity["findings"][0]["severity"] = {}
        malformed_values.append(severity)
        missing_relationship = copy.deepcopy(artifact)
        missing_relationship["relationships"] = []
        malformed_values.append(missing_relationship)
        for malformed in malformed_values:
            with self.subTest(value=malformed):
                with self.assertRaises(ValueError):
                    validate_artifact(malformed)

    def test_standard_outputs_have_expected_shape(self):
        artifact = scan(str(CORPUS))
        bom = cyclonedx(artifact)
        result = sarif(artifact)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.6")
        self.assertEqual(result["version"], "2.1.0")
        self.assertGreater(len(result["runs"][0]["results"]), 0)

    def test_bundle_contains_json_markdown_html_and_checksums(self):
        artifact = scan(str(CORPUS))
        with tempfile.TemporaryDirectory() as temp:
            output = write_bundle(artifact, temp)
            for name in ("agent-sbom.json", "bom.cdx.json", "findings.sarif", "report.md", "report.html", "checksums.sha256"):
                self.assertTrue((output / name).is_file(), name)
            parsed = json.loads((output / "agent-sbom.json").read_text(encoding="utf-8"))
            self.assertEqual(parsed["schema_version"], "agent-sbom/v1")

    def test_symbolic_links_are_never_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "secret.py").write_text(
                'password = "outside-secret-value"\n', encoding="utf-8"
            )
            try:
                (root / "linked.py").symlink_to(outside / "secret.py")
                (root / "linked-dir").symlink_to(outside, target_is_directory=True)
                root_link = base / "root-link"
                root_link.symlink_to(root, target_is_directory=True)
            except (NotImplementedError, OSError) as exc:
                self.skipTest("symbolic links are unavailable: %s" % exc)
            artifact = scan(str(root))
            self.assertEqual(artifact["summary"]["files"], 0)
            self.assertFalse(any("outside-secret-value" in str(item) for item in artifact["findings"]))
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                scan(str(root_link))

    def test_non_regular_files_are_skipped_without_opening(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFOs are unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            os.mkfifo(str(root / "blocked.py"))
            artifact = scan(str(root))
            self.assertEqual(artifact["summary"]["files"], 0)

    def test_type_arrows_and_comparisons_are_not_write_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "types.ts").write_text(
                "const select = (value: number): number => value > 1 ? value : 1;\n"
                "const compatible = version >= 2;\n",
                encoding="utf-8",
            )
            (root / "redirect.sh").write_text("echo result > output.txt\n", encoding="utf-8")
            artifact = scan(str(root))
            write_paths = {
                finding["path"]
                for finding in artifact["findings"]
                if finding["rule"] == "capability/write"
            }
            self.assertEqual(write_paths, {"redirect.sh"})

    def test_large_file_is_truncated_but_fully_stream_hashed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            content = b"a" * 1_000_001
            path = root / "large.txt"
            path.write_bytes(content)
            artifact = scan(str(root))
            component = next(item for item in artifact["components"] if item["path"] == "large.txt")
            self.assertTrue(component["truncated"])
            self.assertEqual(component["size"], len(content))
            self.assertEqual(component["sha256"], hashlib.sha256(content).hexdigest())

    def test_markdown_report_neutralizes_untrusted_values(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "evil` | forged |\n\n## Injected heading.py"
            path.write_text(
                "password = 'short' # ` <img src=x onerror=alert(1)>\n",
                encoding="utf-8",
            )
            report = markdown_report(scan(str(root)))
            self.assertNotIn("## Injected heading", report)
            self.assertNotIn("<img", report)
            self.assertNotIn("| forged |", report)
            self.assertIn("&#96;", report)


if __name__ == "__main__":
    unittest.main()
