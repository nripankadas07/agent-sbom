import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_sbom import safeio
import agent_sbom.scanner as scanner
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

    def test_artifact_capabilities_require_matching_finding_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "safe.py").write_text("value = 1\n", encoding="utf-8")
            artifact = scan(str(root))
            component = next(item for item in artifact["components"] if item["path"] != ".")
            component["capabilities"] = ["network"]
            artifact["summary"]["capabilities"] = ["network"]
            with self.assertRaisesRegex(ValueError, "finding evidence"):
                validate_artifact(artifact)

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

    def test_bundle_rejects_output_symlinks_and_fifos_without_touching_targets(self):
        if not hasattr(os, "symlink") or not hasattr(os, "mkfifo"):
            self.skipTest("symbolic links and FIFOs are required")
        artifact = scan(str(CORPUS))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "output"
            output.mkdir()
            victim = root / "victim.txt"
            victim.write_text("sentinel", encoding="utf-8")
            (output / "report.md").symlink_to(victim)
            with self.assertRaisesRegex(ValueError, "non-regular"):
                write_bundle(artifact, str(output))
            self.assertEqual(victim.read_text(encoding="utf-8"), "sentinel")
            (output / "report.md").unlink()
            os.mkfifo(str(output / "report.md"))
            with self.assertRaisesRegex(ValueError, "non-regular"):
                write_bundle(artifact, str(output))
            real_output = root / "real-output"
            real_output.mkdir()
            linked_output = root / "linked-output"
            linked_output.symlink_to(real_output, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
                write_bundle(artifact, str(linked_output))

            victim_directory = root / "victim-directory"
            victim_directory.mkdir()
            attacker_link = root / "attacker-link"
            attacker_link.symlink_to(victim_directory, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
                write_bundle(artifact, str(attacker_link / "real-subdir"))
            self.assertFalse((victim_directory / "real-subdir").exists())

            relative_output = os.path.relpath(
                attacker_link / "relative-subdir", Path.cwd()
            )
            self.assertIn("..", Path(relative_output).parts)
            with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
                write_bundle(artifact, relative_output)
            self.assertFalse((victim_directory / "relative-subdir").exists())

            with mock.patch.object(
                safeio, "_supports_descriptor_relative_io", return_value=False
            ):
                with self.assertRaisesRegex(OSError, "descriptor-relative"):
                    write_bundle(artifact, str(attacker_link / "fallback-subdir"))
            self.assertFalse((victim_directory / "fallback-subdir").exists())

    def test_bundle_rolls_back_if_second_artifact_publication_fails(self):
        artifact = scan(str(CORPUS))
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            write_bundle(artifact, str(output))
            for path in output.iterdir():
                path.write_text("original:%s\n" % path.name, encoding="utf-8")
            original = {path.name: path.read_bytes() for path in output.iterdir()}

            real_rename = safeio._rename_at
            publications = 0

            def fail_second(directory_fd, source, target):
                nonlocal publications
                if ".tmp-" in source and not target.startswith("."):
                    publications += 1
                    if publications == 2:
                        raise OSError("injected second publication failure")
                return real_rename(directory_fd, source, target)

            with mock.patch.object(safeio, "_rename_at", side_effect=fail_second):
                with self.assertRaisesRegex(OSError, "second publication"):
                    write_bundle(artifact, str(output))

            restored = {path.name: path.read_bytes() for path in output.iterdir()}
            self.assertEqual(restored, original)
            self.assertFalse(
                any(".tmp-" in path.name or ".bak-" in path.name for path in output.iterdir())
            )

    def test_sarif_percent_encodes_paths_as_uri_references(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "risk#café.py").write_text(
                "https://example.invalid\n", encoding="utf-8"
            )
            result = sarif(scan(str(root)))
            uri = result["runs"][0]["results"][0]["locations"][0][
                "physicalLocation"
            ]["artifactLocation"]["uri"]
            self.assertEqual(uri, "risk%23caf%C3%A9.py")

    def test_control_and_noncanonical_artifact_paths_are_rejected(self):
        for filename in ("line\nbreak.py", "bidi\u202e.py"):
            with self.subTest(filename=repr(filename)):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    (root / filename).write_text("value = 1\n", encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "control"):
                        scan(str(root))

        artifact = scan(str(CORPUS))
        component_index = next(
            index
            for index, component in enumerate(artifact["components"])
            if component["path"] != "."
        )
        for path in ("../outside.py", "/absolute.py", "a//b.py", "a\\b.py"):
            malformed = copy.deepcopy(artifact)
            malformed["components"][component_index]["path"] = path
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "path"):
                    validate_artifact(malformed)

        unsupported = copy.deepcopy(artifact)
        unsupported["components"][component_index]["kind"] = "container"
        with self.assertRaisesRegex(ValueError, "kind"):
            validate_artifact(unsupported)

        project_capability = copy.deepcopy(artifact)
        project_capability["components"][0]["capabilities"] = ["network"]
        with self.assertRaisesRegex(ValueError, "project capabilities"):
            validate_artifact(project_capability)

        project_tool = copy.deepcopy(artifact)
        project_tool["components"][0]["declared_tools"] = ["forged"]
        with self.assertRaisesRegex(ValueError, "declared_tools"):
            validate_artifact(project_tool)

    def test_ancestor_directory_swap_cannot_escape_open_root(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "root"
            safe = root / "safe"
            outside = base / "outside"
            safe.mkdir(parents=True)
            outside.mkdir()
            (safe / "payload.py").write_text("value = 'inside'\n", encoding="utf-8")
            (outside / "payload.py").write_text(
                "password = 'outside-secret-value'\n", encoding="utf-8"
            )
            real_inspect = scanner._inspect_file_at
            swapped = False

            def swap_ancestor(directory_fd, name, relative, before, limit=1_000_000):
                nonlocal swapped
                if not swapped and relative == "safe/payload.py":
                    swapped = True
                    safe.rename(root / "safe-original")
                    safe.symlink_to(outside, target_is_directory=True)
                return real_inspect(directory_fd, name, relative, before, limit)

            with mock.patch.object(
                scanner, "_inspect_file_at", side_effect=swap_ancestor
            ):
                artifact = scan(str(root))
            self.assertTrue(swapped)
            component = next(
                item for item in artifact["components"] if item["path"] == "safe/payload.py"
            )
            self.assertEqual(
                component["sha256"],
                hashlib.sha256(b"value = 'inside'\n").hexdigest(),
            )
            self.assertFalse(
                any("outside-secret-value" in str(item) for item in artifact["findings"])
            )

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

    def test_unreadable_regular_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "hidden.py"
            path.write_text("password = 'sensitive'\n", encoding="utf-8")
            path.chmod(0)
            try:
                if os.access(str(path), os.R_OK):
                    self.skipTest("current account can still read mode-zero files")
                with self.assertRaisesRegex(OSError, "cannot read regular file"):
                    scan(temp)
            finally:
                path.chmod(0o600)

    def test_scanner_closes_file_descriptor_when_fstat_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "payload.py").write_text("value = 1\n", encoding="utf-8")
            real_open = scanner.os.open
            real_fstat = scanner.os.fstat
            captured = []

            def capture_open(path, flags, mode=0o600, *, dir_fd=None):
                if dir_fd is None:
                    descriptor = real_open(path, flags, mode)
                else:
                    descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                if path == "payload.py":
                    captured.append(descriptor)
                return descriptor

            def fail_file_fstat(descriptor):
                if descriptor in captured:
                    raise OSError("injected file fstat failure")
                return real_fstat(descriptor)

            with mock.patch.object(scanner.os, "open", side_effect=capture_open), mock.patch.object(
                scanner.os, "fstat", side_effect=fail_file_fstat
            ):
                with self.assertRaisesRegex(OSError, "fstat failure"):
                    scan(str(root))
            self.assertEqual(len(captured), 1)
            with self.assertRaises(OSError):
                real_fstat(captured[0])

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
            path = root / "evil` | forged | <img src=x>.py"
            path.write_text(
                "password = 'short' # ` <img src=x onerror=alert(1)>\n",
                encoding="utf-8",
            )
            report = markdown_report(scan(str(root)))
            self.assertNotIn("<img", report)
            self.assertNotIn("| forged |", report)
            self.assertIn("&#96;", report)


if __name__ == "__main__":
    unittest.main()
