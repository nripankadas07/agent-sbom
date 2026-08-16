import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_clean_wheel_demo_is_self_contained(self):
        if os.environ.get("AGENT_SBOM_EXTRACTED_SDIST_TEST") == "1":
            return
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            source = workspace / "source"
            shutil.copytree(
                PROJECT,
                source,
                ignore=shutil.ignore_patterns(
                    ".git", ".pytest_cache", "__pycache__", "*.pyc", "*.pyo",
                    "*.egg-info", "build", "dist",
                ),
            )
            backend = workspace / "backend"
            backend_install = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-deps",
                    "--target",
                    str(backend),
                    "setuptools>=77",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                backend_install.returncode,
                0,
                backend_install.stdout + backend_install.stderr,
            )
            backend_environment = os.environ.copy()
            backend_environment.update(
                {
                    "PYTHONPATH": str(backend),
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )
            sdists = workspace / "sdists"
            sdists.mkdir()
            sdist_build = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os,sys; os.chdir(sys.argv[1]); "
                        "from setuptools.build_meta import build_sdist; "
                        "print(build_sdist(sys.argv[2]))"
                    ),
                    str(source),
                    str(sdists),
                ],
                env=backend_environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                sdist_build.returncode, 0, sdist_build.stdout + sdist_build.stderr
            )
            self.assertNotIn(
                "SetuptoolsDeprecationWarning", sdist_build.stdout + sdist_build.stderr
            )
            sdist = next(sdists.glob("agent_sbom-0.1.1.tar.gz"))
            extracted = workspace / "extracted"
            extracted.mkdir()
            with tarfile.open(sdist, "r:gz") as archive:
                for member in archive.getmembers():
                    self.assertFalse(member.issym() or member.islnk() or member.isdev())
                    target = (extracted / member.name).resolve()
                    try:
                        target.relative_to(extracted.resolve())
                    except ValueError:
                        self.fail("unsafe sdist member: %s" % member.name)
                if sys.version_info >= (3, 12):
                    archive.extractall(extracted, filter="data")
                else:
                    archive.extractall(extracted)
            extracted_source = next(path for path in extracted.iterdir() if path.is_dir())
            self.assertTrue((extracted_source / "MANIFEST.in").is_file())
            for area in ("tests", "examples", "artifacts/demo", "docs"):
                expected = {
                    path.relative_to(source / area).as_posix(): path.read_bytes()
                    for path in (source / area).rglob("*")
                    if path.is_file()
                }
                actual = {
                    path.relative_to(extracted_source / area).as_posix(): path.read_bytes()
                    for path in (extracted_source / area).rglob("*")
                    if path.is_file()
                }
                self.assertEqual(actual, expected, "incomplete sdist area: %s" % area)

            extracted_environment = os.environ.copy()
            extracted_environment.update(
                {
                    "AGENT_SBOM_EXTRACTED_SDIST_TEST": "1",
                    "PYTHONPATH": str(extracted_source / "src"),
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )
            extracted_suite = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                cwd=str(extracted_source),
                env=extracted_environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                extracted_suite.returncode,
                0,
                extracted_suite.stdout + extracted_suite.stderr,
            )
            wheels = workspace / "wheels"
            wheels.mkdir()
            build = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    str(wheels),
                    str(extracted_source),
                ],
                env=backend_environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            self.assertNotIn("SetuptoolsDeprecationWarning", build.stdout + build.stderr)
            wheel = next(wheels.glob("*.whl"))
            with zipfile.ZipFile(wheel) as archive:
                metadata_name = next(
                    name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
                )
                metadata = archive.read(metadata_name).decode("utf-8")
                self.assertIn("License-Expression: MIT", metadata)
                self.assertTrue(
                    any(name.endswith(".dist-info/licenses/LICENSE") for name in archive.namelist())
                )
            target = workspace / "installed"
            install = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--no-deps",
                    "--ignore-installed",
                    "--target",
                    str(target),
                    str(wheel),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(install.returncode, 0, install.stdout + install.stderr)
            outside = workspace / "outside"
            outside.mkdir()
            output = outside / "demo"
            environment = os.environ.copy()
            environment.update(
                {"PYTHONPATH": str(target), "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
            )
            script = target / ("Scripts" if os.name == "nt" else "bin") / (
                "agent-sbom.exe" if os.name == "nt" else "agent-sbom"
            )
            version = subprocess.run(
                [str(script), "--version"],
                cwd=str(outside),
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(version.returncode, 0, version.stdout + version.stderr)
            self.assertEqual(version.stdout.strip(), "0.1.1")
            demo = subprocess.run(
                [sys.executable, "-m", "agent_sbom", "demo", "--out", str(output)],
                cwd=str(outside),
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(demo.returncode, 0, demo.stdout + demo.stderr)
            artifact = json.loads((output / "agent-sbom.json").read_text(encoding="utf-8"))
            self.assertEqual(artifact["schema_version"], "agent-sbom/v1")
            self.assertGreater(artifact["summary"]["files"], 0)


if __name__ == "__main__":
    unittest.main()
