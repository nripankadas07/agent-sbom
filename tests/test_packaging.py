import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_clean_wheel_demo_is_self_contained(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            source = workspace / "source"
            source.mkdir()
            for name in ("pyproject.toml", "README.md", "LICENSE"):
                shutil.copy2(PROJECT / name, source / name)
            shutil.copytree(PROJECT / "src", source / "src")
            wheels = workspace / "wheels"
            wheels.mkdir()
            build = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-deps",
                    "--wheel-dir",
                    str(wheels),
                    str(source),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            wheel = next(wheels.glob("*.whl"))
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
            self.assertEqual(version.stdout.strip(), "0.1.0")
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
