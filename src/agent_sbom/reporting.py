"""Stable serialization and human-readable reports."""

from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Any, Mapping

from .scanner import cyclonedx, sarif
from .safeio import write_text_files


def stable_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _markdown_literal(value: Any) -> str:
    """Render untrusted data without leaving Markdown structural characters."""
    safe = []
    for character in str(value):
        if character.isalnum() or character == " ":
            safe.append(character)
        else:
            safe.append("&#%d;" % ord(character))
    return "".join(safe)


def markdown_report(artifact: Mapping[str, Any]) -> str:
    summary = artifact["summary"]
    lines = [
        "# Agent SBOM report",
        "",
        "Subject: `%s`" % _markdown_literal(artifact["subject"]["name"]),
        "",
        "## Summary",
        "",
        "- Components: %d" % summary["components"],
        "- Findings: %d (high %d, medium %d, low %d)"
        % (summary["findings"], summary["high"], summary["medium"], summary["low"]),
        "- Capabilities: %s"
        % (", ".join(_markdown_literal(value) for value in summary["capabilities"]) or "none"),
        "",
        "## Findings",
        "",
        "| Severity | Capability | Location | Evidence |",
        "|---|---|---|---|",
    ]
    for item in artifact["findings"]:
        lines.append(
            "| %s | `%s` | `%s:%s` | `%s` |"
            % tuple(
                _markdown_literal(value)
                for value in (
                    item["severity"],
                    item["rule"],
                    item["path"],
                    item["line"],
                    item["evidence"],
                )
            )
        )
    if not artifact["findings"]:
        lines.append("| — | — | — | No heuristic findings |")
    lines.extend(["", "## Heuristic limits", ""])
    lines.extend("- %s" % _markdown_literal(limit) for limit in artifact["limits"])
    lines.append("")
    return "\n".join(lines)


def html_report(artifact: Mapping[str, Any]) -> str:
    summary = artifact["summary"]
    rows = []
    for item in artifact["findings"]:
        rows.append(
            "<tr><td><span class='sev %s'>%s</span></td><td><code>%s</code></td>"
            "<td><code>%s:%s</code></td><td><code>%s</code></td></tr>"
            % tuple(
                html.escape(str(value))
                for value in (
                    item["severity"],
                    item["severity"],
                    item["rule"],
                    item["path"],
                    item["line"],
                    item["evidence"],
                )
            )
        )
    if not rows:
        rows.append("<tr><td colspan='4'>No heuristic findings.</td></tr>")
    embedded = html.escape(stable_json(artifact))
    return """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent SBOM report</title>
<style>
body{font:15px system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#172033;background:#f7f9fc}
h1{margin-bottom:4px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}.card{background:white;border:1px solid #dfe5ef;border-radius:12px;padding:18px}.n{font-size:28px;font-weight:700}table{width:100%%;border-collapse:collapse;background:white}th,td{text-align:left;padding:10px;border-bottom:1px solid #e6eaf0;vertical-align:top}.sev{font-weight:700}.high{color:#b42318}.medium{color:#b54708}.low{color:#175cd3}code{white-space:pre-wrap;overflow-wrap:anywhere}details{margin-top:24px}pre{background:#101828;color:#e4e7ec;padding:16px;overflow:auto;border-radius:8px}
@media(max-width:700px){.cards{grid-template-columns:1fr 1fr}}
</style>
<h1>Agent SBOM report</h1><p>Deterministic capability evidence for <strong>%s</strong>.</p>
<div class="cards"><div class="card"><div class="n">%d</div>components</div><div class="card"><div class="n">%d</div>findings</div><div class="card"><div class="n">%d</div>high</div><div class="card"><div class="n">%d</div>capabilities</div></div>
<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Capability</th><th>Location</th><th>Evidence</th></tr></thead><tbody>%s</tbody></table>
<details><summary>Canonical artifact</summary><pre>%s</pre></details></html>""" % (
        html.escape(str(artifact["subject"]["name"])),
        summary["components"],
        summary["findings"],
        summary["high"],
        len(summary["capabilities"]),
        "".join(rows),
        embedded,
    )


def write_bundle(artifact: Mapping[str, Any], output_value: str) -> Path:
    files = {
        "agent-sbom.json": stable_json(artifact),
        "bom.cdx.json": stable_json(cyclonedx(artifact)),
        "findings.sarif": stable_json(sarif(artifact)),
        "report.md": markdown_report(artifact),
        "report.html": html_report(artifact),
    }
    checksums = []
    for name, content in sorted(files.items()):
        checksums.append("%s  %s" % (hashlib.sha256(content.encode("utf-8")).hexdigest(), name))
    files["checksums.sha256"] = "\n".join(checksums) + "\n"
    return write_text_files(output_value, files)
